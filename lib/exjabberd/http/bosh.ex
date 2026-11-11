defmodule Exjabberd.Http.Bosh do
  @moduledoc """
  BOSH — XEP-0124 (transport) + XEP-0206 (XMPP over BOSH).

  One `Exjabberd.Http.Bosh.Session` GenServer per BOSH session
  (`sid`). The session owns an `Exjabberd.Http.XmppTransport`
  (hence a full C2S session: auth, bind, roster, messages — the
  same XMPP a TCP client gets) and the outbound queue.

  Protocol notes (XEP-0124 §7–§13):

  * Session creation: a `<body>` with no `sid` but a `rid` creates
    a session; the answer carries `sid`, `wait`, `inactivity`,
    `polling`, `requests`, `hold`, `ver='1.6'` and the stream
    features inside the body.
  * Every request carries a strictly increasing `rid`. A repeated
    `rid` replays the cached response for that `rid` (retransmit);
    an older `rid` with no cached response gets an empty body.
  * A request with nothing to answer is held (long-poll) until a
    stanza arrives or `wait` seconds pass — at most one request
    held per session (`hold='1'`).
  * `<body type='terminate'/>` ends the session; no request for
    `inactivity` seconds ends it too.
  * `xmpp:restart='true'` re-opens the stream (new features) —
    used by clients after SASL, before binding.
  """

  require Logger

  alias Exjabberd.Http.{Config, XmppTransport}
  alias Exjabberd.Xmpp.Codec

  @table :exjabberd_bosh_sessions
  @bosh_ns "http://jabber.org/protocol/httpbind"

  @doc "Handle a BOSH HTTP request body. Returns `{status, body_xml}`."
  @spec handle_request(binary()) :: {pos_integer(), binary()}
  def handle_request(body) when is_binary(body) do
    case Codec.parse_xml(body) do
      {:ok, %{name: "body", attrs: attrs, children: _} = el} ->
        dispatch(el, attrs, body)

      _ ->
        {400, error_body("bad-request", "Malformed BOSH body")}
    end
  end

  defp dispatch(el, attrs, raw_body) do
    case Map.get(attrs, "sid") do
      nil -> create_session(el, attrs)
      "" -> create_session(el, attrs)
      sid -> existing_session(sid, el, attrs, raw_body)
    end
  end

  # --- session creation ---

  defp create_session(_el, attrs) do
    rid = parse_rid(Map.get(attrs, "rid"))
    to = Map.get(attrs, "to") || List.first(Exjabberd.Config.hosts()) || "localhost"

    cond do
      rid == :error ->
        {400, error_body("bad-request", "Missing or invalid rid")}

      true ->
        wait = parse_int(Map.get(attrs, "wait"), Config.bosh_wait())
        wait = min(max(wait, 1), 120)

        case __MODULE__.Session.start(to) do
          {:ok, pid, sid} ->
            case GenServer.call(pid, {:create, rid, wait, to}, 10_000) do
              {:ok, features} ->
                inactivity = Config.bosh_inactivity()

                body =
                  bosh_body(
                    %{
                      "sid" => sid,
                      "wait" => to_string(wait),
                      "inactivity" => to_string(inactivity),
                      "polling" => "5",
                      "requests" => "2",
                      "hold" => "1",
                      "accept" => "deflate,gzip",
                      "maxpause" => "120",
                      "ver" => "1.6",
                      "from" => to
                    },
                    features
                  )

                {200, body}

              {:error, reason} ->
                Logger.warning("BOSH session create failed: #{inspect(reason)}")
                {500, error_body("internal-server-error", "Session creation failed")}
            end

          {:error, reason} ->
            Logger.warning("BOSH session start failed: #{inspect(reason)}")
            {500, error_body("internal-server-error", "Session creation failed")}
        end
    end
  end

  # --- existing session ---

  defp existing_session(sid, _el, attrs, raw_body) do
    case lookup(sid) do
      {:ok, pid} ->
        rid = parse_rid(Map.get(attrs, "rid"))

        cond do
          rid == :error ->
            {400, error_body("bad-request", "Missing or invalid rid")}

          Map.get(attrs, "type") == "terminate" ->
            GenServer.call(pid, {:terminate, rid}, 10_000)
            {200, bosh_body(%{"type" => "terminate"}, "")}

          Map.get(attrs, "xmpp:restart") in ["true", "1"] ->
            case GenServer.call(pid, {:restart, rid}, 10_000) do
              {:ok, features} -> {200, bosh_body(%{}, features)}
              {:replay, xml} -> {200, xml}
              {:error, :unknown_rid} -> {200, bosh_body(%{}, "")}
              {:error, :gone} -> {404, error_body("item-not-found", "Unknown session")}
            end

          true ->
            inner = inner_xml(raw_body)

            case GenServer.call(pid, {:request, rid, inner}, wait_timeout(attrs)) do
              {:ok, xml} -> {200, bosh_body(%{}, xml)}
              {:ok_terminated, xml} -> {200, bosh_body(%{"type" => "terminate"}, xml)}
              {:replay, xml} -> {200, xml}
              {:error, :unknown_rid} -> {200, bosh_body(%{}, "")}
              {:error, :gone} -> {404, error_body("item-not-found", "Unknown session")}
            end
        end

      :error ->
        {404, error_body("item-not-found", "Unknown session")}
    end
  end

  defp wait_timeout(attrs) do
    wait = parse_int(Map.get(attrs, "wait"), Config.bosh_wait())
    min(max(wait, 1), 120) * 1000 + 15_000
  end

  defp lookup(sid) do
    ensure_table()

    case :ets.lookup(@table, sid) do
      [{_, pid}] when is_pid(pid) ->
        if Process.alive?(pid), do: {:ok, pid}, else: :error

      [] ->
        :error
    end
  end

  defp parse_rid(nil), do: :error

  defp parse_rid(str) do
    case Integer.parse(String.trim(to_string(str))) do
      {n, ""} when n >= 0 -> n
      _ -> :error
    end
  end

  defp parse_int(nil, default), do: default

  defp parse_int(str, default) do
    case Integer.parse(String.trim(to_string(str))) do
      {n, ""} -> n
      _ -> default
    end
  end

  # Inner XML of the <body> element (the stanzas), without re-encoding.
  # NOTE: split on the LAST "</body>" — a chat message itself contains
  # a `<body>…</body>` child, and splitting on the first one would
  # truncate the stanza (this silently dropped every BOSH message).
  defp inner_xml(raw) do
    case :binary.split(raw, ">") do
      [_, rest] ->
        case :binary.matches(rest, "</body>") do
          [] ->
            ""

          matches ->
            {idx, _len} = List.last(matches)
            binary_part(rest, 0, idx)
        end

      _ ->
        ""
    end
  end

  @doc "Build a `<body>` response element."
  @spec bosh_body(map(), binary()) :: binary()
  def bosh_body(attrs, inner) do
    attrs =
      Map.put_new(attrs, "xmlns", @bosh_ns)
      |> Enum.map_join(" ", fn {k, v} -> ~s(#{k}='#{escape(v)}') end)

    "<body #{attrs}>#{inner}</body>"
  end

  defp error_body(condition, text) do
    bosh_body(
      %{"type" => "terminate", "condition" => condition},
      "<text>#{escape(text)}</text>"
    )
  end

  defp escape(str) do
    str
    |> to_string()
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("'", "&apos;")
  end

  defp ensure_table do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    end
  end

  # --- per-session GenServer ---

  defmodule Session do
    @moduledoc false
    use GenServer
    require Logger

    alias Exjabberd.Http.XmppTransport

    @doc "Start a BOSH session (unlinked — the HTTP handler that created it exits after replying)."
    @spec start(binary()) :: {:ok, pid(), binary()} | {:error, term()}
    def start(host) do
      sid = :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)

      case GenServer.start(__MODULE__, {sid, host}) do
        {:ok, pid} -> {:ok, pid, sid}
        err -> err
      end
    end

    @impl true
    def init({sid, host}) do
      table = :exjabberd_bosh_sessions

      if :ets.whereis(table) == :undefined do
        :ets.new(table, [:named_table, :public, :set, read_concurrency: true])
      end

      :ets.insert(table, {sid, self()})

      case XmppTransport.start(host, self()) do
        {:ok, transport} ->
          {:ok,
           %{
             sid: sid,
             host: host,
             transport: transport,
             last_rid: nil,
             responses: %{},
             queue: [],
             waiter: nil,
             closed: false,
             wait: 60,
             inactivity_timer: nil
           }}

        {:error, reason} ->
          {:stop, reason}
      end
    end

    @impl true
    def handle_call({:create, rid, wait, to}, _from, state) do
      case XmppTransport.open_stream(state.transport, to) do
        {:ok, transport, _header, features} ->
          state = %{state | transport: transport, last_rid: rid, wait: wait}
          {:reply, {:ok, features}, arm_inactivity(state)}

        {:error, reason} ->
          {:reply, {:error, reason}, state}
      end
    end

    def handle_call({:terminate, _rid}, _from, state) do
      XmppTransport.close(state.transport)
      {:stop, :normal, :ok, state}
    end

    def handle_call({:restart, rid}, _from, state) do
      case check_rid(state, rid) do
        :ok ->
          case XmppTransport.open_stream(state.transport, state.host) do
            {:ok, transport, _header, features} ->
              state = %{state | transport: transport, last_rid: rid}
              {:reply, {:ok, features}, arm_inactivity(state)}

            {:error, reason} ->
              {:reply, {:error, reason}, state}
          end

        :replay ->
          {:reply, {:replay, Map.get(state.responses, rid, "")}, state}

        :old ->
          {:reply, {:error, :unknown_rid}, state}
      end
    end

    def handle_call({:request, rid, inner_xml}, from, state) do
      case check_rid(state, rid) do
        :replay ->
          {:reply, {:replay, Map.fetch!(state.responses, rid)}, state}

        :old ->
          {:reply, {:error, :unknown_rid}, state}

        :ok ->
          state = %{state | last_rid: rid}
          state = process_units(state, inner_xml)

          if not state.closed do
            :ok = Exjabberd.C2S.sync(state.transport.c2s)
          end

          state = arm_inactivity(state)

          cond do
            state.closed ->
              {xml, state} = take_queue(state)
              {:stop, :normal, {:ok_terminated, xml}, state}

            state.queue != [] ->
              {xml, state} = take_queue(state)
              {:reply, {:ok, xml}, cache_response(state, rid, xml)}

            true ->
              # Long-poll: hold this request until a stanza arrives
              # or `wait` seconds pass.
              timer =
                Process.send_after(self(), {:poll_timeout, from}, state.wait * 1000)

              {:noreply, %{state | waiter: {from, timer, rid}}}
          end
      end
    end

    @impl true
    def handle_info({:xmpp_out, xml}, state) do
      state = %{state | queue: state.queue ++ [xml]}

      case state.waiter do
        nil ->
          {:noreply, state}

        {from, timer, rid} ->
          Process.cancel_timer(timer)
          {out, state} = take_queue(state)
          GenServer.reply(from, {:ok, out})
          {:noreply, %{state | waiter: nil} |> cache_response(rid, out)}
      end
    end

    def handle_info({:poll_timeout, from}, %{waiter: {from, _timer, rid}} = state) do
      GenServer.reply(from, {:ok, ""})
      {:noreply, %{state | waiter: nil} |> cache_response(rid, "")}
    end

    def handle_info({:poll_timeout, _from}, state), do: {:noreply, state}

    def handle_info(:inactivity_timeout, state) do
      Logger.info("BOSH session #{state.sid} ended (inactivity)")
      XmppTransport.close(state.transport)
      {:stop, :normal, state}
    end

    def handle_info(_msg, state), do: {:noreply, state}

    @impl true
    def terminate(_reason, state) do
      :ets.delete(:exjabberd_bosh_sessions, state.sid)
      :ok
    end

    # --- internals ---

    # rid rules: a repeat of the last rid replays its cached
    # response; an older rid is stale; anything newer is accepted
    # (gaps are tolerated — XEP-0124 allows out-of-order delivery
    # inside the window, and the probes send sequentially).
    defp check_rid(%{last_rid: nil}, _rid), do: :ok

    defp check_rid(%{last_rid: last, responses: r}, rid) when rid == last,
      do: if(Map.has_key?(r, rid), do: :replay, else: :old)

    defp check_rid(%{last_rid: last}, rid) when rid < last, do: :old
    defp check_rid(_state, _rid), do: :ok

    defp process_units(state, "") do
      state
    end

    defp process_units(state, inner_xml) do
      case XmppTransport.parse_buffer(inner_xml, state.transport.max_size) do
        {:ok, units, _rest} ->
          Enum.reduce(units, state, fn unit, acc ->
            case XmppTransport.handle_unit(acc.transport, unit) do
              {:ok, transport, outs} ->
                %{acc | transport: transport, queue: acc.queue ++ outs}

              {:closed, transport, outs} ->
                XmppTransport.close(transport)
                %{acc | transport: transport, closed: true, queue: acc.queue ++ outs}
            end
          end)

        {:error, _} ->
          %{state | queue: state.queue ++ ["<body/>"]}
      end
    end

    defp take_queue(state) do
      {Enum.join(state.queue, ""), %{state | queue: []}}
    end

    defp cache_response(state, rid, xml) do
      responses = Map.put(state.responses, rid, Exjabberd.Http.Bosh.bosh_body(%{}, xml))

      responses =
        if map_size(responses) > 5 do
          oldest = responses |> Map.keys() |> Enum.min()
          Map.delete(responses, oldest)
        else
          responses
        end

      %{state | responses: responses}
    end

    defp arm_inactivity(state) do
      if state.inactivity_timer, do: Process.cancel_timer(state.inactivity_timer)

      timer =
        Process.send_after(
          self(),
          :inactivity_timeout,
          Exjabberd.Http.Config.bosh_inactivity() * 1000
        )

      %{state | inactivity_timer: timer}
    end
  end
end
