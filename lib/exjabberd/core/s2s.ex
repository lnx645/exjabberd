defmodule Exjabberd.S2S do
  @moduledoc """
  Server-to-Server (RFC 6120 §4, XEP-0220 Server Dialback).

  `Exjabberd.S2S` is the per-domain connection manager (like
  `ejabberd_s2s`): `route_to_remote/2` hands a stanza to the
  `Exjabberd.S2S.Out` connection for the target domain, starting one
  when needed. One outbound connection serves one domain pair; it is
  re-established on demand after a failure, and queued stanzas are
  bounced to their senders with a stanza error instead of being
  silently dropped.

  Inbound connections live in `Exjabberd.Listener.S2S` (port 5269);
  dialback keys live in `Exjabberd.S2S.Dialback`.

  Authentication of an outbound connection is dialback (XEP-0220)
  by default; with `s2s_prefer_external: true` the connection first
  tries SASL EXTERNAL (RFC 6120 §4.8, `Exjabberd.S2S.External`)
  after STARTTLS and falls back to dialback when the peer refuses.

  Bidirectional streams (XEP-0288): an inbound connection whose
  peer completed authentication (either method) and sent the
  `<bidi/>` request registers itself here as a *channel* for its
  domain (`register_bidi/2`). `route_to_remote/2` prefers a live
  channel over opening a second, opposite-direction connection —
  one TCP connection then carries both directions, which is the
  whole point of the XEP.

  Domain resolution (`resolve/1`): configured `s2s_host_overrides`
  first (domain → host/port, for tests and for domains without DNS),
  then the `_xmpp-server._tcp` SRV record, then a plain A/AAAA lookup
  on port 5269 (RFC 6120 §3.2.1).
  """

  use GenServer
  require Logger

  alias Exjabberd.S2S.Dialback

  @s2s_port 5269

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(state),
    do: {:ok, Map.merge(%{connections: %{}, bidi_channels: %{}}, Map.new(state))}

  @doc "Route a stanza to a remote domain via S2S (like `ejabberd_s2s:route`)."
  @spec route_to_remote(binary(), map()) :: :ok
  def route_to_remote(remote_domain, stanza) do
    GenServer.cast(__MODULE__, {:route, remote_domain, stanza})
  end

  @doc "Get the S2S outbound connection pid for a domain."
  @spec get_connection(binary()) :: {:ok, pid()} | :error
  def get_connection(domain), do: GenServer.call(__MODULE__, {:get, domain})

  @doc "Live outbound connections with their state, for status/debug."
  @spec connections() :: [map()]
  def connections, do: GenServer.call(__MODULE__, :connections)

  @doc """
  Register an inbound connection process as the XEP-0288
  bidirectional channel for `domain` (called by the S2S listener
  after the peer authenticated and requested bidi). The manager
  monitors the process; the channel dies with the connection.
  """
  @spec register_bidi(binary(), pid()) :: :ok
  def register_bidi(domain, pid) when is_pid(pid) do
    GenServer.cast(__MODULE__, {:register_bidi, String.downcase(to_string(domain)), pid})
  end

  @doc "Live bidirectional channels, for status/debug."
  @spec bidi_channels() :: [%{domain: binary(), pid: pid()}]
  def bidi_channels, do: GenServer.call(__MODULE__, :bidi_channels)

  @doc "Our local host (first configured host) — the Sender Domain on outbound streams."
  @spec local_host() :: binary()
  def local_host do
    List.first(Exjabberd.Config.hosts()) || "localhost"
  end

  @doc """
  Resolve a remote domain to `{host, port}` for the S2S connection.

  Order: `s2s_host_overrides` from configuration, then DNS SRV
  `_xmpp-server._tcp.<domain>`, then A/AAAA on port 5269.
  `host` is a binary hostname or an IP tuple, as `:gen_tcp` accepts.
  """
  @spec resolve(binary()) :: {:ok, {binary() | tuple(), pos_integer()}} | {:error, term()}
  def resolve(domain) when is_binary(domain) do
    domain = String.downcase(String.trim(domain))

    case Map.get(Exjabberd.Config.s2s_host_overrides(), domain) do
      nil -> dns_resolve(domain)
      {host, port} -> {:ok, {host, port}}
      %{host: host, port: port} -> {:ok, {host, port}}
      %{"host" => host, "port" => port} -> {:ok, {to_string(host), port}}
      other -> {:error, {:bad_override, other}}
    end
  end

  @doc "STARTTLS policy for outbound S2S (`:optional` | `:required` | `:disabled`)."
  @spec starttls_policy() :: :optional | :required | :disabled
  def starttls_policy do
    case Exjabberd.Config.get("global", :s2s_use_starttls, :optional) do
      policy when policy in [:optional, :required, :disabled] -> policy
      "optional" -> :optional
      "required" -> :required
      "disabled" -> :disabled
      _ -> :optional
    end
  end

  @impl true
  def handle_cast({:route, domain, stanza}, state) do
    domain = String.downcase(to_string(domain))

    case live_bidi_channel(domain, state) do
      {:ok, pid} ->
        # XEP-0288: the peer's inbound connection carries this
        # direction too — no second connection is opened.
        send(pid, {:s2s_route, stanza})
        {:noreply, state}

      :error ->
        {pid, state} = ensure_connection(domain, state)

        cond do
          is_pid(pid) ->
            send(pid, {:s2s_route, stanza})

          true ->
            # No outbound connection could be started: bounce the
            # sender immediately instead of losing the stanza.
            Exjabberd.Router.route_error(stanza, "remote-server-not-found")
        end

        {:noreply, state}
    end
  end

  def handle_cast({:register_bidi, domain, pid}, state) do
    if Process.alive?(pid) do
      Process.monitor(pid)
      Logger.info("S2S bidi channel registered for #{domain}")
      {:noreply, put_in(state, [:bidi_channels, domain], pid)}
    else
      {:noreply, state}
    end
  end

  @impl true
  def handle_call({:get, domain}, _from, state) do
    case Map.get(state.connections, String.downcase(to_string(domain))) do
      nil -> {:reply, :error, state}
      pid -> {:reply, {:ok, pid}, state}
    end
  end

  def handle_call(:connections, _from, state) do
    list =
      Enum.map(state.connections, fn {domain, pid} ->
        status =
          try do
            Exjabberd.S2S.Out.status(pid)
          catch
            :exit, _ -> %{status: :dead}
          end

        Map.merge(%{domain: domain, pid: pid}, status)
      end)

    {:reply, list, state}
  end

  def handle_call(:bidi_channels, _from, state) do
    list =
      Enum.map(state.bidi_channels, fn {domain, pid} ->
        %{domain: domain, pid: pid}
      end)

    {:reply, list, state}
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, _reason}, state) do
    next =
      Map.reject(state.connections, fn {_domain, p} -> p == pid end)

    channels =
      Map.reject(state.bidi_channels, fn {_domain, p} -> p == pid end)

    {:noreply, %{state | connections: next, bidi_channels: channels}}
  end

  defp live_bidi_channel(domain, state) do
    case Map.get(state.bidi_channels, domain) do
      pid when is_pid(pid) ->
        if Process.alive?(pid), do: {:ok, pid}, else: :error

      _ ->
        :error
    end
  end

  defp ensure_connection(domain, state) do
    case Map.get(state.connections, domain) do
      pid when is_pid(pid) ->
        if Process.alive?(pid) do
          {pid, state}
        else
          start_connection(domain, state)
        end

      nil ->
        start_connection(domain, state)
    end
  end

  defp start_connection(domain, state) do
    case GenServer.start(Exjabberd.S2S.Out, %{domain: domain, local_host: local_host()}) do
      {:ok, pid} ->
        Process.monitor(pid)
        {pid, put_in(state, [:connections, domain], pid)}

      {:error, reason} ->
        Logger.warning("S2S out to #{domain} failed to start: #{inspect(reason)}")
        {nil, state}
    end
  end

  # --- DNS resolution ---

  defp dns_resolve(domain) do
    srv_name = String.to_charlist("_xmpp-server._tcp." <> domain)

    srv =
      try do
        :inet_res.lookup(srv_name, :in, :srv)
      rescue
        _ -> []
      catch
        _, _ -> []
      end

    case srv do
      [{_prio, _weight, port, target} | _] ->
        target = target |> to_string() |> String.trim_trailing(".")
        {:ok, {target, port}}

      _ ->
        case :inet.gethostbyname(String.to_charlist(domain)) do
          {:ok, {:hostent, _, _, :inet, _, [ip | _]}} -> {:ok, {ip, @s2s_port}}
          {:ok, {:hostent, _, _, :inet6, _, [ip | _]}} -> {:ok, {ip, @s2s_port}}
          _ -> {:error, :nxdomain}
        end
    end
  end
end

defmodule Exjabberd.S2S.Out do
  @moduledoc """
  Outbound S2S connection (ejabberd_s2s_out equivalent) — one live
  TCP/TLS connection to one remote domain.

  State machine (active socket, so the handshake and the stream are
  driven by `handle_info/2`):

      connect → wait_features → [STARTTLS → wait_features_tls] →
      dialback_wait → established

  With `s2s_prefer_external: true` and the EXTERNAL mechanism
  offered after STARTTLS, the machine detours instead:

      wait_features_tls → external_wait → (success) →
      wait_features_external → established

  and a SASL `<failure/>` on that detour falls back to
  `dialback_wait`. When the peer advertised the XEP-0288 bidi
  feature, establishment (either path) is followed by a `<bidi/>`
  request; the connection then also *receives*: stanzas the peer
  sends back over this same connection are validated against the
  connection's domain and handed to the router.

  Stanzas arriving before `:established` are queued (XEP-0220
  §2.1.1: the initiator MUST NOT send stanzas before authorization)
  and flushed in order once the receiving server answers
  `<db:result type='valid'/>`. On any failure the queued stanzas are
  bounced to their senders with a stanza error (never silently lost);
  the connection then lingers briefly in `:failed` — bouncing any
  stanza that arrives while it is dying — and stops, so the manager
  starts a fresh connection on the next stanza for the domain.
  """

  use GenServer
  require Logger

  alias Exjabberd.S2S.Dialback
  alias Exjabberd.Xmpp.{Codec, StreamParser}

  @max_queue 100
  @handshake_timeout 15_000
  @failed_linger_ms 5_000
  @max_stanza_size 262_144

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc "Connection status for the manager/status view."
  @spec status(pid()) :: map()
  def status(pid), do: GenServer.call(pid, :status)

  @impl true
  def init(opts) do
    state = %{
      domain: to_string(Map.get(opts, :domain, "")),
      local_host: to_string(Map.get(opts, :local_host, "localhost")),
      sock: nil,
      kind: :tcp,
      buf: "",
      status: :connecting,
      remote_stream_id: nil,
      queue: [],
      tls: false,
      timer: nil,
      fail_condition: nil,
      stop_timer: nil,
      external_tried: false,
      auth_method: nil,
      bidi_offered: false,
      bidi: false
    }

    {:ok, state, {:continue, :connect}}
  end

  @impl true
  def handle_continue(:connect, state) do
    case Exjabberd.S2S.resolve(state.domain) do
      {:ok, {host, port}} ->
        host_arg = if is_tuple(host), do: host, else: String.to_charlist(host)

        case :gen_tcp.connect(host_arg, port, [:binary, packet: 0, active: true], 5_000) do
          {:ok, sock} ->
            :ok = :gen_tcp.send(sock, Dialback.stream_header(state.local_host, state.domain))

            timer = Process.send_after(self(), :handshake_timeout, @handshake_timeout)
            {:noreply, %{state | sock: sock, status: :wait_features, timer: timer}}

          {:error, reason} ->
            Logger.warning("S2S out to #{state.domain}: connect failed #{inspect(reason)}")
            {:noreply, fail(state, :unreachable)}
        end

      {:error, reason} ->
        Logger.warning("S2S out to #{state.domain}: resolve failed #{inspect(reason)}")
        {:noreply, fail(state, :unreachable)}
    end
  end

  @impl true
  def handle_call(:status, _from, state) do
    {:reply,
     %{status: state.status, tls: state.tls, queued: length(state.queue),
       remote_stream_id: state.remote_stream_id,
       auth_method: state.auth_method, bidi: state.bidi}, state}
  end

  @impl true
  def handle_info({:s2s_route, stanza}, %{status: :established} = state) do
    case send_raw(state, Codec.encode(stanza)) do
      :ok ->
        {:noreply, state}

      {:error, reason} ->
        # The socket died under us: bounce this stanza too, then fail.
        Logger.warning("S2S out to #{state.domain}: send failed #{inspect(reason)}")
        bounce(state, stanza, "remote-server-timeout")
        {:noreply, fail(state, :timeout)}
    end
  end

  def handle_info({:s2s_route, stanza}, %{status: :failed} = state) do
    bounce(state, stanza, state.fail_condition || "internal-server-error")
    {:noreply, state}
  end

  def handle_info({:s2s_route, stanza}, state) do
    if length(state.queue) >= @max_queue do
      bounce(state, stanza, "service-unavailable")
      {:noreply, state}
    else
      {:noreply, %{state | queue: state.queue ++ [stanza]}}
    end
  end

  def handle_info({:tcp, sock, data}, %{sock: sock, kind: :tcp} = state),
    do: handle_data(data, state)

  def handle_info({:ssl, sock, data}, %{sock: sock, kind: :ssl} = state),
    do: handle_data(data, state)

  def handle_info({:tcp_closed, sock}, %{sock: sock} = state),
    do: handle_closed(state)

  def handle_info({:ssl_closed, sock}, %{sock: sock} = state),
    do: handle_closed(state)

  def handle_info({:tcp_error, sock, reason}, %{sock: sock} = state) do
    Logger.warning("S2S out to #{state.domain}: tcp error #{inspect(reason)}")
    handle_closed(state)
  end

  def handle_info({:ssl_error, sock, reason}, %{sock: sock} = state) do
    Logger.warning("S2S out to #{state.domain}: ssl error #{inspect(reason)}")
    handle_closed(state)
  end

  def handle_info(:handshake_timeout, %{status: status} = state)
      when status in [:established, :failed] do
    {:noreply, state}
  end

  def handle_info(:handshake_timeout, state) do
    Logger.warning("S2S out to #{state.domain}: handshake timed out in #{state.status}")
    {:noreply, fail(state, :timeout)}
  end

  # A failed connection lingers briefly so stanzas that arrive while
  # it is dying are bounced instead of lost, then stops; the manager
  # starts a fresh connection on the next stanza for the domain.
  def handle_info(:stop_after_failure, %{status: :failed} = state) do
    {:stop, :normal, state}
  end

  def handle_info(:stop_after_failure, state), do: {:noreply, state}

  def handle_info(_msg, state), do: {:noreply, state}

  # --- inbound bytes ---

  defp handle_data(_data, %{status: :failed} = state), do: {:noreply, state}

  defp handle_data(data, state) do
    buf = state.buf <> data

    case StreamParser.parse_buffer(buf, @max_stanza_size) do
      {:ok, units, rest} ->
        state = %{state | buf: rest}

        case process_units(units, state) do
          {:ok, state2} -> {:noreply, state2}
          {:failed, state2} -> {:noreply, state2}
        end

      {:error, reason} ->
        Logger.warning("S2S out to #{state.domain}: stream parse #{inspect(reason)}")
        {:noreply, fail(state, :internal)}
    end
  end

  defp process_units(units, state) do
    Enum.reduce_while(units, {:ok, state}, fn unit, {:ok, acc} ->
      case handle_unit(unit, acc) do
        {:ok, next} -> {:cont, {:ok, next}}
        {:failed, next} -> {:halt, {:failed, next}}
      end
    end)
  end

  defp handle_unit(unit, state) do
    cond do
      String.starts_with?(unit, "<?xml") or String.starts_with?(unit, "<!--") ->
        {:ok, state}

      String.starts_with?(unit, "<stream:stream") ->
        handle_stream_open(unit, state)

      String.starts_with?(unit, "<stream:features") ->
        handle_features(unit, state)

      String.starts_with?(unit, "<proceed") ->
        handle_proceed(state)

      String.starts_with?(unit, "<success") and state.status == :external_wait ->
        # SASL EXTERNAL succeeded: restart the stream (RFC 6120
        # §4.8.5); the features of the restarted stream complete
        # the establishment — no dialback follows.
        case send_raw(state, Dialback.stream_header(state.local_host, state.domain)) do
          :ok ->
            {:ok, %{state | status: :wait_features_external, auth_method: :external, buf: ""}}

          {:error, _reason} ->
            {:failed, fail(state, :unreachable)}
        end

      String.starts_with?(unit, "<failure") and state.status == :external_wait ->
        # EXTERNAL refused (e.g. our certificate is not pinned
        # there): fall back to dialback, the pre-EXTERNAL default.
        Logger.warning(
          "S2S out to #{state.domain}: EXTERNAL refused, falling back to dialback"
        )

        send_db_result(state)

      String.starts_with?(unit, "<failure") ->
        Logger.warning("S2S out to #{state.domain}: remote failure #{String.slice(unit, 0, 120)}")
        {:failed, fail(state, :tls_failed)}

      String.starts_with?(unit, "<db:result") ->
        handle_db_result(unit, state)

      String.starts_with?(unit, "<stream:error") ->
        Logger.warning("S2S out to #{state.domain}: remote stream error")
        {:failed, fail(state, :internal)}

      String.starts_with?(unit, "</stream:stream") ->
        {:failed, fail(state, :closed)}

      state.status == :established and state.bidi and
          (String.starts_with?(unit, "<message") or String.starts_with?(unit, "<presence") or
             String.starts_with?(unit, "<iq")) ->
        route_inbound_stanza(unit, state)

      true ->
        Logger.debug("S2S out to #{state.domain}: ignoring #{String.slice(unit, 0, 60)}")
        {:ok, state}
    end
  end

  # A stanza arriving over a bidirectional connection: it is a
  # stanza *from* the peer domain (the reverse direction of this
  # connection). Only the connection's own domain may speak here —
  # anything else is dropped, exactly like the inbound listener.
  defp route_inbound_stanza(unit, state) do
    case Codec.decode(unit) do
      {:ok, stanza} ->
        if from_domain?(stanza.from, state.domain) do
          Exjabberd.Router.route(stanza)
        else
          Logger.warning(
            "S2S bidi stanza from #{inspect(stanza.from)} on connection for #{state.domain}, dropping"
          )
        end

      {:error, _} ->
        Logger.warning("S2S bidi: malformed stanza from #{state.domain}, dropping")
    end

    {:ok, state}
  end

  defp from_domain?(%Exjabberd.Xmpp.Jid{domain: domain}, expected),
    do: String.downcase(domain) == expected

  defp from_domain?(bin, expected) when is_binary(bin) do
    case Exjabberd.Xmpp.Jid.parse(bin) do
      {:ok, %Exjabberd.Xmpp.Jid{domain: domain}} -> String.downcase(domain) == expected
      _ -> false
    end
  end

  defp from_domain?(_, _), do: false

  defp handle_stream_open(unit, state) do
    from = attr(unit, "from")
    id = attr(unit, "id")

    cond do
      state.status not in [:wait_features, :wait_features_tls, :wait_features_external] ->
        {:ok, state}

      from != nil and String.downcase(from) != state.domain ->
        Logger.warning("S2S out to #{state.domain}: stream from #{inspect(from)}, aborting")
        {:failed, fail(state, :internal)}

      id in [nil, ""] ->
        Logger.warning("S2S out to #{state.domain}: stream without id, aborting")
        {:failed, fail(state, :internal)}

      true ->
        {:ok, %{state | remote_stream_id: id}}
    end
  end

  defp handle_features(unit, state) do
    state = %{state | bidi_offered: state.bidi_offered or features_has?(unit, "bidi")}

    case state.status do
      status when status in [:wait_features, :wait_features_tls] ->
        starttls? = features_has?(unit, "starttls")
        policy = Exjabberd.S2S.starttls_policy()

        cond do
          # Not on TLS yet and the peer offers it: upgrade first —
          # EXTERNAL is only ever attempted on the encrypted
          # stream, and dialback prefers it too.
          not state.tls and starttls? and policy != :disabled ->
            send_raw(state, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
            {:ok, %{state | status: :tls_proceed}}

          not state.tls and policy == :required ->
            Logger.warning("S2S out to #{state.domain}: STARTTLS required but not offered")
            {:failed, fail(state, :tls_failed)}

          # On TLS (or TLS not offered/allowed): SASL EXTERNAL
          # when configured to prefer it and the peer offers the
          # mechanism; otherwise dialback, as before.
          state.tls and not state.external_tried and
            Exjabberd.Config.s2s_prefer_external?() and
              features_offers_external?(unit) ->
            case send_raw(
                   state,
                   "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>=</auth>"
                 ) do
              :ok -> {:ok, %{state | status: :external_wait, external_tried: true}}
              {:error, _reason} -> {:failed, fail(state, :unreachable)}
            end

          true ->
            send_db_result(state)
        end

      :wait_features_external ->
        # Features of the post-EXTERNAL restarted stream: the
        # connection is authorized — establish and flush.
        Logger.info("S2S out to #{state.domain}: EXTERNAL verified (tls=#{state.tls})")
        state = cancel_timer(%{state | status: :established})
        state = maybe_request_bidi(state)

        case flush_queue(state) do
          {:ok, state2} -> {:ok, state2}
          {:failed, state2} -> {:failed, state2}
        end

      _ ->
        {:ok, state}
    end
  end

  # XEP-0288: when the peer advertised the bidi feature and bidi is
  # enabled locally, ask to use this connection in both directions.
  # There is no acknowledgement — the peer simply starts sending.
  defp maybe_request_bidi(state) do
    if state.bidi_offered and not state.bidi and Exjabberd.Config.s2s_bidi?() do
      case send_raw(state, "<bidi xmlns='urn:xmpp:bidi:0'/>") do
        :ok ->
          Logger.info("S2S out to #{state.domain}: bidi requested")
          %{state | bidi: true}

        {:error, reason} ->
          Logger.warning("S2S out to #{state.domain}: bidi request failed #{inspect(reason)}")
          state
      end
    else
      state
    end
  end

  # Does a <stream:features/> unit offer the SASL EXTERNAL mechanism?
  defp features_offers_external?(unit) do
    case Codec.parse_xml(unit) do
      {:ok, %{children: children}} ->
        Enum.any?(children, fn
          %{name: "mechanisms", children: mechanisms} ->
            Enum.any?(mechanisms, fn
              %{name: "mechanism", children: texts} ->
                Enum.any?(texts, &(is_binary(&1) and String.trim(&1) == "EXTERNAL"))

              _ ->
                false
            end)

          _ ->
            false
        end)

      _ ->
        false
    end
  end

  defp handle_proceed(%{status: :tls_proceed} = state) do
    case :ssl.connect(state.sock, Exjabberd.Tls.ssl_client_opts(), 10_000) do
      {:ok, ssl_sock} ->
        :ok = :ssl.setopts(ssl_sock, active: true)
        :ok = :ssl.send(ssl_sock, Dialback.stream_header(state.local_host, state.domain))

        {:ok,
         %{state | sock: ssl_sock, kind: :ssl, tls: true, buf: "", status: :wait_features_tls}}

      {:error, reason} ->
        Logger.warning("S2S out to #{state.domain}: TLS handshake failed #{inspect(reason)}")
        {:failed, fail(state, :tls_failed)}
    end
  end

  defp handle_proceed(state), do: {:ok, state}

  defp send_db_result(state) do
    key =
      Dialback.generate_key(
        Dialback.secret(),
        state.remote_stream_id,
        state.local_host,
        state.domain
      )

    case send_raw(
           state,
           "<db:result xmlns:db='jabber:server:dialback' from='#{state.local_host}' " <>
             "to='#{state.domain}' id='#{state.remote_stream_id}'>#{key}</db:result>"
         ) do
      :ok -> {:ok, %{state | status: :dialback_wait}}
      {:error, _reason} -> {:failed, fail(state, :unreachable)}
    end
  end

  defp handle_db_result(unit, %{status: :dialback_wait} = state) do
    case Codec.parse_xml(unit) do
      {:ok, %{attrs: attrs}} ->
        from = Map.get(attrs, "from")
        to = Map.get(attrs, "to")
        type = Map.get(attrs, "type")

        cond do
          type == "valid" and from == state.domain and to == state.local_host ->
            Logger.info("S2S out to #{state.domain}: dialback verified (tls=#{state.tls})")
            state = cancel_timer(%{state | status: :established, auth_method: :dialback})
            state = maybe_request_bidi(state)

            case flush_queue(state) do
              {:ok, state2} -> {:ok, state2}
              {:failed, state2} -> {:failed, state2}
            end

          type == "invalid" ->
            Logger.warning("S2S out to #{state.domain}: dialback invalid")
            {:failed, fail(state, :not_authorized)}

          type == "error" ->
            Logger.warning("S2S out to #{state.domain}: dialback error")
            {:failed, fail(state, :timeout)}

          true ->
            Logger.warning("S2S out to #{state.domain}: unexpected db:result #{inspect(attrs)}")
            {:failed, fail(state, :internal)}
        end

      _ ->
        {:failed, fail(state, :internal)}
    end
  end

  defp handle_db_result(_unit, state), do: {:ok, state}

  # --- sending / queue ---

  # Flush the queue in order. A send error mid-flush fails the
  # connection and bounces the stanza that failed plus the rest.
  defp flush_queue(state) do
    flush_list(state.queue, %{state | queue: []})
  end

  defp flush_list([], state), do: {:ok, state}

  defp flush_list([stanza | rest], state) do
    case send_raw(state, Codec.encode(stanza)) do
      :ok ->
        flush_list(rest, state)

      {:error, reason} ->
        Logger.warning("S2S out to #{state.domain}: flush send failed #{inspect(reason)}")
        bounce(state, stanza, "remote-server-timeout")
        Enum.each(rest, fn s -> bounce(state, s, "remote-server-timeout") end)
        {:failed, fail(state, :timeout)}
    end
  end

  defp send_raw(%{sock: sock, kind: :ssl}, data), do: :ssl.send(sock, data)
  defp send_raw(%{sock: sock}, data), do: :gen_tcp.send(sock, data)

  # --- failure: bounce queued stanzas, linger, then stop ---

  defp handle_closed(%{status: :failed} = state), do: {:noreply, state}

  defp handle_closed(%{status: :established} = state) do
    Logger.warning("S2S out to #{state.domain}: connection closed after establishment")
    {:noreply, fail(state, :timeout)}
  end

  defp handle_closed(state) do
    Logger.warning("S2S out to #{state.domain}: connection closed during #{state.status}")
    {:noreply, fail(state, :unreachable)}
  end

  # Failure reasons map to stanza errors (XEP-0220 §2.1.1: an invalid
  # dialback bounces queued stanzas with <internal-server-error/>; a
  # dialback error with <remote-server-timeout/>; an unreachable
  # domain with <remote-server-not-found/>).
  #
  # A failed connection does NOT stop immediately: stanzas for the
  # domain can still be in flight to this process (they were sent by
  # the manager right after the process started, while the connect
  # was still failing), and stopping would drop them from the
  # mailbox unseen. Instead the connection lingers in `:failed`
  # (bouncing every new stanza at once) and stops after
  # `@failed_linger_ms`; the manager then starts fresh on the next
  # stanza. Idempotent — a second failure while already failed is a
  # no-op, so the original bounce condition is kept.
  defp fail(%{status: :failed} = state, _reason), do: state

  defp fail(state, reason) do
    state = cancel_timer(state)
    condition = fail_condition(reason)

    Enum.each(state.queue, fn stanza -> bounce(state, stanza, condition) end)

    state = %{state | status: :failed, queue: [], fail_condition: condition}
    state = close_socket(state)
    %{state | stop_timer: Process.send_after(self(), :stop_after_failure, @failed_linger_ms)}
  end

  defp close_socket(%{sock: nil} = state), do: state

  defp close_socket(%{sock: sock, kind: :ssl} = state) do
    try do
      :ssl.close(sock)
    catch
      _, _ -> :ok
    end

    %{state | sock: nil}
  end

  defp close_socket(%{sock: sock} = state) do
    try do
      :gen_tcp.close(sock)
    catch
      _, _ -> :ok
    end

    %{state | sock: nil}
  end

  defp fail_condition(:unreachable), do: "remote-server-not-found"
  defp fail_condition(:timeout), do: "remote-server-timeout"
  defp fail_condition(:not_authorized), do: "internal-server-error"
  defp fail_condition(_), do: "internal-server-error"

  defp bounce(_state, stanza, condition) do
    # A bounce is itself a route, never an S2S route: the sender is
    # local, so the error stanza is delivered locally.
    Exjabberd.Router.route_error(stanza, condition)
  rescue
    e -> Logger.warning("S2S bounce failed: #{inspect(e)}")
  end

  defp cancel_timer(%{timer: nil} = state), do: state

  defp cancel_timer(%{timer: timer} = state) do
    Process.cancel_timer(timer)
    %{state | timer: nil}
  end

  # Does a <stream:features/> unit contain a child element `name`?
  defp features_has?(unit, name) do
    case Codec.parse_xml(unit) do
      {:ok, %{children: children}} ->
        Enum.any?(children, fn
          %{name: ^name} -> true
          _ -> false
        end)

      _ ->
        false
    end
  end

  defp attr(unit, name) do
    case Regex.run(~r/#{name}=(["'])(.*?)\1/, unit) do
      [_, _, value] -> value
      _ -> nil
    end
  end
end
