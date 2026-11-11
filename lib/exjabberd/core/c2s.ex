defmodule Exjabberd.C2S do
  @moduledoc """
  Client-to-Server connection handler (RFC 6120 §3-5, RFC 7590).

  Equivalent to `ejabberd_c2s` + `ejabberd_c2s_config` + `ejabberd_listener`.

  Handles SASL (PLAIN, SCRAM-SHA-256), resource binding, session
  establishment, and stanza routing. Each client connection is a
  GenServer supervised by `Exjabberd.ListenerSupervisor`.

  The GenServer owns the socket for *writing*: the listener hands it
  the accepted socket (`set_socket/3`) and updates it after a STARTTLS
  upgrade, so routed stanzas are actually delivered to the client.
  Reading stays in the listener's serve loop.

  Stream Management (XEP-0198) lives here too: the counters and the
  unacknowledged queue must sit in the process that writes to the
  socket, so a stanza is counted exactly when it goes on the wire.
  While SM is enabled, a dropped TCP connection does not kill this
  process — it detaches (socket set to `nil`, registrations kept)
  and waits `resume_timeout` seconds for a `<resume/>` on a fresh
  connection, which hands the new socket over (`{:sm_resume, ...}`).

  Client State Indication (XEP-0352) is also enforced here: while
  the client is `inactive`, message and presence stanzas are queued
  in `csi_queue` and flushed on `<active/>`; IQ and error stanzas
  always go through immediately (see `Exjabberd.Mod.Csi`).
  """

  use GenServer
  require Logger

  alias Exjabberd.Mod.StreamMgmt
  alias Exjabberd.Xmpp.{Codec, Jid, Stanza, Stream}

  @type state :: %{
          socket: port() | nil,
          socket_kind: :tcp | :ssl,
          out_pid: pid() | nil,
          tls: boolean(),
          jid: Jid.t() | nil,
          host: binary(),
          authenticated: boolean(),
          resource: binary() | nil,
          shaper: atom(),
          stream_id: binary(),
          lang: binary(),
          csi_state: :active | :inactive,
          csi_queue: [map()],
          sm:
            nil
            | %{
                id: binary(),
                resume: boolean(),
                in_h: non_neg_integer(),
                out_h: non_neg_integer(),
                unacked: [{non_neg_integer(), map() | nil, binary()}],
                max: pos_integer(),
                timer: reference() | nil
              }
        }

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @impl true
  def init(opts) do
    host = Keyword.get(opts, :host, "localhost")
    stream_id = :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)

    {:ok,
     %{
       socket: Keyword.get(opts, :socket),
       socket_kind: Keyword.get(opts, :socket_kind, :tcp),
       # Non-TCP transport (BOSH / WebSocket): when set, outbound XML
       # is sent as `{:xmpp_out, xml}` to this pid instead of to a
       # socket. The HTTP transports own the wire; the session logic
       # (routing, SM counting, CSI, hooks) is exactly the TCP one.
       out_pid: Keyword.get(opts, :out_pid),
       tls: Keyword.get(opts, :tls, false),
       jid: nil,
       host: host,
       authenticated: false,
       resource: nil,
       shaper: :none,
       stream_id: stream_id,
       lang: "en",
       csi_state: :active,
       csi_queue: [],
       sm: nil
     }}
  end

  @doc "Authenticate a JID (SASL PLAIN)."
  @spec authenticate(pid(), binary(), binary()) :: :ok | {:error, term()}
  def authenticate(pid, user, password), do: GenServer.call(pid, {:authenticate, user, password})

  @doc "Mark the connection authenticated after a verified SCRAM exchange (the listener did the crypto)."
  @spec authenticate_scram_verified(pid(), binary()) :: :ok
  def authenticate_scram_verified(pid, user),
    do: GenServer.call(pid, {:scram_verified, user})

  @doc "Bind resource after auth (RFC 6120 §7)."
  @spec bind(pid(), binary()) :: {:ok, Jid.t()} | {:error, term()}
  def bind(pid, resource), do: GenServer.call(pid, {:bind, resource})

  @doc "Send stanza through c2s (with shaper + hooks)."
  @spec send_stanza(pid(), map()) :: :ok
  def send_stanza(pid, stanza), do: GenServer.cast(pid, {:send, stanza})

  @doc """
  Send already-encoded XML to the client (IQ results, bind result).

  Goes through the same counting as routed stanzas, so Stream
  Management `h` values include IQ replies. Serialised through
  this process, so wire order against routed stanzas is kept.
  """
  @spec send_xml(pid(), binary()) :: :ok
  def send_xml(pid, xml), do: GenServer.cast(pid, {:send_raw, xml})

  @doc "Hand the connection socket to this process (listener accept / STARTTLS upgrade)."
  @spec set_socket(pid(), port(), :tcp | :ssl) :: :ok
  def set_socket(pid, socket, kind), do: GenServer.call(pid, {:set_socket, socket, kind})

  @doc """
  Route outbound XML to a pid (`{:xmpp_out, xml}`) instead of a
  socket — the BOSH / WebSocket transports. Cleared by `set_socket/3`.
  """
  @spec set_out_pid(pid(), pid()) :: :ok
  def set_out_pid(pid, out_pid), do: GenServer.call(pid, {:set_out_pid, out_pid})

  @doc """
  Barrier: returns only after every cast sent to this process before
  the call has been processed. The HTTP transports use it after
  handling a request so an IQ reply sent via `send_xml/2` has
  reached the transport's outbound queue before the HTTP response
  is built (casts alone give no such guarantee).
  """
  @spec sync(pid()) :: :ok
  def sync(pid), do: GenServer.call(pid, :sync)

  @doc "Handle stream header (ejabberd_c2s:open_stream). Returns the stream header plus exactly ONE valid `<stream:features>` block."
  @spec open_stream(pid(), binary(), binary()) :: {:ok, binary()} | {:error, term()}
  def open_stream(pid, from, to), do: GenServer.call(pid, {:open_stream, from, to})

  @doc "Close stream."
  @spec close(pid(), binary()) :: :ok
  def close(pid, reason), do: GenServer.cast(pid, {:close, reason})

  @doc """
  Enable Stream Management (XEP-0198). Returns `{:ok, enabled_xml}`
  or `{:error, failed_xml}`. `resume?` is the client's
  `resume='true'` request; `client_max` is its preferred resumption
  time (noted, not enforced — the server's own `resume_timeout`
  applies).
  """
  @spec sm_enable(pid(), boolean(), non_neg_integer() | nil) ::
          {:ok, binary()} | {:error, binary()}
  def sm_enable(pid, resume?, client_max),
    do: GenServer.call(pid, {:sm_enable, resume?, client_max})

  @doc "Answer an `<r/>` ack request with the current inbound count."
  @spec sm_request_ack(pid()) :: {:ok, binary()} | {:error, :not_enabled}
  def sm_request_ack(pid), do: GenServer.call(pid, :sm_request_ack)

  @doc "Record the client's ack of outbound stanzas up to `h`."
  @spec sm_client_ack(pid(), non_neg_integer()) ::
          {:ok, non_neg_integer()}
          | {:error, :not_enabled | :count_too_high | :bad_request}
  def sm_client_ack(pid, h), do: GenServer.call(pid, {:sm_client_ack, h})

  @doc "Count one stanza received from the client (listener calls this for every message/presence/IQ)."
  @spec sm_inbound(pid()) :: :ok
  def sm_inbound(pid), do: GenServer.cast(pid, :sm_inbound)

  @doc "Set the CSI state (`:active` flushes the queued stanzas first)."
  @spec csi_set(pid(), :active | :inactive) :: :ok
  def csi_set(pid, csi_state), do: GenServer.call(pid, {:csi_set, csi_state})

  @impl true
  def handle_call({:authenticate, user, password}, _from, state) do
    case Exjabberd.Auth.authenticate(state.host, user, password) do
      true ->
        {:ok, jid} = Jid.parse("#{user}@#{state.host}")
        Exjabberd.Hooks.run(:c2s_auth_result, state.host, {:ok, user})
        {:reply, :ok, %{state | authenticated: true, jid: jid}}

      false ->
        Exjabberd.Hooks.run(:c2s_auth_failed, state.host, {user, password})
        Exjabberd.Hooks.run(:c2s_auth_result, state.host, {:error, user})
        {:reply, {:error, :not_authorized}, state}
    end
  end

  def handle_call({:scram_verified, user}, _from, state) do
    {:ok, jid} = Jid.parse("#{user}@#{state.host}")
    Exjabberd.Hooks.run(:c2s_auth_result, state.host, {:ok, user})
    {:reply, :ok, %{state | authenticated: true, jid: jid}}
  end

  def handle_call({:bind, resource}, _from, %{authenticated: true, jid: jid, host: host} = state) do
    res = if resource == "", do: random_resource(), else: resource
    full_jid = %{jid | resource: res}

    # A previous detached SM session for this exact resource is
    # superseded by the fresh bind. Terminate it synchronously
    # *before* registering, or its teardown would delete the new
    # session's registrations.
    case StreamMgmt.lookup_by_jid(Jid.to_string(full_jid)) do
      {:ok, sm_id, old_pid} when old_pid != self() ->
        terminate_session_sync(old_pid)
        StreamMgmt.unregister(sm_id)

      _ ->
        :ok
    end

    :ok = Exjabberd.SessionManager.register(Jid.bare(jid), res, self())
    :ok = Exjabberd.Router.register_route(Jid.to_string(full_jid), self())
    :ok = Exjabberd.Router.register_route(Jid.bare(jid), self())
    Exjabberd.Hooks.run(:user_available, host, full_jid)
    :telemetry.execute([:exjabberd, :c2s, :bind], %{count: 1}, %{host: host})
    {:reply, {:ok, full_jid}, %{state | resource: res, jid: full_jid}}
  end

  def handle_call({:bind, _}, _from, state), do: {:reply, {:error, :not_authenticated}, state}

  def handle_call({:external, cert_jid}, _from, state) do
    case Jid.parse(cert_jid) do
      {:ok, jid} -> {:reply, :ok, %{state | authenticated: true, jid: jid}}
      _ -> {:reply, {:error, :not_authorized}, state}
    end
  end

  def handle_call({:fast, user, token}, _from, state) do
    if Exjabberd.Mod.AuthFast.verify(state.host, "#{user}@#{state.host}", token) do
      {:ok, jid} = Jid.parse("#{user}@#{state.host}")
      {:reply, :ok, %{state | authenticated: true, jid: jid}}
    else
      {:reply, {:error, :not_authorized}, state}
    end
  end

  def handle_call({:set_socket, socket, kind}, _from, state) do
    {:reply, :ok, %{state | socket: socket, socket_kind: kind, tls: kind == :ssl, out_pid: nil}}
  end

  def handle_call({:set_out_pid, out_pid}, _from, state) do
    {:reply, :ok, %{state | out_pid: out_pid, socket: nil}}
  end

  def handle_call(:sync, _from, state), do: {:reply, :ok, state}

  def handle_call({:open_stream, from, to}, _from, state) do
    # The stream's `to` is the domain the client addressed — that is
    # this connection's host from here on (authentication, JID
    # construction, feature hooks and module lookups all key on it).
    # Without this, a client connecting to a non-default host would
    # be bound as user@localhost and federation would break.
    host = if is_binary(to) and to != "", do: to, else: state.host
    header = Stream.open_header(from, to, state.stream_id)

    features =
      Codec.stream_features(host,
        authenticated: state.authenticated,
        tls: state.tls
      )

    {:reply, {:ok, header <> Codec.encode_stream_features(features)}, %{state | host: host}}
  end

  # --- Stream Management (XEP-0198) ---

  def handle_call({:sm_enable, _resume?, _client_max}, _from, %{sm: sm} = state)
      when sm != nil do
    # Second <enable/>: recoverable <failed/> instead of the stream
    # error the XEP suggests (see Mod.StreamMgmt moduledoc).
    {:reply, {:error, StreamMgmt.failed_xml("unexpected-request")}, state}
  end

  def handle_call({:sm_enable, resume?, _client_max}, _from, state) do
    cond do
      not state.authenticated or state.jid == nil or state.resource == nil ->
        # The client MUST NOT enable SM before resource binding.
        {:reply, {:error, StreamMgmt.failed_xml("unexpected-request")}, state}

      not StreamMgmt.enabled?(state.host) ->
        {:reply, {:error, StreamMgmt.failed_xml("feature-not-implemented")}, state}

      true ->
        id = :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
        timeout = StreamMgmt.resume_timeout(state.host)

        sm = %{
          id: id,
          resume: resume? == true,
          in_h: 0,
          out_h: 0,
          unacked: [],
          max: StreamMgmt.max_ack_queue(state.host),
          timer: nil
        }

        if resume? == true, do: StreamMgmt.register(id, self(), Jid.to_string(state.jid))

        xml =
          "<enabled xmlns='urn:xmpp:sm:3' id='#{id}' previd='#{id}' max='#{timeout}'" <>
            if(resume? == true, do: " resume='true'", else: "") <> "/>"

        {:reply, {:ok, xml}, %{state | sm: sm}}
    end
  end

  def handle_call(:sm_request_ack, _from, %{sm: nil} = state) do
    {:reply, {:error, :not_enabled}, state}
  end

  def handle_call(:sm_request_ack, _from, %{sm: sm} = state) do
    {:reply, {:ok, "<a xmlns='urn:xmpp:sm:3' h='#{sm.in_h}'/>"}, state}
  end

  def handle_call({:sm_client_ack, _h}, _from, %{sm: nil} = state) do
    {:reply, {:error, :not_enabled}, state}
  end

  def handle_call({:sm_client_ack, h}, _from, %{sm: sm} = state) do
    cond do
      not is_integer(h) or h < 0 ->
        {:reply, {:error, :bad_request}, state}

      h > sm.out_h ->
        {:reply, {:error, :count_too_high, h, sm.out_h}, state}

      true ->
        kept = Enum.filter(sm.unacked, fn {seq, _stanza, _xml} -> seq > h end)
        {:reply, {:ok, length(sm.unacked) - length(kept)}, %{state | sm: %{sm | unacked: kept}}}
    end
  end

  # Resume a detached session onto a fresh socket. Called by
  # `Exjabberd.Mod.StreamMgmt.resume/5` from the new connection.
  # HTTP transports (BOSH / WebSocket) cannot take over a socket:
  # resumption across transports is not supported — the client gets
  # `item-not-found` and starts a fresh session (BOSH has its own
  # rid-based retransmission instead).
  def handle_call({:sm_resume, _h, _socket, _kind}, _from, %{out_pid: pid} = state)
      when is_pid(pid) do
    {:reply, {:error, :not_found}, state}
  end

  def handle_call({:sm_resume, _h, _socket, _kind}, _from, %{sm: nil} = state) do
    {:reply, {:error, :not_found}, state}
  end

  def handle_call({:sm_resume, h, socket, kind}, _from, %{sm: sm} = state) do
    cond do
      not is_integer(h) or h < 0 or h > sm.out_h ->
        {:reply, {:error, :count_too_high}, state}

      superseded?(state) ->
        {:reply, {:error, :superseded}, state}

      true ->
        state = cancel_sm_timer(state)

        # The old stream should already be gone; if it is somehow
        # still attached, end it with a conflict error first (§5).
        state =
          if state.socket != nil do
            send_to_client(
              state,
              Stream.error("conflict", "Stream resumed on a new connection") <>
                "</stream:stream>"
            )

            close_socket(state)
            %{state | socket: nil}
          else
            state
          end

        # Sequence numbers carry over, nothing is reset (§5). The
        # CSI state resets to active (§5.2 of XEP-0352).
        remaining = Enum.filter(sm.unacked, fn {seq, _stanza, _xml} -> seq > h end)

        state = %{
          state
          | socket: socket,
            socket_kind: kind,
            tls: kind == :ssl,
            csi_state: :active,
            sm: %{sm | unacked: remaining}
        }

        send_to_client(
          state,
          "<resumed xmlns='urn:xmpp:sm:3' h='#{sm.in_h}' previd='#{sm.id}'/>"
        )

        # Replay, in order, without re-counting: these stanzas keep
        # their original sequence numbers and stay unacked until the
        # client acks them.
        Enum.each(remaining, fn {_seq, _stanza, xml} -> send_to_client(state, xml) end)

        state = flush_csi_queue(state)
        {:reply, {:ok, length(remaining)}, state}
    end
  end

  # Synchronous teardown of a detached session (fresh bind superseded it).
  def handle_call(:sm_terminate_now, _from, state) do
    final_teardown(state)
    {:stop, :normal, :ok, state}
  end

  # --- Client State Indication (XEP-0352) ---

  def handle_call({:csi_set, :active}, _from, state) do
    {:reply, :ok, state |> Map.put(:csi_state, :active) |> flush_csi_queue()}
  end

  def handle_call({:csi_set, :inactive}, _from, state) do
    {:reply, :ok, %{state | csi_state: :inactive}}
  end

  @impl true
  def handle_cast({:send, stanza}, state) do
    :ok = Exjabberd.Shaper.check(state.shaper, byte_size(inspect(stanza)))
    # The server stamps the sender's full JID when the client did not.
    stanza =
      if stanza[:from] == nil and state.jid != nil,
        do: %{stanza | from: state.jid},
        else: stanza

    routed = Exjabberd.Hooks.run_fold(:user_send_packet, state.host, stanza, [state.jid])
    Exjabberd.Router.route(routed)
    {:noreply, state}
  end

  def handle_cast({:send_raw, xml}, state) do
    {:noreply, deliver(state, xml)}
  end

  def handle_cast(:sm_inbound, %{sm: nil} = state), do: {:noreply, state}

  def handle_cast(:sm_inbound, %{sm: sm} = state) do
    {:noreply, %{state | sm: %{sm | in_h: sm.in_h + 1}}}
  end

  def handle_cast(:sm_terminate_now, state) do
    final_teardown(state)
    {:stop, :normal, state}
  end

  # Plain close: without SM the session ends here. With SM enabled
  # the process detaches instead — the session (registrations, SM
  # queue, CSI queue) survives for resumption until the timer fires.
  def handle_cast({:close, reason}, %{sm: nil} = state) do
    Logger.info("C2S close #{inspect(state.jid)} reason: #{reason}")
    final_teardown(state)
    {:stop, :normal, state}
  end

  def handle_cast({:close, _reason}, %{socket: nil} = state) do
    # Already detached (cleanup can run twice); do not re-arm the timer.
    {:noreply, state}
  end

  def handle_cast({:close, reason}, %{sm: sm} = state) do
    Logger.info(
      "C2S detach #{inspect(state.jid)} reason: #{reason} (SM #{sm.id}, resumable #{StreamMgmt.resume_timeout(state.host)}s)"
    )

    timer =
      Process.send_after(self(), :sm_resume_timeout, StreamMgmt.resume_timeout(state.host) * 1000)

    {:noreply, %{state | socket: nil, sm: %{sm | timer: timer}}}
  end

  @impl true
  def handle_info({:route, stanza}, state) do
    filtered = Exjabberd.Hooks.run_fold(:user_receive_packet, state.host, stanza, [state.jid])

    cond do
      not (is_map(filtered) and Map.has_key?(filtered, :name)) ->
        {:noreply, state}

      state.csi_state == :active or csi_deliver_now?(filtered) ->
        {:noreply, deliver_stanza(state, filtered)}

      true ->
        {:noreply, queue_csi(state, filtered)}
    end
  end

  def handle_info({:roster_push, item}, state) do
    if state.jid do
      iq =
        Stanza.new(:iq,
          from: state.host,
          to: state.jid,
          type: "set",
          payload: [%{xmlns: "jabber:iq:roster", items: [item]}]
        )

      {:noreply, deliver_stanza(state, iq)}
    else
      {:noreply, state}
    end
  end

  def handle_info({:blocking_push, list}, state) do
    if state.jid do
      iq =
        Stanza.new(:iq,
          from: state.host,
          to: state.jid,
          type: "set",
          payload: [%{xmlns: "urn:xmpp:blocking", blocklist: list}]
        )

      {:noreply, deliver_stanza(state, iq)}
    else
      {:noreply, state}
    end
  end

  def handle_info(:ping, state) do
    # mod_ping keepalive
    {:noreply, state}
  end

  def handle_info(:sm_resume_timeout, %{sm: nil} = state), do: {:noreply, state}

  def handle_info(:sm_resume_timeout, state) do
    if state.socket == nil do
      Logger.info("C2S SM resume timeout #{inspect(state.jid)}, ending session")
      final_teardown(state)
      {:stop, :normal, state}
    else
      # Resumed already; this timer is stale.
      {:noreply, state}
    end
  end

  def handle_info({:stream_error, condition, text}, state) do
    Logger.warning("C2S stream error #{condition}: #{text} for #{inspect(state.jid)}")
    send_to_client(state, Stream.error(condition, text) <> "</stream:stream>")
    {:stop, :normal, state}
  end

  # Unknown messages (for example hook notifications a handler does not
  # care about) must not crash the session.
  def handle_info(_msg, state), do: {:noreply, state}

  # --- counted delivery (XEP-0198) ---

  # Send one stanza to the client, counting it when SM is enabled.
  # A detached session still counts and queues: the stanza is
  # replayed on resume instead of being lost.
  defp deliver_stanza(state, stanza), do: deliver(state, Codec.encode(stanza), stanza)

  defp deliver(state, xml, stanza \\ nil) do
    case state.sm do
      nil ->
        send_to_client(state, xml)
        state

      sm ->
        seq = sm.out_h + 1
        unacked = Enum.take(sm.unacked ++ [{seq, stanza, xml}], -sm.max)

        if length(sm.unacked) + 1 > sm.max do
          Logger.warning(
            "C2S SM ack queue full for #{inspect(state.jid)} (max #{sm.max}), dropping oldest unacked stanza"
          )
        end

        state = %{state | sm: %{sm | out_h: seq, unacked: unacked}}
        if state.socket != nil or state.out_pid != nil, do: send_to_client(state, xml)
        state
    end
  end

  # --- CSI queue (XEP-0352) ---

  defp queue_csi(state, stanza) do
    max = Exjabberd.Mod.Csi.max_queue(state.host)
    queue = Enum.take(state.csi_queue ++ [stanza], -max)

    if length(state.csi_queue) + 1 > max do
      Logger.warning(
        "C2S CSI queue full for #{inspect(state.jid)} (max #{max}), dropping oldest queued stanza"
      )
    end

    %{state | csi_queue: queue}
  end

  defp flush_csi_queue(%{csi_queue: []} = state), do: state

  defp flush_csi_queue(state) do
    Enum.reduce(state.csi_queue, %{state | csi_queue: []}, fn stanza, acc ->
      deliver_stanza(acc, stanza)
    end)
  end

  defp csi_deliver_now?(stanza) do
    if Code.ensure_loaded?(Exjabberd.Mod.Csi),
      do: Exjabberd.Mod.Csi.deliver_now?(stanza),
      else: stanza.name == :iq or stanza.type == "error"
  end

  # --- session teardown ---

  # End a session for real: presence, registrations, SM id, and a
  # last chance for unacknowledged/queued messages via offline storage.
  defp final_teardown(state) do
    if state.jid, do: Exjabberd.Hooks.run(:user_unavailable, state.host, state.jid)

    if state.resource do
      Exjabberd.SessionManager.unregister(Jid.bare(state.jid), state.resource)
      Exjabberd.Router.unregister_route(Jid.to_string(state.jid))
      Exjabberd.Router.unregister_route(Jid.bare(state.jid))
    end

    case state.sm do
      %{id: id} -> StreamMgmt.unregister(id)
      _ -> :ok
    end

    unacked =
      case state.sm do
        %{unacked: list} -> Enum.map(list, fn {_seq, stanza, _xml} -> stanza end)
        _ -> []
      end

    (unacked ++ state.csi_queue)
    |> Enum.filter(&is_map/1)
    |> Enum.filter(&(&1.name == :message))
    |> Enum.each(fn stanza ->
      Exjabberd.Hooks.run(:offline_message, state.host, stanza)
    end)

    :ok
  end

  # True when another live session has taken over this resource
  # (a fresh bind superseded the detached one).
  defp superseded?(state) do
    case state.jid do
      nil ->
        true

      jid ->
        case Exjabberd.SessionManager.get_session(Jid.bare(jid), state.resource || "") do
          {:ok, pid} -> pid != self()
          :error -> true
        end
    end
  end

  defp cancel_sm_timer(%{sm: %{timer: nil}} = state), do: state

  defp cancel_sm_timer(%{sm: %{timer: timer} = sm} = state) do
    if timer, do: Process.cancel_timer(timer)
    %{state | sm: %{sm | timer: nil}}
  end

  defp cancel_sm_timer(state), do: state

  defp terminate_session_sync(pid) do
    try do
      GenServer.call(pid, :sm_terminate_now, 5_000)
    catch
      :exit, _ -> :ok
    end

    :ok
  end

  defp send_to_client(%{out_pid: pid} = _state, data) when is_pid(pid) do
    send(pid, {:xmpp_out, data})
    :ok
  end

  defp send_to_client(%{socket: nil} = state, _data) do
    Logger.warning("C2S no socket to send to #{inspect(state.jid)}")
    :ok
  end

  defp send_to_client(%{socket: socket, socket_kind: :ssl}, data) do
    case :ssl.send(socket, data) do
      :ok -> :ok
      {:error, reason} -> Logger.warning("C2S ssl send failed: #{inspect(reason)}")
    end
  end

  defp send_to_client(%{socket: socket}, data) do
    case :gen_tcp.send(socket, data) do
      :ok -> :ok
      {:error, reason} -> Logger.warning("C2S tcp send failed: #{inspect(reason)}")
    end
  end

  defp close_socket(%{socket: nil}), do: :ok
  defp close_socket(%{socket: socket, socket_kind: :ssl}), do: :ssl.close(socket)
  defp close_socket(%{socket: socket}), do: :gen_tcp.close(socket)

  defp random_resource,
    do: "exjabberd-" <> (:crypto.strong_rand_bytes(4) |> Base.encode16(case: :lower))

  # --- Stabil dalam: SASL EXTERNAL (ejabberd_auth_anonymous + cert) ---
  @doc "SASL EXTERNAL (XEP-178 + ejabberd_c2s EXTERNAL)."
  @spec authenticate_external(pid(), binary()) :: :ok | {:error, term()}
  def authenticate_external(pid, cert_jid), do: GenServer.call(pid, {:external, cert_jid})

  # --- Stabil dalam: FAST (XEP-0484, ejabberd mod_auth_fast) ---
  @doc "FAST token auth."
  @spec authenticate_fast(pid(), binary(), binary()) :: :ok | {:error, term()}
  def authenticate_fast(pid, user, token), do: GenServer.call(pid, {:fast, user, token})

  # --- Stabil dalam: stream error (RFC6120 §4.9) ---
  @doc "Send stream error and close."
  @spec stream_error(pid(), binary(), binary()) :: :ok
  def stream_error(pid, condition, text),
    do: GenServer.cast(pid, {:stream_error, condition, text})
end
