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
  """

  use GenServer
  require Logger

  alias Exjabberd.Xmpp.{Codec, Jid, Stanza, Stream}

  @type state :: %{
          socket: port() | nil,
          socket_kind: :tcp | :ssl,
          tls: boolean(),
          jid: Jid.t() | nil,
          host: binary(),
          authenticated: boolean(),
          resource: binary() | nil,
          shaper: atom(),
          stream_id: binary(),
          lang: binary(),
          csi_state: :active | :inactive
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
       tls: Keyword.get(opts, :tls, false),
       jid: nil,
       host: host,
       authenticated: false,
       resource: nil,
       shaper: :none,
       stream_id: stream_id,
       lang: "en",
       csi_state: :active
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

  @doc "Hand the connection socket to this process (listener accept / STARTTLS upgrade)."
  @spec set_socket(pid(), port(), :tcp | :ssl) :: :ok
  def set_socket(pid, socket, kind), do: GenServer.call(pid, {:set_socket, socket, kind})

  @doc "Handle stream header (ejabberd_c2s:open_stream). Returns the stream header plus exactly ONE valid `<stream:features>` block."
  @spec open_stream(pid(), binary(), binary()) :: {:ok, binary()} | {:error, term()}
  def open_stream(pid, from, to), do: GenServer.call(pid, {:open_stream, from, to})

  @doc "Close stream."
  @spec close(pid(), binary()) :: :ok
  def close(pid, reason), do: GenServer.cast(pid, {:close, reason})

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
    {:reply, :ok, %{state | socket: socket, socket_kind: kind, tls: kind == :ssl}}
  end

  def handle_call({:open_stream, from, to}, _from, state) do
    header = Stream.open_header(from, to, state.stream_id)

    features =
      Codec.stream_features(state.host,
        authenticated: state.authenticated,
        tls: state.tls
      )

    {:reply, {:ok, header <> Codec.encode_stream_features(features)}, state}
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

  @impl true
  def handle_cast({:close, reason}, state) do
    Logger.info("C2S close #{inspect(state.jid)} reason: #{reason}")
    if state.jid, do: Exjabberd.Hooks.run(:user_unavailable, state.host, state.jid)

    if state.resource,
      do: Exjabberd.SessionManager.unregister(Jid.bare(state.jid), state.resource)

    {:stop, :normal, state}
  end

  @impl true
  def handle_info({:route, stanza}, state) do
    filtered = Exjabberd.Hooks.run_fold(:user_receive_packet, state.host, stanza, [state.jid])

    if state.csi_state == :active do
      # A hook may deny the stanza (for example a privacy list); only
      # real stanzas are written to the socket.
      if is_map(filtered) and Map.has_key?(filtered, :name) do
        send_to_client(state, Codec.encode(filtered))
      end
    else
      if Code.ensure_loaded?(Exjabberd.Mod.Csi),
        do: apply(Exjabberd.Mod.Csi, :on_inactive, [filtered, state.host])
    end

    {:noreply, state}
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

      send_to_client(state, Codec.encode(iq))
    end

    {:noreply, state}
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

      send_to_client(state, Codec.encode(iq))
    end

    {:noreply, state}
  end

  def handle_info(:ping, state) do
    # mod_ping keepalive
    {:noreply, state}
  end

  def handle_info({:stream_error, condition, text}, state) do
    Logger.warning("C2S stream error #{condition}: #{text} for #{inspect(state.jid)}")
    send_to_client(state, Stream.error(condition, text) <> "</stream:stream>")
    {:stop, :normal, state}
  end

  # Unknown messages (for example hook notifications a handler does not
  # care about) must not crash the session.
  def handle_info(_msg, state), do: {:noreply, state}

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
