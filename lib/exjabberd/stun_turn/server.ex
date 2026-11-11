defmodule Exjabberd.StunTurn.Server do
  @moduledoc """
  STUN (RFC 5389) + TURN (RFC 5766) server on one port (5478 by
  default): UDP always, TCP as well when configured.

  One UDP socket serves both STUN Binding and TURN control messages
  — the two are told apart by message type, exactly as RFC 5766
  intends for a combined server. TURN allocations live in
  `Exjabberd.StunTurn.Allocation` processes (one relayed UDP socket
  each); this process only owns the control socket, the allocation
  registry (`{transport, ip, port} -> pid`), and the TCP listener.

  Authentication is the RFC 5389 long-term credential mechanism
  (§10.2): a client that sends no credentials gets `401` with
  `REALM` + a stateless `NONCE`; it retries with USERNAME /
  REALM / NONCE / MESSAGE-INTEGRITY, where the key is
  `MD5(username ":" realm ":" password)` and the password is
  `Base64(HMAC-SHA1(shared_secret, username))` — the same
  derivation XEP-0215 advertises, so any client that fetched its
  TURN credentials over XMPP can allocate here.

  A STUN Binding Request without credentials is answered
  unauthenticated (RFC 5389 allows it); with a USERNAME it must
  carry a valid MESSAGE-INTEGRITY or it gets `401`.

  TCP (RFC 5766 §7.2 / RFC 6062 framing): STUN messages and
  ChannelData share the length-prefixed framing on the wire, so one
  per-connection process (`Exjabberd.StunTurn.TcpConnection`)
  buffers bytes and hands complete frames to this server's
  `handle_tcp_frame/3` logic through the same code path as UDP.
  """

  use GenServer
  require Logger

  alias Exjabberd.StunTurn
  alias Exjabberd.StunTurn.Allocation

  @default_lifetime 600

  defstruct [
    :udp_socket,
    :tcp_listener,
    :config,
    allocations: %{},
    tcp_clients: %{},
    monitors: %{}
  ]

  @doc "Start the server. `opts` overrides the `turn:` config (used by tests)."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "List active allocations: `[{client_key, relay_addr, lifetime}]`."
  @spec list_allocations(GenServer.server()) :: [term()]
  def list_allocations(server \\ __MODULE__) do
    GenServer.call(server, :list_allocations)
  catch
    :exit, _ -> []
  end

  @impl true
  def init(opts) do
    config = config_from_opts(opts)
    ip = config.ip
    port = config.port

    case :gen_udp.open(port, [:binary, active: true, ip: ip, reuseaddr: true]) do
      {:ok, udp_socket} ->
        tcp_listener =
          if config.tcp do
            case listen_tcp_with_retry(port, ip, 5) do
              {:ok, listener} ->
                # Capture the server pid here: `self()` inside the
                # spawned fun would be the accept loop's own pid.
                server = self()
                spawn_link(fn -> accept_loop(listener, server) end)
                listener

              {:error, reason} ->
                Logger.warning("STUN/TURN TCP listener on #{port} failed: #{inspect(reason)}")
                nil
            end
          end

        Logger.info(
          "STUN/TURN listening on #{:inet.ntoa(ip)}:#{port} (UDP#{if tcp_listener, do: " + TCP", else: ""}, realm=#{config.realm})"
        )

        {:ok, %__MODULE__{udp_socket: udp_socket, tcp_listener: tcp_listener, config: config}}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  def handle_call(:list_allocations, _from, state) do
    list =
      Enum.map(state.allocations, fn {key, pid} ->
        relay =
          try do
            Allocation.relay_addr(pid)
          catch
            :exit, _ -> nil
          end

        {key, relay}
      end)

    {:reply, list, state}
  end

  def handle_call({:tcp_frame, client_key, data}, _from, state) do
    # A complete STUN message or ChannelData frame from a TCP client.
    {:reply, :ok, handle_client_data(state, client_key, data)}
  end

  def handle_call({:tcp_closed, client_key}, _from, state) do
    state = drop_allocation(state, client_key)
    {:reply, :ok, %{state | tcp_clients: Map.delete(state.tcp_clients, client_key)}}
  end

  def handle_call({:tcp_register, client_key, socket}, _from, state) do
    {:reply, :ok, %{state | tcp_clients: Map.put(state.tcp_clients, client_key, socket)}}
  end

  @impl true
  def handle_info({:udp, socket, ip, port, data}, %{udp_socket: socket} = state) do
    client_key = {:udp, ip, port}
    {:noreply, handle_client_data(state, client_key, data)}
  end

  # A relayed packet for a client: write it to the client's transport.
  def handle_info({:relay_to_client, client_key, datagram}, state) do
    case client_key do
      {:udp, ip, port} ->
        :gen_udp.send(state.udp_socket, ip, port, datagram)

      {:tcp, _ip, _port} = key ->
        case Map.get(state.tcp_clients, key) do
          nil -> :ok
          socket -> :gen_tcp.send(socket, datagram)
        end
    end

    {:noreply, state}
  end

  def handle_info({:allocation_expired, client_key}, state) do
    {:noreply, drop_allocation(state, client_key, notify: false)}
  end

  def handle_info({:DOWN, ref, :process, pid, _reason}, state) do
    case Map.get(state.monitors, ref) do
      nil ->
        {:noreply, state}

      client_key ->
        state = %{state | monitors: Map.delete(state.monitors, ref)}

        state =
          case Map.get(state.allocations, client_key) do
            ^pid -> %{state | allocations: Map.delete(state.allocations, client_key)}
            _ -> state
          end

        {:noreply, state}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    if state.udp_socket, do: :gen_udp.close(state.udp_socket)
    if state.tcp_listener, do: :gen_tcp.close(state.tcp_listener)
    :ok
  end

  # --- per-client datagram handling (UDP and TCP share this) ---

  defp handle_client_data(state, client_key, data) do
    cond do
      StunTurn.channel_data?(data) ->
        handle_channel_data(state, client_key, data)

      StunTurn.stun_message?(data) ->
        handle_stun_message(state, client_key, data)

      true ->
        state
    end
  end

  defp handle_channel_data(state, client_key, data) do
    case StunTurn.decode_channel_data(data) do
      {:ok, channel, payload, _rest} ->
        case Map.get(state.allocations, client_key) do
          nil -> state
          pid -> Allocation.channel_data(pid, channel, payload)
        end

        state

      :error ->
        state
    end
  end

  defp handle_stun_message(state, client_key, raw) do
    case StunTurn.decode(raw) do
      {:ok, msg} ->
        dispatch(state, client_key, raw, msg)

      {:error, _reason} ->
        # Malformed: if the header is readable, answer 400 so the
        # client learns something; otherwise drop silently.
        case raw do
          <<_type::16, _len::16, _cookie::32, tid::binary-size(12), _::binary>> ->
            reply(
              state,
              client_key,
              StunTurn.error_response(
                %{type: 0, transaction_id: tid, attrs: []},
                400,
                "Bad Request"
              )
            )

          _ ->
            state
        end
    end
  end

  # --- STUN method dispatch ---

  defp dispatch(state, client_key, raw, %{type: type} = msg) do
    cond do
      type == StunTurn.binding_request() ->
        handle_binding(state, client_key, raw, msg)

      type == StunTurn.allocate_request() ->
        handle_allocate(state, client_key, raw, msg)

      type == StunTurn.refresh_request() ->
        handle_refresh(state, client_key, raw, msg)

      type == StunTurn.create_permission_request() ->
        handle_create_permission(state, client_key, raw, msg)

      type == StunTurn.channel_bind_request() ->
        handle_channel_bind(state, client_key, raw, msg)

      type == StunTurn.send_indication() ->
        handle_send(state, client_key, msg)

      type == StunTurn.data_indication() ->
        # Data indications flow server -> client, never the reverse.
        state

      true ->
        reply(state, client_key, StunTurn.error_response(msg, 400, "Bad Request"))
    end
  end

  # --- Binding (RFC 5389 §7) ---

  defp handle_binding(state, client_key, raw, msg) do
    cond do
      StunTurn.verify_fingerprint(raw) == {:error, :bad_fingerprint} ->
        reply(state, client_key, StunTurn.error_response(msg, 400, "Bad Request"))

      # Authenticated binding: USERNAME present.
      not is_nil(StunTurn.attr(msg, StunTurn.attr_username())) ->
        handle_authenticated_binding(state, client_key, raw, msg)

      true ->
        reply_binding(state, client_key, msg, nil)
    end
  end

  defp handle_authenticated_binding(state, client_key, raw, msg) do
    username = StunTurn.attr(msg, StunTurn.attr_username())

    case authenticate(state, raw, msg, username) do
      {:ok, key, _username} ->
        reply_binding(state, client_key, msg, key)

      {:error, :stale_nonce} ->
        reply_unauthorized(state, client_key, msg)

      {:error, _} ->
        reply_unauthorized(state, client_key, msg)
    end
  end

  defp reply_binding(state, client_key, msg, key) do
    {_, ip, port} = client_key
    family = ip_family(ip)
    tid = msg.transaction_id

    attrs = [
      {StunTurn.attr_xor_mapped_address(), {:xor, {family, ip, port}, tid}},
      {StunTurn.attr_mapped_address(), {family, ip, port}},
      {StunTurn.attr_software(), "exjabberd"}
    ]

    # Fingerprint in the reply mirrors the request (RFC 5389 §15.5).
    response =
      StunTurn.encode(%{msg | type: StunTurn.binding_success(), attrs: attrs},
        integrity_key: key,
        fingerprint: request_had_fingerprint?(msg, state)
      )

    reply(state, client_key, response)
  end

  # --- Allocate (RFC 5766 §6) ---

  defp handle_allocate(state, client_key, raw, msg) do
    with :ok <- require_transport(msg),
         {:ok, key, username} <- require_auth(state, raw, msg),
         :ok <- check_no_allocation(state, client_key) do
      allocate(state, client_key, msg, key, username)
    else
      {:error, :bad_transport} ->
        reply(state, client_key, StunTurn.error_response(msg, 400, "Bad Request"))

      {:error, :unauthorized} ->
        reply_unauthorized(state, client_key, msg)

      {:error, :stale_nonce} ->
        reply_unauthorized(state, client_key, msg)

      {:error, :allocation_mismatch} ->
        reply(state, client_key, StunTurn.error_response(msg, 437, "Allocation Mismatch"))
    end
  end

  defp allocate(state, client_key, msg, key, _username) do
    if map_size(state.allocations) >= state.config.max_allocations do
      reply(state, client_key, StunTurn.error_response(msg, 486, "Allocation Quota Reached"))
    else
      lifetime = clamp_lifetime(state, StunTurn.attr(msg, StunTurn.attr_lifetime()))

      case Allocation.start_link(
             server: self(),
             client_key: client_key,
             bind_ip: state.config.bind_ip,
             advertise_ip: state.config.advertise_ip,
             lifetime: lifetime
           ) do
        {:ok, pid} ->
          ref = Process.monitor(pid)
          relay_addr = Allocation.relay_addr(pid)
          {_, ip, port} = client_key
          family = ip_family(ip)
          tid = msg.transaction_id

          attrs = [
            {StunTurn.attr_xor_relayed_address(), {:xor, relay_addr, tid}},
            {StunTurn.attr_xor_mapped_address(), {:xor, {family, ip, port}, tid}},
            {StunTurn.attr_lifetime(), lifetime},
            {StunTurn.attr_software(), "exjabberd"}
          ]

          response =
            StunTurn.encode(%{msg | type: 0x0103, attrs: attrs},
              integrity_key: key,
              fingerprint: request_had_fingerprint?(msg, state)
            )

          state = %{
            state
            | allocations: Map.put(state.allocations, client_key, pid),
              monitors: Map.put(state.monitors, ref, client_key)
          }

          reply(state, client_key, response)

        {:error, reason} ->
          Logger.warning("TURN allocate failed: #{inspect(reason)}")
          reply(state, client_key, StunTurn.error_response(msg, 500, "Server Error"))
      end
    end
  end

  # --- Refresh (RFC 5766 §7) ---

  defp handle_refresh(state, client_key, raw, msg) do
    with {:ok, key, _username} <- require_auth(state, raw, msg),
         {:ok, pid} <- fetch_allocation(state, client_key) do
      lifetime = StunTurn.attr(msg, StunTurn.attr_lifetime())

      cond do
        lifetime == 0 ->
          state = drop_allocation(state, client_key)
          reply_lifetime(state, client_key, msg, key, 0)

        true ->
          new_lifetime = clamp_lifetime(state, lifetime)
          {:ok, _} = Allocation.refresh(pid, new_lifetime)
          reply_lifetime(state, client_key, msg, key, new_lifetime)
      end
    else
      {:error, :unauthorized} ->
        reply_unauthorized(state, client_key, msg)

      {:error, :stale_nonce} ->
        reply_unauthorized(state, client_key, msg)

      {:error, :allocation_mismatch} ->
        reply(state, client_key, StunTurn.error_response(msg, 437, "Allocation Mismatch"))
    end
  end

  defp reply_lifetime(state, client_key, msg, key, lifetime) do
    response =
      StunTurn.encode(%{msg | type: 0x0104, attrs: [{StunTurn.attr_lifetime(), lifetime}]},
        integrity_key: key,
        fingerprint: request_had_fingerprint?(msg, state)
      )

    reply(state, client_key, response)
  end

  # --- CreatePermission (RFC 5766 §8) ---

  defp handle_create_permission(state, client_key, raw, msg) do
    with {:ok, key, _username} <- require_auth(state, raw, msg),
         {:ok, pid} <- fetch_allocation(state, client_key) do
      peers = StunTurn.address_attrs(msg, StunTurn.attr_xor_peer_address())

      if peers == [] do
        reply(state, client_key, StunTurn.error_response(msg, 400, "Bad Request"))
      else
        Enum.each(peers, fn {_family, ip, _port} -> Allocation.create_permission(pid, ip) end)

        response =
          StunTurn.encode(%{msg | type: 0x0108, attrs: []},
            integrity_key: key,
            fingerprint: request_had_fingerprint?(msg, state)
          )

        reply(state, client_key, response)
      end
    else
      {:error, :unauthorized} ->
        reply_unauthorized(state, client_key, msg)

      {:error, :stale_nonce} ->
        reply_unauthorized(state, client_key, msg)

      {:error, :allocation_mismatch} ->
        reply(state, client_key, StunTurn.error_response(msg, 437, "Allocation Mismatch"))
    end
  end

  # --- ChannelBind (RFC 5766 §11) ---

  defp handle_channel_bind(state, client_key, raw, msg) do
    with {:ok, key, _username} <- require_auth(state, raw, msg),
         {:ok, pid} <- fetch_allocation(state, client_key),
         {:ok, channel, peer} <- parse_channel_bind(msg) do
      case Allocation.channel_bind(pid, channel, peer) do
        :ok ->
          response =
            StunTurn.encode(%{msg | type: 0x0109, attrs: []},
              integrity_key: key,
              fingerprint: request_had_fingerprint?(msg, state)
            )

          reply(state, client_key, response)

        {:error, :bad_channel} ->
          reply(state, client_key, StunTurn.error_response(msg, 400, "Bad Request"))

        {:error, :channel_in_use} ->
          reply(state, client_key, StunTurn.error_response(msg, 400, "Bad Request"))
      end
    else
      {:error, :unauthorized} ->
        reply_unauthorized(state, client_key, msg)

      {:error, :stale_nonce} ->
        reply_unauthorized(state, client_key, msg)

      {:error, :allocation_mismatch} ->
        reply(state, client_key, StunTurn.error_response(msg, 437, "Allocation Mismatch"))

      {:error, :bad_channel_bind} ->
        reply(state, client_key, StunTurn.error_response(msg, 400, "Bad Request"))
    end
  end

  defp parse_channel_bind(msg) do
    channel = StunTurn.attr(msg, StunTurn.attr_channel_number())
    peer = StunTurn.address_attr(msg, StunTurn.attr_xor_peer_address())

    cond do
      is_nil(channel) or is_nil(peer) -> {:error, :bad_channel_bind}
      channel < 0x4000 or channel > 0x7FFF -> {:error, :bad_channel_bind}
      true -> {:ok, channel, {elem(peer, 1), elem(peer, 2)}}
    end
  end

  # --- Send indication (RFC 5766 §10) ---

  defp handle_send(state, client_key, msg) do
    case Map.get(state.allocations, client_key) do
      nil ->
        state

      pid ->
        peer = StunTurn.address_attr(msg, StunTurn.attr_xor_peer_address())
        data = StunTurn.attr(msg, StunTurn.attr_data())

        if peer && data do
          Allocation.send_to_peer(pid, {elem(peer, 1), elem(peer, 2)}, data)
        end

        state
    end
  end

  # --- authentication helpers ---

  defp require_transport(msg) do
    case StunTurn.attr(msg, StunTurn.attr_requested_transport()) do
      17 -> :ok
      _ -> {:error, :bad_transport}
    end
  end

  defp check_no_allocation(state, client_key) do
    if Map.has_key?(state.allocations, client_key),
      do: {:error, :allocation_mismatch},
      else: :ok
  end

  defp fetch_allocation(state, client_key) do
    case Map.get(state.allocations, client_key) do
      nil -> {:error, :allocation_mismatch}
      pid -> {:ok, pid}
    end
  end

  # Long-term auth for a request. Returns `{:ok, key, username}` or
  # `{:error, :unauthorized | :stale_nonce}`.
  defp require_auth(state, raw, msg) do
    username = StunTurn.attr(msg, StunTurn.attr_username())

    if is_nil(username) or not StunTurn.has_integrity?(raw) do
      {:error, :unauthorized}
    else
      authenticate(state, raw, msg, username)
    end
  end

  defp authenticate(state, raw, msg, username) do
    realm = StunTurn.attr(msg, StunTurn.attr_realm())
    nonce = StunTurn.attr(msg, StunTurn.attr_nonce())

    cond do
      realm != state.config.realm ->
        {:error, :unauthorized}

      is_nil(nonce) ->
        {:error, :unauthorized}

      true ->
        case StunTurn.verify_nonce(state.config.secret, nonce) do
          {:error, reason} ->
            {:error, reason}

          :ok ->
            password = StunTurn.turn_password(username, state.config.secret)
            key = StunTurn.long_term_key(username, state.config.realm, password)

            case StunTurn.verify_integrity(raw, key) do
              :ok -> {:ok, key, username}
              _ -> {:error, :unauthorized}
            end
        end
    end
  end

  defp reply_unauthorized(state, client_key, msg) do
    nonce = StunTurn.make_nonce(state.config.secret)

    attrs = [
      {StunTurn.attr_realm(), state.config.realm},
      {StunTurn.attr_nonce(), nonce}
    ]

    reply(state, client_key, StunTurn.error_response(msg, 401, "Unauthorized", attrs))
  end

  # --- transport helpers ---

  defp reply(state, {:udp, ip, port}, data) do
    :gen_udp.send(state.udp_socket, ip, port, data)
    state
  end

  defp reply(state, {:tcp, _ip, _port} = key, data) do
    case Map.get(state.tcp_clients, key) do
      nil -> state
      socket -> :gen_tcp.send(socket, data)
    end

    state
  end

  defp drop_allocation(state, client_key, opts \\ []) do
    case Map.pop(state.allocations, client_key) do
      {nil, _} ->
        state

      {pid, allocations} ->
        if Keyword.get(opts, :notify, true), do: Allocation.delete(pid)

        ref =
          Enum.find_value(state.monitors, fn {r, k} -> if k == client_key, do: r end)

        monitors = if ref, do: Map.delete(state.monitors, ref), else: state.monitors
        if ref, do: Process.demonitor(ref, [:flush])
        %{state | allocations: allocations, monitors: monitors}
    end
  end

  defp clamp_lifetime(state, nil), do: state.config.default_lifetime

  defp clamp_lifetime(state, requested) do
    max(0, min(requested, state.config.max_lifetime))
  end

  # The client address of a request: both UDP (`{:udp, ip, port}`)
  # and TCP (`{:tcp, ip, port}`) keys carry it in the same slots.
  defp request_had_fingerprint?(msg, _state) do
    Enum.any?(msg.attrs, fn {type, _} -> type == StunTurn.attr_fingerprint() end)
  end

  defp ip_family({_, _, _, _}), do: :ipv4
  defp ip_family({_, _, _, _, _, _, _, _}), do: :ipv6

  # --- config ---

  defp config_from_opts(opts) do
    turn = Exjabberd.Config.turn()
    secret = Exjabberd.Config.turn_secret() || Keyword.get(opts, :secret, "unset-turn-secret")

    # The relay socket binds `bind_ip` (0.0.0.0 by default: every
    # interface) but the relayed address handed to clients must be
    # reachable — advertising the 0.0.0.0 bind address would hand
    # them an unusable relay. By default the advertised address is
    # the configured TURN host (`turn.host`, "localhost" ->
    # 127.0.0.1); an explicit `turn.relay_ip` binds and advertises
    # that IP, and `turn.advertise_ip` overrides the advertisement.
    {bind_ip, advertise_ip} =
      case {turn[:relay_ip] || turn["relay_ip"], turn[:advertise_ip] || turn["advertise_ip"]} do
        {nil, nil} ->
          {{0, 0, 0, 0}, resolve_host(turn[:host] || turn["host"] || "localhost")}

        {nil, adv} ->
          {{0, 0, 0, 0}, parse_ip(adv)}

        {relay, nil} ->
          {parse_ip(relay), parse_ip(relay)}

        {relay, adv} ->
          {parse_ip(relay), parse_ip(adv)}
      end

    %{
      ip: Keyword.get(opts, :ip, parse_ip(turn[:ip] || turn["ip"] || "0.0.0.0")),
      port: Keyword.get(opts, :port, turn[:port] || turn["port"] || 5478),
      tcp: Keyword.get(opts, :tcp, turn[:tcp] != false and turn["tcp"] != false),
      realm: Keyword.get(opts, :realm, turn[:realm] || turn["realm"] || "localhost"),
      secret: secret,
      bind_ip: Keyword.get(opts, :bind_ip, bind_ip),
      advertise_ip: Keyword.get(opts, :advertise_ip, advertise_ip),
      default_lifetime:
        Keyword.get(
          opts,
          :default_lifetime,
          turn[:default_lifetime] || turn["default_lifetime"] || @default_lifetime
        ),
      max_lifetime:
        Keyword.get(opts, :max_lifetime, turn[:max_lifetime] || turn["max_lifetime"] || 3600),
      max_allocations:
        Keyword.get(
          opts,
          :max_allocations,
          turn[:max_allocations] || turn["max_allocations"] || 500
        )
    }
  end

  defp parse_ip(ip) when is_tuple(ip), do: ip

  defp parse_ip(ip) when is_binary(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, parsed} -> parsed
      _ -> {0, 0, 0, 0}
    end
  end

  defp parse_ip(_), do: {0, 0, 0, 0}

  # Resolve a hostname (e.g. the configured TURN host) to an IP
  # for the advertised relay address; localhost on failure.
  defp resolve_host(host) when is_binary(host) do
    case :inet.getaddr(String.to_charlist(host), :inet) do
      {:ok, ip} -> ip
      _ -> {127, 0, 0, 1}
    end
  end

  defp resolve_host(_), do: {127, 0, 0, 1}

  # A crash-restart can race the old listener socket's release
  # (`eaddrinuse`); retry briefly instead of losing TCP entirely.
  defp listen_tcp_with_retry(_port, _ip, 0), do: {:error, :eaddrinuse}

  defp listen_tcp_with_retry(port, ip, tries) do
    case :gen_tcp.listen(
           port,
           [:binary, active: false, ip: ip, reuseaddr: true, packet: :raw]
         ) do
      {:ok, listener} ->
        {:ok, listener}

      {:error, :eaddrinuse} ->
        Process.sleep(200)
        listen_tcp_with_retry(port, ip, tries - 1)

      {:error, reason} ->
        {:error, reason}
    end
  end

  # --- TCP accept loop ---

  defp accept_loop(listener, server) do
    case :gen_tcp.accept(listener) do
      {:ok, socket} ->
        {:ok, {ip, port}} = :inet.peername(socket)
        client_key = {:tcp, ip, port}

        case Exjabberd.StunTurn.TcpConnection.start_link(
               socket: socket,
               server: server,
               client_key: client_key
             ) do
          {:ok, pid} ->
            :ok = :gen_tcp.controlling_process(socket, pid)
            GenServer.call(server, {:tcp_register, client_key, socket})
            GenServer.cast(pid, :start_reading)

          {:error, _} ->
            :gen_tcp.close(socket)
        end

        accept_loop(listener, server)

      {:error, :closed} ->
        :ok

      {:error, _reason} ->
        Process.sleep(100)
        accept_loop(listener, server)
    end
  end
end
