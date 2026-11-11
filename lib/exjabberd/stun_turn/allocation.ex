defmodule Exjabberd.StunTurn.Allocation do
  @moduledoc """
  One TURN allocation (RFC 5766 §6): a relayed UDP transport address
  plus the permissions and channel bindings that guard it.

  The allocation owns its relay `:gen_udp` socket. Packets arriving
  on the relay socket from a permitted peer are handed to the TURN
  server process as a fully built datagram (a Data indication, or
  ChannelData when the peer has a channel bound) — the server only
  writes those bytes to the client's transport (UDP socket or TCP
  connection), so this process never needs to know how the client
  is connected.

  Permissions live 300 seconds (RFC 5766 §6.2, §8); channels live
  10 minutes and are refreshed by re-binding (§11.2). The allocation
  itself expires `lifetime` seconds after the last Refresh and then
  tells the server it is gone before stopping.
  """

  use GenServer
  require Logger

  alias Exjabberd.StunTurn

  @permission_lifetime 300
  @channel_lifetime 600

  defstruct [
    :server,
    :client_key,
    :relay_socket,
    :relay_addr,
    :lifetime,
    :expiry_timer,
    permissions: %{},
    channels: %{},
    channels_by_peer: %{}
  ]

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc "Refresh the allocation lifetime; returns the new lifetime in seconds."
  @spec refresh(pid(), non_neg_integer()) :: {:ok, non_neg_integer()}
  def refresh(pid, lifetime), do: GenServer.call(pid, {:refresh, lifetime})

  @doc "Add a permission for `peer_ip` (300 s). Always succeeds."
  @spec create_permission(pid(), :inet.ip_address()) :: :ok
  def create_permission(pid, peer_ip), do: GenServer.call(pid, {:create_permission, peer_ip})

  @doc """
  Bind `channel` (0x4000..0x7FFF) to `peer` (`{ip, port}` — the
  port comes from the ChannelBind request's XOR-PEER-ADDRESS).
  Binding also creates the permission for that peer (RFC 5766 §11.2).
  """
  @spec channel_bind(pid(), non_neg_integer(), {:inet.ip_address(), :inet.port_number()}) ::
          :ok | {:error, :bad_channel | :channel_in_use}
  def channel_bind(pid, channel, peer),
    do: GenServer.call(pid, {:channel_bind, channel, peer})

  @doc "Send `data` from the relay socket to `peer` (a `{ip, port}`)."
  @spec send_to_peer(pid(), {:inet.ip_address(), :inet.port_number()}, binary()) ::
          :ok | {:error, :no_permission}
  def send_to_peer(pid, peer, data), do: GenServer.call(pid, {:send_to_peer, peer, data})

  @doc "Deliver ChannelData received from the client to its bound peer."
  @spec channel_data(pid(), non_neg_integer(), binary()) :: :ok | {:error, :no_channel}
  def channel_data(pid, channel, data), do: GenServer.call(pid, {:channel_data, channel, data})

  @doc "The relayed transport address of this allocation."
  @spec relay_addr(pid()) :: StunTurn.address()
  def relay_addr(pid), do: GenServer.call(pid, :relay_addr)

  @doc "Stop the allocation (Delete Allocation / Refresh with lifetime 0)."
  @spec delete(pid()) :: :ok
  def delete(pid), do: GenServer.cast(pid, :delete)

  @impl true
  def init(opts) do
    server = Keyword.fetch!(opts, :server)
    client_key = Keyword.fetch!(opts, :client_key)
    # Bind all interfaces by default; advertise a reachable IP.
    bind_ip = Keyword.get(opts, :bind_ip, Keyword.get(opts, :relay_ip, {0, 0, 0, 0}))
    advertise_ip = Keyword.get(opts, :advertise_ip, bind_ip)
    lifetime = Keyword.fetch!(opts, :lifetime)

    case :gen_udp.open(0, [:binary, active: true, ip: bind_ip, reuseaddr: true]) do
      {:ok, socket} ->
        {:ok, {_bound_ip, bound_port}} = :inet.sockname(socket)
        timer = Process.send_after(self(), :expired, lifetime * 1000)

        {:ok,
         %__MODULE__{
           server: server,
           client_key: client_key,
           relay_socket: socket,
           relay_addr: {ip_family(advertise_ip), advertise_ip, bound_port},
           lifetime: lifetime,
           expiry_timer: timer
         }}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  def handle_call(:relay_addr, _from, state), do: {:reply, state.relay_addr, state}

  def handle_call({:refresh, lifetime}, _from, state) do
    if state.expiry_timer, do: Process.cancel_timer(state.expiry_timer)
    timer = Process.send_after(self(), :expired, lifetime * 1000)
    {:reply, {:ok, lifetime}, %{state | lifetime: lifetime, expiry_timer: timer}}
  end

  def handle_call({:create_permission, peer_ip}, _from, state) do
    expiry = System.system_time(:second) + @permission_lifetime
    {:reply, :ok, %{state | permissions: Map.put(state.permissions, peer_ip, expiry)}}
  end

  def handle_call({:channel_bind, channel, {peer_ip, peer_port}}, _from, state) do
    existing = Map.get(state.channels, channel)

    cond do
      channel < 0x4000 or channel > 0x7FFF ->
        {:reply, {:error, :bad_channel}, state}

      # The channel is already bound to a different peer.
      existing != nil and elem(existing, 0) != peer_ip ->
        {:reply, {:error, :channel_in_use}, state}

      true ->
        now = System.system_time(:second)
        expiry = now + @permission_lifetime

        state = %{
          state
          | channels:
              Map.put(state.channels, channel, {peer_ip, peer_port, now + @channel_lifetime}),
            channels_by_peer: Map.put(state.channels_by_peer, peer_ip, channel),
            permissions: Map.put(state.permissions, peer_ip, expiry)
        }

        {:reply, :ok, state}
    end
  end

  def handle_call({:send_to_peer, {peer_ip, peer_port}, data}, _from, state) do
    if permission?(state, peer_ip) do
      :gen_udp.send(state.relay_socket, peer_ip, peer_port, data)
      {:reply, :ok, state}
    else
      {:reply, {:error, :no_permission}, state}
    end
  end

  def handle_call({:channel_data, channel, data}, _from, state) do
    case Map.get(state.channels, channel) do
      {peer_ip, peer_port, expiry} ->
        if expiry > System.system_time(:second) do
          :gen_udp.send(state.relay_socket, peer_ip, peer_port, data)
          {:reply, :ok, state}
        else
          {:reply, {:error, :no_channel}, state}
        end

      nil ->
        {:reply, {:error, :no_channel}, state}
    end
  end

  @impl true
  def handle_cast(:delete, state) do
    {:stop, :normal, state}
  end

  @impl true
  def handle_info({:udp, socket, peer_ip, peer_port, data}, %{relay_socket: socket} = state) do
    if permission?(state, peer_ip) do
      datagram =
        case Map.get(state.channels_by_peer, peer_ip) do
          nil ->
            # Data indication: XOR-PEER-ADDRESS + DATA, no integrity
            # (RFC 5766 §10.3 — indications are not authenticated).
            tid = StunTurn.new_transaction_id()

            StunTurn.encode(%{
              type: StunTurn.data_indication(),
              transaction_id: tid,
              attrs: [
                {StunTurn.attr_xor_peer_address(),
                 {:xor, {ip_family(peer_ip), peer_ip, peer_port}, tid}},
                {StunTurn.attr_data(), data}
              ]
            })

          channel ->
            StunTurn.encode_channel_data(channel, data)
        end

      send(state.server, {:relay_to_client, state.client_key, datagram})
    end

    {:noreply, state}
  end

  def handle_info(:expired, state) do
    send(state.server, {:allocation_expired, state.client_key})
    {:stop, :normal, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    if state.relay_socket, do: :gen_udp.close(state.relay_socket)
    if state.expiry_timer, do: Process.cancel_timer(state.expiry_timer)
    :ok
  end

  # --- private ---

  defp permission?(state, peer_ip) do
    case Map.get(state.permissions, peer_ip) do
      nil -> false
      expiry -> expiry > System.system_time(:second)
    end
  end

  defp ip_family({_, _, _, _}), do: :ipv4
  defp ip_family({_, _, _, _, _, _, _, _}), do: :ipv6
end
