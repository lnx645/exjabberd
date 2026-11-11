defmodule Exjabberd.StunTurn.TcpConnection do
  @moduledoc """
  One TURN-over-TCP client connection (RFC 5766 §7.2).

  STUN messages and ChannelData share the same framing on TCP:
  the first two bytes are the message type (STUN) or the channel
  number (ChannelData, `0x4000..0x7FFF`), the next two are the
  length. This process buffers bytes until a complete frame is
  available, hands it to the STUN/TURN server for processing, and
  dies — dropping the client's allocations — when the socket
  closes.
  """

  use GenServer
  require Logger

  defstruct [:socket, :server, :client_key, buffer: ""]

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @impl true
  def init(opts) do
    {:ok,
     %__MODULE__{
       socket: Keyword.fetch!(opts, :socket),
       server: Keyword.fetch!(opts, :server),
       client_key: Keyword.fetch!(opts, :client_key)
     }}
  end

  @impl true
  def handle_cast(:start_reading, state) do
    :inet.setopts(state.socket, active: :once)
    {:noreply, state}
  end

  @impl true
  def handle_info({:tcp, socket, data}, %{socket: socket} = state) do
    :inet.setopts(socket, active: :once)
    state = %{state | buffer: state.buffer <> data}
    {:noreply, drain_frames(state)}
  end

  def handle_info({:tcp_closed, socket}, %{socket: socket} = state) do
    GenServer.call(state.server, {:tcp_closed, state.client_key})
    {:stop, :normal, state}
  end

  def handle_info({:tcp_error, socket, _reason}, %{socket: socket} = state) do
    GenServer.call(state.server, {:tcp_closed, state.client_key})
    {:stop, :normal, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    if state.socket, do: :gen_tcp.close(state.socket)
    :ok
  end

  # Pull complete frames out of the buffer and hand each to the server.
  defp drain_frames(state) do
    case next_frame(state.buffer) do
      {:ok, frame, rest} ->
        GenServer.call(state.server, {:tcp_frame, state.client_key, frame})
        drain_frames(%{state | buffer: rest})

      :incomplete ->
        state
    end
  end

  defp next_frame(bin) when byte_size(bin) >= 4 do
    <<first::16, len::16, _::binary>> = bin

    cond do
      # ChannelData (first two bits `01`): 4-byte header, the data
      # itself is padded to a 4-byte boundary (RFC 5766 §11.5).
      first >= 0x4000 and first <= 0x7FFF ->
        padded = len + rem(4 - rem(len, 4), 4)

        if byte_size(bin) >= 4 + padded do
          <<frame::binary-size(4 + padded), tail::binary>> = bin
          {:ok, frame, tail}
        else
          :incomplete
        end

      # STUN message (first two bits `00`): 20-byte header, the
      # length counts the attributes only (RFC 5766 §7.2).
      first < 0x4000 ->
        if byte_size(bin) >= 20 + len do
          <<frame::binary-size(20 + len), tail::binary>> = bin
          {:ok, frame, tail}
        else
          :incomplete
        end

      true ->
        :incomplete
    end
  end

  defp next_frame(_), do: :incomplete
end
