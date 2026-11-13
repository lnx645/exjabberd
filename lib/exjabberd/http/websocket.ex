defmodule Exjabberd.Http.WebSocket do
  @moduledoc """
  XMPP over WebSocket — RFC 7395 (subprotocol `xmpp`) on top of
  RFC 6455 framing.

  The HTTP server hands an upgraded socket to `serve/3` (a plain
  process, not a GenServer — it owns the socket and the XMPP
  transport). The process runs with `active: :once` and handles
  both TCP data and `{:xmpp_out, xml}` messages from the C2S
  session, so a stanza routed to this client is framed and sent
  immediately.

  Framing implemented: text + binary (treated as text) frames,
  continuation frames, ping → pong, close handshake, 16-bit and
  64-bit lengths, mandatory client masking. A masked frame from
  the client is unmasked; server frames are never masked
  (RFC 6455 §5.1). Payloads over 1 MiB are rejected with a close
  frame (1009).
  """

  require Logger

  alias Exjabberd.Http.XmppTransport

  @ws_guid "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
  @max_frame 1_048_576

  @doc "True when the request headers ask for a WebSocket upgrade to the `xmpp` subprotocol."
  @spec upgrade_request?(map()) :: boolean()
  def upgrade_request?(headers) do
    upgrade = Map.get(headers, "upgrade", "") |> String.downcase()
    connection = Map.get(headers, "connection", "") |> String.downcase()
    protocols = Map.get(headers, "sec-websocket-protocol", "")

    String.contains?(upgrade, "websocket") and String.contains?(connection, "upgrade") and
      protocols |> String.split(",") |> Enum.map(&String.trim/1) |> Enum.member?("xmpp") and
      Map.get(headers, "sec-websocket-key") not in [nil, ""]
  end

  @doc "101 Switching Protocols response headers for the handshake."
  @spec handshake_response(map()) :: {pos_integer(), [{binary(), binary()}], binary()}
  def handshake_response(headers) do
    key = Map.get(headers, "sec-websocket-key", "")

    accept =
      :crypto.hash(:sha, key <> @ws_guid) |> Base.encode64()

    {101,
     [
       {"Upgrade", "websocket"},
       {"Connection", "Upgrade"},
       {"Sec-WebSocket-Accept", accept},
       {"Sec-WebSocket-Protocol", "xmpp"}
     ], ""}
  end

  @doc "Take over an upgraded socket and run the XMPP-over-WebSocket session until it ends. `transport` is `:gen_tcp` (ws://) or `:ssl` (wss://)."
  @spec serve(:gen_tcp | :ssl, port(), binary(), binary()) :: :ok
  def serve(transport, sock, host, _peer) do
    receive do
      {:take_socket, ^sock} -> :ok
    after
      5_000 -> :ok
    end

    case XmppTransport.start(host, self()) do
      {:ok, xmpp} ->
        t_setopts(transport, sock, active: :once)
        loop(%{sock: sock, net: transport, transport: xmpp, buf: "", frag: nil, xmpp_buf: ""})

      {:error, reason} ->
        Logger.warning("WebSocket XMPP session start failed: #{inspect(reason)}")
        t_close(transport, sock)
        :ok
    end
  end

  defp t_setopts(:gen_tcp, sock, opts), do: :inet.setopts(sock, opts)
  defp t_setopts(:ssl, sock, opts), do: :ssl.setopts(sock, opts)
  defp t_close(:gen_tcp, sock), do: :gen_tcp.close(sock)
  defp t_close(:ssl, sock), do: :ssl.close(sock)
  defp t_send(:gen_tcp, sock, data), do: :gen_tcp.send(sock, data)
  defp t_send(:ssl, sock, data), do: :ssl.send(sock, data)

  defp loop(state) do
    receive do
      {:tcp, sock, data} when sock == state.sock ->
        on_data(state, data)

      {:ssl, sock, data} when sock == state.sock ->
        on_data(state, data)

      {:tcp_closed, sock} when sock == state.sock ->
        cleanup(state)

      {:ssl_closed, sock} when sock == state.sock ->
        cleanup(state)

      {:tcp_error, sock, _} when sock == state.sock ->
        cleanup(state)

      {:ssl_error, sock, _} when sock == state.sock ->
        cleanup(state)

      {:xmpp_out, xml} ->
        send_frame(state.net, state.sock, 0x1, xml)
        loop(state)

      _other ->
        loop(state)
    after
      300_000 ->
        # Idle 5 minutes with no traffic: close politely.
        cleanup(state)
    end
  end

  defp on_data(state, data) do
    t_setopts(state.net, state.sock, active: :once)
    state = %{state | buf: state.buf <> data}

    case process_frames(state) do
      {:ok, state} -> loop(state)
      {:closed, state} -> cleanup(state)
    end
  end

  defp cleanup(state) do
    XmppTransport.close(state.transport)

    try do
      t_close(state.net, state.sock)
    catch
      _, _ -> :ok
    end

    :ok
  end

  # --- frame parsing ---

  defp process_frames(state) do
    case parse_frame(state.buf) do
      {:ok, frame, rest} ->
        state = %{state | buf: rest}

        case handle_frame(frame, state) do
          {:ok, state} -> process_frames(state)
          {:closed, state} -> {:closed, state}
        end

      {:incomplete, _} ->
        {:ok, state}

      {:error, :too_large} ->
        send_frame(state.net, state.sock, 0x8, <<1009::16>>)
        {:closed, state}

      {:error, _} ->
        {:closed, state}
    end
  end

  defp handle_frame(%{opcode: 0x8, payload: payload}, state) do
    # Close: echo the close frame and end.
    send_frame(state.net, state.sock, 0x8, payload)
    {:closed, state}
  end

  defp handle_frame(%{opcode: 0x9, payload: payload}, state) do
    send_frame(state.net, state.sock, 0xA, payload)
    {:ok, state}
  end

  defp handle_frame(%{opcode: 0xA}, state), do: {:ok, state}

  defp handle_frame(%{opcode: opcode, fin: fin, payload: payload}, state)
       when opcode in [0x1, 0x2, 0x0] do
    cond do
      opcode == 0x0 and state.frag == nil ->
        # Continuation with nothing to continue.
        {:closed, state}

      fin ->
        text = (state.frag || "") <> payload
        handle_text(%{state | frag: nil}, text)

      true ->
        {:ok, %{state | frag: (state.frag || "") <> payload}}
    end
  end

  defp handle_frame(_frame, state), do: {:ok, state}

  defp handle_text(state, text) do
    buf = state.xmpp_buf <> text

    case XmppTransport.parse_buffer(buf, state.transport.max_size) do
      {:ok, units, rest} ->
        state = %{state | xmpp_buf: rest}

        Enum.reduce_while(units, {:ok, state}, fn unit, {:ok, acc} ->
          case XmppTransport.handle_unit(acc.transport, unit) do
            {:ok, transport, outs} ->
              Enum.each(outs, &send_frame(acc.net, acc.sock, 0x1, &1))
              {:cont, {:ok, %{acc | transport: transport}}}

            {:closed, transport, outs} ->
              Enum.each(outs, &send_frame(acc.net, acc.sock, 0x1, &1))
              {:halt, {:closed, %{acc | transport: transport}}}
          end
        end)

      {:error, _} ->
        {:closed, state}
    end
  end

  # Parse one frame from the front of the buffer.
  # Returns {:ok, frame, rest} | {:incomplete, buf} | {:error, reason}.
  defp parse_frame(buf) when byte_size(buf) < 2, do: {:incomplete, buf}

  defp parse_frame(<<fin::1, _rsv::3, opcode::4, mask::1, len7::7, rest::binary>> = buf) do
    with {:len, len, rest} <- read_length(len7, rest, buf),
         {:mask, mask_key, rest} <- read_mask(mask, rest, buf),
         true <- len <= @max_frame or {:error, :too_large},
         true <- byte_size(rest) >= len or {:incomplete, buf} do
      <<payload::binary-size(len), tail::binary>> = rest
      payload = if mask_key, do: unmask(payload, mask_key), else: payload
      {:ok, %{fin: fin == 1, opcode: opcode, payload: payload}, tail}
    end
  end

  defp parse_frame(_buf), do: {:error, :malformed}

  defp read_length(126, rest, buf) do
    if byte_size(rest) < 2, do: {:incomplete, buf}, else: (<<len::16, r::binary>> = rest; {:len, len, r})
  end

  defp read_length(127, rest, buf) do
    if byte_size(rest) < 8, do: {:incomplete, buf}, else: (<<len::64, r::binary>> = rest; {:len, len, r})
  end

  defp read_length(n, rest, _buf), do: {:len, n, rest}

  defp read_mask(1, rest, buf) do
    if byte_size(rest) < 4,
      do: {:incomplete, buf},
      else: (<<key::binary-size(4), r::binary>> = rest; {:mask, key, r})
  end

  defp read_mask(0, rest, _buf), do: {:mask, nil, rest}

  defp unmask(payload, <<m0, m1, m2, m3>>) do
    payload
    |> :binary.bin_to_list()
    |> Enum.with_index()
    |> Enum.map(fn {b, i} ->
      mask_byte =
        case rem(i, 4) do
          0 -> m0
          1 -> m1
          2 -> m2
          3 -> m3
        end

      Bitwise.bxor(b, mask_byte)
    end)
    |> :binary.list_to_bin()
  end

  defp send_frame(net, sock, opcode, payload) when is_binary(payload) do
    header =
      case byte_size(payload) do
        len when len < 126 ->
          <<1::1, 0::3, opcode::4, 0::1, len::7>>

        len when len < 65_536 ->
          <<1::1, 0::3, opcode::4, 0::1, 126::7, len::16>>

        len ->
          <<1::1, 0::3, opcode::4, 0::1, 127::7, len::64>>
      end

    case t_send(net, sock, header <> payload) do
      :ok -> :ok
      {:error, reason} -> Logger.debug("WebSocket send failed: #{inspect(reason)}")
    end
  end
end
