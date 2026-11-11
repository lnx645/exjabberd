defmodule Exjabberd.Mqtt.Connection do
  @moduledoc """
  One MQTT client connection: owns the TCP socket, decodes the byte
  stream with `Exjabberd.Mqtt.Codec`, drives the CONNECT handshake
  (authentication against `Exjabberd.Auth`), and hands publishes to
  `Exjabberd.Mqtt.Broker`.

  The process is a plain spawned loop (like the C2S serve loop): the
  socket is `active: :once`, deliveries from the broker arrive as
  `{:mqtt_publish, packet}` messages, and the keep-alive timer is a
  `send_after` reset on every received packet — a silent client is
  disconnected after 1.5 × keep alive (§3.1.2.10) and its Will message
  is published (§3.1.2.5).

  A client that sends DISCONNECT goes away cleanly (no Will). Any
  other close — socket error, keep-alive timeout, protocol error,
  takeover by a second connection with the same client id — publishes
  the Will first, unless the takeover message says otherwise (a
  takeover is a session replacement, not a failure, so no Will).
  """

  require Logger

  alias Exjabberd.Mqtt.{Broker, Codec}

  @connect_timeout_ms 10_000

  @type state :: %{
          socket: :gen_tcp.socket(),
          host: binary(),
          buffer: binary(),
          connected: boolean(),
          client_id: binary() | nil,
          clean_session: boolean(),
          keep_alive: non_neg_integer(),
          username: binary() | nil,
          will: map() | nil,
          keepalive_timer: reference() | nil,
          connect_timer: reference() | nil,
          closing: boolean()
        }

  @doc "Spawn the connection loop for an accepted socket (the caller transfers socket ownership first)."
  @spec start(:gen_tcp.socket(), binary()) :: pid()
  def start(socket, host) do
    spawn(fn ->
      receive do
        {:take_socket, ^socket} -> :ok
      after
        5_000 -> :ok
      end

      :inet.setopts(socket, active: :once)
      timer = Process.send_after(self(), :connect_timeout, @connect_timeout_ms)

      loop(%{
        socket: socket,
        host: host,
        buffer: <<>>,
        connected: false,
        client_id: nil,
        clean_session: true,
        keep_alive: 0,
        username: nil,
        will: nil,
        keepalive_timer: nil,
        connect_timer: timer,
        closing: false
      })
    end)
  end

  # --- loop -----------------------------------------------------------

  defp loop(%{closing: true} = state) do
    # Drain nothing — the socket is already closed or closing.
    _ = state
    :ok
  end

  defp loop(state) do
    receive do
      {:tcp, socket, data} when socket == state.socket ->
        :inet.setopts(socket, active: :once)
        state = %{state | buffer: state.buffer <> data}
        state = handle_buffer(state)

        if state.closing do
          loop(%{state | closing: true})
        else
          loop(state)
        end

      {:tcp_closed, socket} when socket == state.socket ->
        abnormal_close(state)

      {:tcp_error, socket, _reason} when socket == state.socket ->
        abnormal_close(state)

      {:mqtt_publish, packet} ->
        send_packet(state, packet)
        loop(state)

      :mqtt_takeover ->
        # Session taken over by a new connection with the same client
        # id: close quietly, no Will (§3.1.2.4 — the session lives on).
        close_quietly(state)

      :connect_timeout ->
        if state.connected do
          loop(state)
        else
          Logger.debug("mqtt: client never sent CONNECT, closing")
          close_quietly(state)
        end

      {:keepalive_timeout, ref} ->
        if state.connected and state.keepalive_timer == ref do
          Logger.debug("mqtt: keep-alive timeout for #{state.client_id}, closing")
          abnormal_close(state)
        else
          # Stale timer: a packet arrived after it was scheduled.
          loop(state)
        end
    end
  end

  # --- inbound bytes --------------------------------------------------

  defp handle_buffer(state) do
    case Codec.decode(state.buffer) do
      {:ok, packet, rest} ->
        state = %{state | buffer: rest}
        state = handle_packet(state, packet)

        if state.closing or rest == <<>> do
          state
        else
          handle_buffer(state)
        end

      {:incomplete, _} ->
        state

      {:error, reason} ->
        Logger.debug("mqtt: protocol error #{inspect(reason)} from #{inspect(state.client_id)}, closing")
        state = maybe_refuse_connect(state, reason)
        close_abnormal_now(state)
    end
  end

  defp handle_packet(%{connected: false} = state, %{type: :connect} = packet) do
    if state.connect_timer, do: Process.cancel_timer(state.connect_timer)
    handle_connect(state, packet)
  end

  defp handle_packet(%{connected: false} = state, _packet) do
    # The first packet must be CONNECT (§3.1).
    Logger.debug("mqtt: first packet was not CONNECT, closing")
    close_abnormal_now(state)
  end

  defp handle_packet(state, %{type: :disconnect}) do
    # Clean disconnect: no Will (§3.14).
    if state.client_id, do: Broker.client_gone(state.client_id, :clean)
    close_socket(state)
    %{state | closing: true}
  end

  defp handle_packet(state, %{type: :pingreq}) do
    state = reset_keepalive(state)
    send_packet(state, %{type: :pingresp})
    state
  end

  defp handle_packet(state, %{type: :publish} = packet) do
    state = reset_keepalive(state)
    handle_publish(state, packet)
  end

  defp handle_packet(state, %{type: :subscribe} = packet) do
    state = reset_keepalive(state)
    granted = Broker.subscribe(state.client_id, self(), packet.topics)
    send_packet(state, %{type: :suback, packet_id: packet.packet_id, granted: granted})
    state
  end

  defp handle_packet(state, %{type: :unsubscribe} = packet) do
    state = reset_keepalive(state)
    Broker.unsubscribe(state.client_id, packet.topics)
    send_packet(state, %{type: :unsuback, packet_id: packet.packet_id})
    state
  end

  defp handle_packet(state, %{type: :puback}) do
    reset_keepalive(state)
  end

  defp handle_packet(state, %{type: :pubrec, packet_id: packet_id}) do
    state = reset_keepalive(state)
    # Our QoS 2 delivery was received: answer PUBREL (§4.3.3).
    Broker.out_qos2_pubrec(state.client_id, packet_id)
    send_packet(state, %{type: :pubrel, packet_id: packet_id})
    state
  end

  defp handle_packet(state, %{type: :pubrel, packet_id: packet_id}) do
    state = reset_keepalive(state)

    case Broker.release_in_qos2(state.client_id, packet_id) do
      {:ok, packet} ->
        Broker.publish(packet.topic, packet.payload, packet.qos, packet.retain)

      :error ->
        :ok
    end

    send_packet(state, %{type: :pubcomp, packet_id: packet_id})
    state
  end

  defp handle_packet(state, %{type: :pubcomp, packet_id: packet_id}) do
    state = reset_keepalive(state)
    Broker.out_qos2_pubcomp(state.client_id, packet_id)
    state
  end

  defp handle_packet(state, %{type: :connect}) do
    # A second CONNECT on one connection is a protocol error (§3.1).
    Logger.debug("mqtt: second CONNECT, closing")
    close_abnormal_now(state)
  end

  defp handle_packet(state, _other) do
    reset_keepalive(state)
  end

  # §3.1.4: a CONNECT that fails validation is answered with a CONNACK
  # carrying the reason, and only then is the connection closed.
  # Unacceptable protocol version → 0x01; client id rejected → 0x02.
  # Any other protocol error just closes the connection.
  defp maybe_refuse_connect(%{connected: false} = state, :unacceptable_protocol_version) do
    send_packet(state, %{type: :connack, session_present: false, return_code: 1})
    state
  end

  defp maybe_refuse_connect(%{connected: false} = state, :empty_client_id_without_clean_session) do
    send_packet(state, %{type: :connack, session_present: false, return_code: 2})
    state
  end

  defp maybe_refuse_connect(state, _reason), do: state

  # --- CONNECT ----------------------------------------------------------

  defp handle_connect(state, packet) do
    case authenticate(state, packet) do
      {:ok, _session_present} ->
        will =
          if packet.will_flag do
            %{
              topic: packet.will_topic,
              payload: packet.will_message,
              qos: packet.will_qos,
              retain: packet.will_retain
            }
          else
            nil
          end

        case Broker.register(packet.client_id, self(), packet.clean_session,
               username: packet.username,
               will: will
             ) do
          {:ok, session_present} ->
            state = %{
              state
              | connected: true,
                client_id: packet.client_id,
                clean_session: packet.clean_session,
                keep_alive: packet.keep_alive,
                username: packet.username,
                will: will,
                connect_timer: nil
            }

            state = reset_keepalive(state)
            send_packet(state, %{type: :connack, session_present: session_present, return_code: 0})
            state

          {:error, :max_clients} ->
            send_packet(state, %{type: :connack, session_present: false, return_code: 5})
            close_socket(state)
            %{state | closing: true}
        end

      {:error, return_code} ->
        send_packet(state, %{type: :connack, session_present: false, return_code: return_code})
        close_socket(state)
        %{state | closing: true}
    end
  end

  defp authenticate(state, packet) do
    cond do
      packet.username not in [nil, ""] ->
        {user, host} = split_username(packet.username, state.host)
        password = packet.password || ""

        if Exjabberd.Auth.authenticate(host, user, password) do
          {:ok, false}
        else
          {:error, 5}
        end

      Exjabberd.Mqtt.config(:allow_anonymous, true) ->
        {:ok, false}

      true ->
        {:error, 5}
    end
  end

  defp split_username(username, default_host) do
    case String.split(username, "@") do
      [user] ->
        {user, default_host}

      parts ->
        {domain, user_parts} = {List.last(parts), Enum.drop(parts, -1)}
        user = Enum.join(user_parts, "@")

        if domain in Exjabberd.Config.hosts() do
          {user, domain}
        else
          {username, default_host}
        end
    end
  end

  # --- PUBLISH ---------------------------------------------------------

  defp handle_publish(state, packet) do
    cond do
      byte_size(packet.payload) > Exjabberd.Mqtt.config(:max_payload, 262_144) ->
        Logger.debug("mqtt: payload over max_payload from #{state.client_id}, closing")
        close_abnormal_now(state)

      packet.qos == 0 ->
        Broker.publish(packet.topic, packet.payload, 0, packet.retain)
        state

      packet.qos == 1 ->
        Broker.publish(packet.topic, packet.payload, 1, packet.retain)
        send_packet(state, %{type: :puback, packet_id: packet.packet_id})
        state

      packet.qos == 2 ->
        case Broker.store_in_qos2(state.client_id, packet.packet_id, packet) do
          :ok -> :ok
          # Duplicate PUBLISH (§4.3.3): PUBREC again, do not re-publish.
          :duplicate -> :ok
        end

        send_packet(state, %{type: :pubrec, packet_id: packet.packet_id})
        state
    end
  end

  # --- timers / socket --------------------------------------------------

  defp reset_keepalive(state) do
    if state.keepalive_timer, do: Process.cancel_timer(state.keepalive_timer)

    if state.connected and state.keep_alive > 0 do
      ref = make_ref()
      Process.send_after(self(), {:keepalive_timeout, ref}, trunc(state.keep_alive * 1.5 * 1000))
      %{state | keepalive_timer: ref}
    else
      %{state | keepalive_timer: nil}
    end
  end

  defp send_packet(state, packet) do
    :gen_tcp.send(state.socket, Codec.encode(packet))
    :ok
  end

  defp close_socket(state) do
    :gen_tcp.close(state.socket)
    :ok
  end

  defp close_quietly(state) do
    if state.client_id, do: Broker.client_gone(state.client_id, :clean)
    close_socket(state)
    :ok
  end

  defp close_abnormal_now(state) do
    abnormal_close(state)
    %{state | closing: true}
  end

  defp abnormal_close(state) do
    if state.client_id do
      Broker.client_gone(state.client_id, :abnormal)
    end

    close_socket(state)
    :ok
  end
end
