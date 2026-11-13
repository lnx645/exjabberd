defmodule Exjabberd.Mqtt.Connection do
  @moduledoc """
  One MQTT client connection (v3.1.1 or v5.0, negotiated by the
  CONNECT Protocol Level): owns the TCP socket, decodes the byte
  stream with `Exjabberd.Mqtt.Codec`, drives the CONNECT handshake
  (authentication against `Exjabberd.Auth`), and hands publishes to
  `Exjabberd.Mqtt.Broker`.

  The process is a plain spawned loop (like the C2S serve loop): the
  socket is `active: :once`, deliveries from the broker arrive as
  `{:mqtt_publish, packet}` messages, and the keep-alive timer is a
  `send_after` reset on every received packet — a silent client is
  disconnected after 1.5 × keep alive (§3.1.2.10) and its Will message
  is published (§3.1.2.5).

  A client that sends DISCONNECT goes away cleanly (no Will, except
  for a v5 DISCONNECT with reason 0x04, which publishes it). Any
  other close — socket error, keep-alive timeout, protocol error,
  takeover by a second connection with the same client id — publishes
  the Will first, unless the takeover message says otherwise (a
  takeover is a session replacement, not a failure, so no Will).
  Broker calls carry this process's pid, so a taken-over connection's
  late teardown can never disturb the session's new owner.

  ## v5.0 specifics

  * CONNACK carries the negotiated limits: Receive Maximum,
    Maximum Packet Size (`mqtt.max_payload` + framing allowance),
    Topic Alias Maximum (#{16}), Retain/Wildcard/Subscription
    Identifier/Shared Subscription availability.
  * An empty ClientId is assigned one (`Assigned Client Identifier`).
  * Enhanced authentication is not offered: a CONNECT naming an
    Authentication Method is refused with CONNACK reason 0x8C, and a
    stray AUTH packet closes the connection with DISCONNECT 0x82.
  * Inbound Topic Aliases are resolved per connection (an unknown
    alias is DISCONNECT 0x94); Payload Format Indicator 1 payloads
    must be valid UTF-8 (else DISCONNECT 0x99).
  * Outbound flow control honors the client's Receive Maximum
    (excess QoS 1/2 deliveries queue in order) and Maximum Packet
    Size (oversize deliveries are dropped, never sent).
  * Protocol errors after CONNECT are answered with a v5 DISCONNECT
    carrying the mapped reason code before the connection closes.
  """

  require Logger

  alias Exjabberd.Mqtt.{Broker, Codec}

  @connect_timeout_ms 10_000
  @topic_alias_maximum 16

  @type state :: %{
          socket: :gen_tcp.socket(),
          host: binary(),
          buffer: binary(),
          connected: boolean(),
          version: 4 | 5,
          client_id: binary() | nil,
          clean_session: boolean(),
          session_expiry: non_neg_integer() | :infinity | nil,
          keep_alive: non_neg_integer(),
          username: binary() | nil,
          will: map() | nil,
          aliases: %{optional(non_neg_integer()) => binary()},
          client_max_packet: non_neg_integer() | nil,
          receive_maximum: pos_integer(),
          out_inflight: MapSet.t(),
          out_pending: :queue.queue(),
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
        version: 4,
        client_id: nil,
        clean_session: true,
        session_expiry: nil,
        keep_alive: 0,
        username: nil,
        will: nil,
        aliases: %{},
        client_max_packet: nil,
        receive_maximum: 65_535,
        out_inflight: MapSet.new(),
        out_pending: :queue.new(),
        keepalive_timer: nil,
        connect_timer: timer,
        closing: false
      })
    end)
  end

  # The largest packet we accept from (and advertise to) a v5 client:
  # the configured payload cap plus framing allowance.
  defp advertised_max_packet_size do
    Exjabberd.Mqtt.config(:max_payload, 262_144) + 4096
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
        loop(deliver_out(state, packet))

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
          if state.version == 5 do
            send_packet(state, %{type: :disconnect, reason_code: 0x8D})
          end

          abnormal_close(state)
        else
          # Stale timer: a packet arrived after it was scheduled.
          loop(state)
        end
    end
  end

  # --- inbound bytes --------------------------------------------------

  defp handle_buffer(state) do
    opts =
      if state.version == 5 and state.connected do
        [max_packet_size: advertised_max_packet_size()]
      else
        []
      end

    case Codec.decode(state.buffer, state.version, opts) do
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
        state = maybe_refuse(state, reason)
        close_abnormal_now(state)
    end
  end

  # §3.1.4 (v3.1.1): a CONNECT that fails validation is answered with
  # a CONNACK carrying the reason, and only then is the connection
  # closed. Unacceptable protocol version → 0x01; client id rejected
  # → 0x02. After a v5 CONNECT, protocol errors are answered with a
  # DISCONNECT carrying the mapped reason code (§4.13).
  defp maybe_refuse(%{connected: false} = state, :unacceptable_protocol_version) do
    send_packet(state, %{type: :connack, session_present: false, return_code: 1})
    state
  end

  defp maybe_refuse(%{connected: false} = state, :empty_client_id_without_clean_session) do
    send_packet(state, %{type: :connack, session_present: false, return_code: 2})
    state
  end

  defp maybe_refuse(%{connected: true, version: 5} = state, reason) do
    send_packet(state, %{type: :disconnect, reason_code: disconnect_reason(reason)})
    state
  end

  defp maybe_refuse(state, _reason), do: state

  defp disconnect_reason(:packet_too_large), do: 0x95
  defp disconnect_reason(:invalid_topic_alias), do: 0x94
  defp disconnect_reason(:bad_string), do: 0x81
  defp disconnect_reason(:unknown_property), do: 0x81
  defp disconnect_reason(:bad_properties), do: 0x81
  defp disconnect_reason(:duplicate_property), do: 0x81
  defp disconnect_reason(:property_not_allowed), do: 0x81
  defp disconnect_reason(:bad_property_value), do: 0x81
  defp disconnect_reason(_other), do: 0x82

  # --- packet dispatch ---------------------------------------------------

  defp handle_packet(%{connected: false} = state, %{type: :connect} = packet) do
    if state.connect_timer, do: Process.cancel_timer(state.connect_timer)
    handle_connect(state, packet)
  end

  defp handle_packet(%{connected: false} = state, _packet) do
    # The first packet must be CONNECT (§3.1).
    Logger.debug("mqtt: first packet was not CONNECT, closing")
    close_abnormal_now(state)
  end

  defp handle_packet(state, %{type: :disconnect} = packet) do
    handle_disconnect(state, packet)
  end

  defp handle_packet(state, %{type: :pingreq}) do
    state = reset_keepalive(state)
    send_packet(state, %{type: :pingresp})
    state
  end

  defp handle_packet(state, %{type: :publish} = packet) do
    state = reset_keepalive(state)

    case resolve_publish(state, packet) do
      {:ok, state, packet} -> handle_publish(state, packet)
      {:error, state} -> state
    end
  end

  defp handle_packet(state, %{type: :subscribe} = packet) do
    state = reset_keepalive(state)

    sub_opts =
      case Map.get(packet, :properties) do
        %{subscription_identifiers: [id | _]} -> [subscription_identifier: id]
        _ -> []
      end

    granted = Broker.subscribe(state.client_id, self(), packet.topics, sub_opts)

    granted =
      if state.version == 5 do
        # v5 reason code for an invalid filter is 0x8F, not 0x80.
        Enum.map(granted, fn 0x80 -> 0x8F; code -> code end)
      else
        granted
      end

    send_packet(state, %{type: :suback, packet_id: packet.packet_id, granted: granted})
    state
  end

  defp handle_packet(state, %{type: :unsubscribe} = packet) do
    state = reset_keepalive(state)

    if state.version == 5 do
      codes = Broker.unsubscribe_codes(state.client_id, packet.topics)
      send_packet(state, %{type: :unsuback, packet_id: packet.packet_id, codes: codes})
    else
      Broker.unsubscribe(state.client_id, packet.topics)
      send_packet(state, %{type: :unsuback, packet_id: packet.packet_id})
    end

    state
  end

  defp handle_packet(state, %{type: :puback, packet_id: packet_id}) do
    state = reset_keepalive(state)
    state |> ack_outbound(packet_id) |> flush_pending()
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
        Broker.publish(packet.topic, packet.payload, packet.qos, packet.retain,
          publish_opts(state, packet)
        )

      :error ->
        :ok
    end

    ack =
      if state.version == 5,
        do: %{type: :pubcomp, packet_id: packet_id, reason_code: 0},
        else: %{type: :pubcomp, packet_id: packet_id}

    send_packet(state, ack)
    state
  end

  defp handle_packet(state, %{type: :pubcomp, packet_id: packet_id}) do
    state = reset_keepalive(state)
    Broker.out_qos2_pubcomp(state.client_id, packet_id)
    state |> ack_outbound(packet_id) |> flush_pending()
  end

  defp handle_packet(state, %{type: :auth}) do
    # We never start enhanced authentication, so an AUTH packet is a
    # protocol error (v5 §3.15).
    if state.version == 5 do
      send_packet(state, %{type: :disconnect, reason_code: 0x82})
    end

    close_abnormal_now(state)
  end

  defp handle_packet(state, %{type: :connect}) do
    # A second CONNECT on one connection is a protocol error (§3.1).
    Logger.debug("mqtt: second CONNECT, closing")

    if state.version == 5 do
      send_packet(state, %{type: :disconnect, reason_code: 0x82})
    end

    close_abnormal_now(state)
  end

  defp handle_packet(state, _other) do
    reset_keepalive(state)
  end

  # --- DISCONNECT ----------------------------------------------------------

  defp handle_disconnect(%{version: 5} = state, packet) do
    reason = Map.get(packet, :reason_code, 0)
    props = Map.get(packet, :properties, %{})

    expiry_opt =
      case Map.fetch(props, :session_expiry_interval) do
        :error ->
          []

        {:ok, seconds} ->
          negotiated = state.session_expiry

          if is_integer(negotiated) and seconds > negotiated do
            # MQTT-3.14.2.1: the client MUST NOT raise the session
            # expiry at DISCONNECT — protocol error, ungraceful close.
            Logger.debug("mqtt: DISCONNECT raised session expiry for #{state.client_id}")
            close_abnormal_now(state)
            :raised
          else
            [session_expiry: seconds]
          end
      end

    if expiry_opt == :raised do
      %{state | closing: true}
    else
      gone_reason = if reason == 0x04, do: :disconnect_will, else: :clean
      opts = [from_pid: self()] ++ expiry_opt
      if state.client_id, do: Broker.client_gone(state.client_id, gone_reason, opts)
      close_socket(state)
      %{state | closing: true}
    end
  end

  defp handle_disconnect(state, _packet) do
    # v3.1.1 clean disconnect: no Will (§3.14).
    if state.client_id, do: Broker.client_gone(state.client_id, :clean, from_pid: self())
    close_socket(state)
    %{state | closing: true}
  end

  # --- CONNECT ----------------------------------------------------------

  defp handle_connect(state, %{version: 5} = packet) do
    props = packet.properties
    state = %{state | version: 5}

    cond do
      Map.has_key?(props, :authentication_method) ->
        # Enhanced authentication is not supported: refuse with
        # 0x8C (Bad authentication method, §3.2.2.2).
        refuse_v5(state, 0x8C)

      true ->
        {client_id, assigned} =
          if packet.client_id == "" do
            {"exj5-" <> Base.encode16(:crypto.strong_rand_bytes(6), case: :lower), true}
          else
            {packet.client_id, false}
          end

        session_expiry = Map.get(props, :session_expiry_interval, 0)

        register_opts = [
          session_expiry: if(session_expiry == 0xFFFF_FFFF, do: :infinity, else: session_expiry)
        ]

        finish_connect(state, packet, client_id, register_opts,
          on_auth_error: 0x86,
          on_anon_error: 0x87,
          on_full_error: 0x88,
          connack: fn session_present ->
            connack_props =
              %{
                receive_maximum: 65_535,
                maximum_packet_size: advertised_max_packet_size(),
                topic_alias_maximum: @topic_alias_maximum,
                retain_available: 1,
                wildcard_subscription_available: 1,
                subscription_identifier_available: 1,
                shared_subscription_available: 1
              }
              |> then(fn p ->
                if assigned,
                  do: Map.put(p, :assigned_client_identifier, client_id),
                  else: p
              end)
              |> then(fn p ->
                if Map.has_key?(props, :session_expiry_interval),
                  do: Map.put(p, :session_expiry_interval, session_expiry),
                  else: p
              end)

            %{
              type: :connack,
              session_present: session_present,
              reason_code: 0,
              properties: connack_props
            }
          end,
          session_expiry: session_expiry
        )
    end
  end

  defp handle_connect(state, packet) do
    finish_connect(state, packet, packet.client_id, [],
      on_auth_error: 5,
      on_anon_error: 5,
      on_full_error: 5,
      connack: fn session_present ->
        %{type: :connack, session_present: session_present, return_code: 0}
      end,
      session_expiry: nil
    )
  end

  defp refuse_v5(state, reason_code) do
    send_packet(state, %{
      type: :connack,
      session_present: false,
      reason_code: reason_code,
      properties: %{}
    })

    close_socket(state)
    %{state | closing: true}
  end

  defp finish_connect(state, packet, client_id, register_opts, outcome) do
    case authenticate(state, packet) do
      {:ok, _session_present} ->
        will = build_will(packet)

        register_opts =
          register_opts ++ [username: packet.username, will: will]

        case Broker.register(client_id, self(), packet.clean_session, register_opts) do
          {:ok, session_present} ->
            props = Map.get(packet, :properties, %{})

            state = %{
              state
              | connected: true,
                client_id: client_id,
                clean_session: packet.clean_session,
                session_expiry: outcome[:session_expiry],
                keep_alive: packet.keep_alive,
                username: packet.username,
                will: will,
                client_max_packet: Map.get(props, :maximum_packet_size),
                receive_maximum: Map.get(props, :receive_maximum, 65_535),
                connect_timer: nil
            }

            state = reset_keepalive(state)
            send_packet(state, outcome[:connack].(session_present))
            state

          {:error, :max_clients} ->
            if state.version == 5 do
              refuse_v5(state, outcome[:on_full_error])
            else
              send_packet(state, %{type: :connack, session_present: false, return_code: outcome[:on_full_error]})
              close_socket(state)
              %{state | closing: true}
            end
        end

      {:error, kind} ->
        code = if kind == :anon, do: outcome[:on_anon_error], else: outcome[:on_auth_error]

        if state.version == 5 do
          refuse_v5(state, code)
        else
          send_packet(state, %{type: :connack, session_present: false, return_code: code})
          close_socket(state)
          %{state | closing: true}
        end
    end
  end

  defp build_will(%{will_flag: false}), do: nil

  defp build_will(packet) do
    will_props = Map.get(packet, :will_properties, %{})

    %{
      topic: packet.will_topic,
      payload: packet.will_message,
      qos: packet.will_qos,
      retain: packet.will_retain,
      delay: Map.get(will_props, :will_delay_interval, 0),
      properties: pass_through_props(will_props),
      message_expiry: Map.get(will_props, :message_expiry_interval)
    }
  end

  defp authenticate(state, packet) do
    cond do
      packet.username not in [nil, ""] ->
        {user, host} = split_username(packet.username, state.host)
        password = packet.password || ""

        if Exjabberd.Auth.authenticate(host, user, password) do
          {:ok, false}
        else
          {:error, :auth}
        end

      Exjabberd.Mqtt.config(:allow_anonymous, true) ->
        {:ok, false}

      true ->
        {:error, :anon}
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

  # Resolve a v5 Topic Alias: an empty topic takes the alias's stored
  # topic; a full topic together with an alias (re)binds it. Unknown
  # or out-of-range aliases are a protocol error (DISCONNECT 0x94).
  defp resolve_publish(%{version: 5} = state, packet) do
    props = Map.get(packet, :properties, %{})
    alias_id = Map.get(props, :topic_alias)

    cond do
      alias_id != nil and (alias_id < 1 or alias_id > @topic_alias_maximum) ->
        alias_error(state)

      packet.topic == "" and alias_id != nil ->
        case Map.fetch(state.aliases, alias_id) do
          {:ok, topic} -> {:ok, state, %{packet | topic: topic}}
          :error -> alias_error(state)
        end

      alias_id != nil ->
        {:ok, %{state | aliases: Map.put(state.aliases, alias_id, packet.topic)}, packet}

      true ->
        {:ok, state, packet}
    end
  end

  defp resolve_publish(state, packet), do: {:ok, state, packet}

  defp alias_error(state) do
    send_packet(state, %{type: :disconnect, reason_code: 0x94})
    {:error, close_abnormal_now(state)}
  end

  defp publish_opts(state, packet) do
    props = Map.get(packet, :properties, %{})

    [
      from_client: state.client_id,
      properties: pass_through_props(props),
      message_expiry: Map.get(props, :message_expiry_interval)
    ]
  end

  # The v5 properties that travel with a message from publisher to
  # subscribers (§3.3.2).
  defp pass_through_props(props) do
    Map.take(props, [
      :payload_format_indicator,
      :content_type,
      :response_topic,
      :correlation_data,
      :user_properties
    ])
  end

  defp handle_publish(state, packet) do
    props = Map.get(packet, :properties, %{})

    cond do
      byte_size(packet.payload) > Exjabberd.Mqtt.config(:max_payload, 262_144) ->
        Logger.debug("mqtt: payload over max_payload from #{state.client_id}, closing")

        if state.version == 5 do
          send_packet(state, %{type: :disconnect, reason_code: 0x95})
        end

        close_abnormal_now(state)

      state.version == 5 and Map.get(props, :payload_format_indicator, 0) == 1 and
          not String.valid?(packet.payload) ->
        # Payload Format Indicator 1 promises UTF-8 (§3.3.2.1).
        send_packet(state, %{type: :disconnect, reason_code: 0x99})
        close_abnormal_now(state)

      packet.qos == 0 ->
        Broker.publish(packet.topic, packet.payload, 0, packet.retain, publish_opts(state, packet))
        state

      packet.qos == 1 ->
        Broker.publish(packet.topic, packet.payload, 1, packet.retain, publish_opts(state, packet))
        send_packet(state, ack_packet(state, :puback, packet.packet_id))
        state

      packet.qos == 2 ->
        case Broker.store_in_qos2(state.client_id, packet.packet_id, packet) do
          :ok -> :ok
          # Duplicate PUBLISH (§4.3.3): PUBREC again, do not re-publish.
          :duplicate -> :ok
        end

        send_packet(state, ack_packet(state, :pubrec, packet.packet_id))
        state
    end
  end

  defp ack_packet(%{version: 5}, type, packet_id),
    do: %{type: type, packet_id: packet_id, reason_code: 0}

  defp ack_packet(_state, type, packet_id), do: %{type: type, packet_id: packet_id}

  # --- outbound deliveries -------------------------------------------------

  # Deliver a broker publish honoring the v5 client's Receive Maximum
  # (queue in FIFO order while the window is full) and Maximum Packet
  # Size (drop oversize; the spec permits discard, §3.2.2.10). The
  # remaining Message Expiry is stamped from the packet's
  # `:expires_at` at send time; an expired packet is dropped.
  defp deliver_out(state, packet) do
    packet = stamp_message_expiry(packet)

    cond do
      packet == nil ->
        state

      oversize_for_client?(state, packet) ->
        Logger.debug("mqtt: delivery to #{state.client_id} exceeds its Maximum Packet Size, dropped")
        state

      state.version == 5 and packet.qos in [1, 2] and
          MapSet.size(state.out_inflight) >= state.receive_maximum ->
        %{state | out_pending: :queue.in(packet, state.out_pending)}

      true ->
        send_packet(state, packet)
        track_inflight(state, packet)
    end
  end

  defp stamp_message_expiry(%{expires_at: expires_at} = packet) when is_integer(expires_at) do
    remaining = expires_at - System.os_time(:second)

    if remaining <= 0 do
      nil
    else
      props = Map.get(packet, :properties, %{})
      packet = Map.put(packet, :properties, Map.put(props, :message_expiry_interval, remaining))
      Map.delete(packet, :expires_at)
    end
  end

  defp stamp_message_expiry(packet), do: packet

  defp oversize_for_client?(%{version: 5, client_max_packet: max}, packet)
       when is_integer(max) do
    byte_size(Codec.encode(packet, 5)) > max
  end

  defp oversize_for_client?(_state, _packet), do: false

  defp track_inflight(state, %{qos: qos, packet_id: packet_id})
       when qos in [1, 2] and is_integer(packet_id) do
    if state.version == 5 do
      %{state | out_inflight: MapSet.put(state.out_inflight, packet_id)}
    else
      state
    end
  end

  defp track_inflight(state, _packet), do: state

  defp ack_outbound(state, packet_id) do
    %{state | out_inflight: MapSet.delete(state.out_inflight, packet_id)}
  end

  defp flush_pending(state) do
    cond do
      state.version != 5 ->
        state

      MapSet.size(state.out_inflight) >= state.receive_maximum ->
        state

      true ->
        case :queue.out(state.out_pending) do
          {:empty, _} ->
            state

          {{:value, packet}, rest} ->
            state = %{state | out_pending: rest}

            # The window has room (checked above), so send directly
            # instead of going through deliver_out's queueing path.
            case stamp_message_expiry(packet) do
              nil ->
                flush_pending(state)

              packet ->
                if oversize_for_client?(state, packet) do
                  flush_pending(state)
                else
                  send_packet(state, packet)
                  state |> track_inflight(packet) |> flush_pending()
                end
            end
        end
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
    :gen_tcp.send(state.socket, Codec.encode(packet, state.version))
    :ok
  end

  defp close_socket(state) do
    :gen_tcp.close(state.socket)
    :ok
  end

  defp close_quietly(state) do
    if state.client_id, do: Broker.client_gone(state.client_id, :clean, from_pid: self())
    close_socket(state)
    :ok
  end

  defp close_abnormal_now(state) do
    abnormal_close(state)
    %{state | closing: true}
  end

  defp abnormal_close(state) do
    if state.client_id do
      Broker.client_gone(state.client_id, :abnormal, from_pid: self())
    end

    close_socket(state)
    :ok
  end
end
