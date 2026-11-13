defmodule Exjabberd.Mqtt.Codec do
  @moduledoc """
  MQTT packet codec for v3.1.1 (OASIS Standard, MQTT Version 3.1.1)
  and v5.0 (OASIS Standard, MQTT Version 5).

  Pure encode/decode of the wire format — no sockets, no state — so it
  is unit-testable in isolation:

  * fixed header + Remaining Length variable-byte integer (§2.2.3),
  * CONNECT / CONNACK / PUBLISH / PUBACK / PUBREC / PUBREL / PUBCOMP /
    SUBSCRIBE / SUBACK / UNSUBSCRIBE / UNSUBACK / PINGREQ / PINGRESP /
    DISCONNECT (§3 of both specs) and, for v5, AUTH (type 15),
  * topic-filter validation and matching with the `+` (single level)
    and `#` (multi level) wildcards (§4.7), including the rule that a
    filter not starting with `$` never matches a topic starting with
    `$` (§4.7.2).

  Packets are plain maps, e.g.
  `%{type: :publish, dup: false, qos: 1, retain: false, topic: "a/b",
  packet_id: 7, payload: "hi"}`.

  ## Version handling

  `decode/2` takes the connection's protocol version (4 = v3.1.1,
  5 = v5.0); CONNECT ignores it and self-detects from the Protocol
  Level byte. A v3.1.1 packet decodes to exactly the map shape it
  always has — v5 packets additionally carry `version: 5` (CONNECT),
  `properties` (a map with atom keys, see `@properties`) and, for
  SUBSCRIBE, per-filter option maps. `encode/1` encodes the v3.1.1
  form; `encode/2` with version 5 encodes the v5 form (Properties,
  Reason Codes, subscription options, AUTH).

  v5 property values are represented as:

  * scalar properties under their atom key (`:session_expiry_interval`,
    `:receive_maximum`, `:topic_alias`, …),
  * `:user_properties` — a list of `{name, value}` string pairs,
  * `:subscription_identifiers` — a list of integers (PUBLISH may
    carry several; SUBSCRIBE carries at most one).
  """

  import Bitwise

  @type packet :: map()

  @max_remaining_length 268_435_455

  @packet_types %{
    1 => :connect,
    2 => :connack,
    3 => :publish,
    4 => :puback,
    5 => :pubrec,
    6 => :pubrel,
    7 => :pubcomp,
    8 => :subscribe,
    9 => :suback,
    10 => :unsubscribe,
    11 => :unsuback,
    12 => :pingreq,
    13 => :pingresp,
    14 => :disconnect,
    15 => :auth
  }

  @type_ids Map.new(@packet_types, fn {k, v} -> {v, k} end)

  # v5 property registry: id => {key, wire type} (§2.2.2).
  @properties %{
    0x01 => {:payload_format_indicator, :byte},
    0x02 => {:message_expiry_interval, :u32},
    0x03 => {:content_type, :string},
    0x08 => {:response_topic, :string},
    0x09 => {:correlation_data, :binary},
    0x0B => {:subscription_identifier, :varint},
    0x11 => {:session_expiry_interval, :u32},
    0x12 => {:assigned_client_identifier, :string},
    0x13 => {:server_keep_alive, :u16},
    0x15 => {:authentication_method, :string},
    0x16 => {:authentication_data, :binary},
    0x17 => {:request_problem_information, :byte},
    0x18 => {:will_delay_interval, :u32},
    0x19 => {:request_response_information, :byte},
    0x1A => {:response_information, :string},
    0x1C => {:server_reference, :string},
    0x1F => {:reason_string, :string},
    0x21 => {:receive_maximum, :u16},
    0x22 => {:topic_alias_maximum, :u16},
    0x23 => {:topic_alias, :u16},
    0x24 => {:maximum_qos, :byte},
    0x25 => {:retain_available, :byte},
    0x26 => {:user_property, :pair},
    0x27 => {:maximum_packet_size, :u32},
    0x28 => {:wildcard_subscription_available, :byte},
    0x29 => {:subscription_identifier_available, :byte},
    0x2A => {:shared_subscription_available, :byte}
  }

  # Which properties each v5 packet may carry (§2.2.2.2 table).
  @allowed_properties %{
    connect:
      ~w(session_expiry_interval receive_maximum maximum_packet_size topic_alias_maximum
         request_response_information request_problem_information user_property
         authentication_method authentication_data)a,
    will:
      ~w(payload_format_indicator message_expiry_interval content_type response_topic
         correlation_data user_property will_delay_interval)a,
    connack:
      ~w(session_expiry_interval receive_maximum maximum_qos retain_available
         maximum_packet_size assigned_client_identifier topic_alias_maximum
         response_information server_reference user_property authentication_method
         authentication_data reason_string wildcard_subscription_available
         subscription_identifier_available shared_subscription_available
         server_keep_alive)a,
    publish:
      ~w(payload_format_indicator message_expiry_interval content_type response_topic
         correlation_data user_property subscription_identifier topic_alias)a,
    ack: ~w(reason_string user_property)a,
    subscribe: ~w(subscription_identifier user_property)a,
    suback: ~w(reason_string user_property)a,
    unsubscribe: ~w(user_property)a,
    unsuback: ~w(reason_string user_property)a,
    disconnect: ~w(session_expiry_interval reason_string user_property server_reference)a,
    auth: ~w(authentication_method authentication_data reason_string user_property)a
  }

  # --- decoding -------------------------------------------------------

  @doc """
  Decode one packet from the front of `buffer`.

  `version` is the connection's MQTT version (4 or 5; CONNECT ignores
  it). Options: `:max_packet_size` — refuse a packet whose total size
  exceeds this many bytes with `{:error, :packet_too_large}` (v5
  Maximum Packet Size enforcement, §3.2.2.10 by symmetry).

  Returns `{:ok, packet, rest}`, `{:incomplete, buffer}` when more
  bytes are needed, or `{:error, reason}` on a malformed packet
  (protocol error — the caller must close the connection).
  """
  @spec decode(binary(), 4 | 5, keyword()) ::
          {:ok, packet(), binary()} | {:incomplete, binary()} | {:error, term()}
  def decode(buffer, version \\ 4, opts \\ [])

  def decode(buffer, version, opts) when is_binary(buffer) do
    # The helpers report `:incomplete` with a partial buffer; callers
    # retry with the *original* bytes plus whatever arrives next, so
    # always hand the untouched input back on that path.
    case do_decode(buffer, version, opts) do
      {:incomplete, _} -> {:incomplete, buffer}
      other -> other
    end
  end

  defp do_decode(<<>>, _version, _opts), do: {:incomplete, <<>>}

  defp do_decode(<<first, rest::binary>> = buffer, version, opts) do
    type_id = first >>> 4
    flags = first &&& 0x0F

    case Map.fetch(@packet_types, type_id) do
      :error ->
        {:error, :unknown_packet_type}

      {:ok, type} ->
        with :ok <- check_flags(type, flags),
             {:ok, length, after_len} <- decode_remaining_length(rest, 0, 0),
             {:ok, body, tail} <- take_body(after_len, length),
             :ok <- check_packet_size(buffer, tail, opts) do
          decode_body(type, flags, body, tail, version)
        end
    end
  end

  defp check_packet_size(buffer, tail, opts) do
    case Keyword.get(opts, :max_packet_size) do
      nil ->
        :ok

      max ->
        if byte_size(buffer) - byte_size(tail) > max,
          do: {:error, :packet_too_large},
          else: :ok
    end
  end

  # Fixed-header flags that must be zero / a fixed value (§3).
  defp check_flags(:subscribe, 0b0010), do: :ok
  defp check_flags(:unsubscribe, 0b0010), do: :ok
  defp check_flags(:pubrel, 0b0010), do: :ok
  defp check_flags(:subscribe, _), do: {:error, :bad_subscribe_flags}
  defp check_flags(:unsubscribe, _), do: {:error, :bad_unsubscribe_flags}
  defp check_flags(:pubrel, _), do: {:error, :bad_pubrel_flags}
  defp check_flags(:auth, 0), do: :ok
  defp check_flags(:auth, _), do: {:error, :bad_flags}

  defp check_flags(type, 0)
       when type in [:puback, :pubrec, :pubcomp, :suback, :unsuback, :pingreq, :pingresp, :disconnect, :connack, :connect],
       do: :ok

  defp check_flags(type, _)
       when type in [:puback, :pubrec, :pubcomp, :suback, :unsuback, :pingreq, :pingresp, :disconnect, :connack, :connect],
       do: {:error, :bad_flags}

  defp check_flags(:publish, flags) do
    # QoS 3 is forbidden (§3.3.1); DUP/RETAIN are free bits.
    if ((flags >>> 1) &&& 0b11) == 3, do: {:error, :bad_qos}, else: :ok
  end

  # Variable-byte integer (Remaining Length §2.2.3, also the v5
  # Variable Byte Integer of §1.5.5).
  defp decode_remaining_length(<<>>, _acc, _n), do: {:incomplete, <<>>}

  defp decode_remaining_length(<<byte, rest::binary>>, acc, n) do
    value = acc + ((byte &&& 0x7F) <<< (7 * n))

    cond do
      n == 3 and (byte &&& 0x80) != 0 ->
        {:error, :remaining_length_too_long}

      (byte &&& 0x80) != 0 ->
        decode_remaining_length(rest, value, n + 1)

      value > @max_remaining_length ->
        {:error, :remaining_length_too_long}

      true ->
        {:ok, value, rest}
    end
  end

  defp encode_varint(n), do: encode_remaining_length(n)

  defp take_body(buffer, length) do
    if byte_size(buffer) < length do
      {:incomplete, buffer}
    else
      <<body::binary-size(length), tail::binary>> = buffer
      {:ok, body, tail}
    end
  end

  # --- CONNECT ----------------------------------------------------------

  defp decode_body(:connect, _flags, body, tail, _version) do
    # The Protocol Name + Level decide the version; everything after
    # differs between v3.1.1 and v5.
    with {:ok, proto, r1} <- take_string(body),
         {:ok, level, r2} <- take_byte(r1) do
      cond do
        proto != "MQTT" -> {:error, :unacceptable_protocol_version}
        level == 4 -> decode_connect_v4(r2, tail)
        level == 5 -> decode_connect_v5(r2, tail)
        true -> {:error, :unacceptable_protocol_version}
      end
    end
  end

  # --- CONNACK ----------------------------------------------------------

  defp decode_body(:connack, _flags, <<session_present, return_code>>, tail, 4) do
    {:ok,
     %{type: :connack, session_present: session_present == 1, return_code: return_code}, tail}
  end

  defp decode_body(:connack, _flags, body, tail, 5) do
    with <<session_present, reason_code, rest::binary>> <- body,
         {:ok, props, <<>>} <- take_properties(rest, @allowed_properties.connack) do
      {:ok,
       %{
         type: :connack,
         session_present: session_present == 1,
         return_code: reason_code,
         reason_code: reason_code,
         properties: props
       }, tail}
    else
      _ -> {:error, :bad_connack}
    end
  end

  defp decode_body(:connack, _flags, _body, _tail, _version), do: {:error, :bad_connack}

  # --- PUBLISH ----------------------------------------------------------

  defp decode_body(:publish, flags, body, tail, 4) do
    dup = (flags &&& 0x08) != 0
    qos = (flags >>> 1) &&& 0b11
    retain = (flags &&& 0x01) != 0

    with {:ok, topic, r1} <- take_string(body),
         {:ok, packet_id, payload} <- take_packet_id(qos, r1) do
      if valid_topic?(topic) do
        {:ok,
         %{
           type: :publish,
           dup: dup,
           qos: qos,
           retain: retain,
           topic: topic,
           packet_id: packet_id,
           payload: payload
         }, tail}
      else
        {:error, :invalid_topic}
      end
    end
  end

  defp decode_body(:publish, flags, body, tail, 5) do
    dup = (flags &&& 0x08) != 0
    qos = (flags >>> 1) &&& 0b11
    retain = (flags &&& 0x01) != 0

    with {:ok, topic, r1} <- take_string(body),
         {:ok, packet_id, r2} <- take_packet_id(qos, r1),
         {:ok, props, payload} <- take_properties(r2, @allowed_properties.publish) do
      cond do
        topic == "" and not Map.has_key?(props, :topic_alias) ->
          {:error, :invalid_topic}

        topic != "" and not valid_topic?(topic) ->
          {:error, :invalid_topic}

        Map.has_key?(props, :response_topic) and not valid_topic?(props.response_topic) ->
          {:error, :invalid_response_topic}

        true ->
          {:ok,
           %{
             type: :publish,
             dup: dup,
             qos: qos,
             retain: retain,
             topic: topic,
             packet_id: packet_id,
             payload: payload,
             properties: props
           }, tail}
      end
    end
  end

  # --- PUBACK / PUBREC / PUBREL / PUBCOMP --------------------------------

  defp decode_body(type, _flags, body, tail, 5)
       when type in [:puback, :pubrec, :pubrel, :pubcomp] do
    case body do
      <<packet_id::16>> ->
        {:ok, %{type: type, packet_id: packet_id}, tail}

      <<packet_id::16, reason_code>> ->
        {:ok, %{type: type, packet_id: packet_id, reason_code: reason_code}, tail}

      <<packet_id::16, reason_code, rest::binary>> ->
        with {:ok, props, <<>>} <- take_properties(rest, @allowed_properties.ack) do
          {:ok,
           %{type: type, packet_id: packet_id, reason_code: reason_code, properties: props},
           tail}
        end

      _ ->
        {:error, :bad_packet_id}
    end
  end

  defp decode_body(type, _flags, <<packet_id::16>>, tail, _version)
       when type in [:puback, :pubrec, :pubrel, :pubcomp] do
    {:ok, %{type: type, packet_id: packet_id}, tail}
  end

  defp decode_body(type, _flags, _body, _tail, _version)
       when type in [:puback, :pubrec, :pubrel, :pubcomp],
       do: {:error, :bad_packet_id}

  # --- SUBSCRIBE / SUBACK -------------------------------------------------

  defp decode_body(:subscribe, _flags, body, tail, 4) do
    with {:ok, packet_id, rest} <- take_packet_id(1, body),
         {:ok, topics} <- take_subscriptions(rest, []) do
      if packet_id == 0 or topics == [] do
        {:error, :bad_subscribe}
      else
        {:ok, %{type: :subscribe, packet_id: packet_id, topics: topics}, tail}
      end
    end
  end

  defp decode_body(:subscribe, _flags, body, tail, 5) do
    with {:ok, packet_id, r1} <- take_packet_id(1, body),
         {:ok, props, r2} <- take_properties(r1, @allowed_properties.subscribe),
         {:ok, topics} <- take_subscriptions_v5(r2, []) do
      cond do
        packet_id == 0 or topics == [] ->
          {:error, :bad_subscribe}

        length(Map.get(props, :subscription_identifiers, [])) > 1 ->
          {:error, :multiple_subscription_identifiers}

        true ->
          {:ok, %{type: :subscribe, packet_id: packet_id, topics: topics, properties: props},
           tail}
      end
    end
  end

  defp decode_body(:suback, _flags, body, tail, 4) do
    with {:ok, packet_id, rest} <- take_packet_id(1, body) do
      {:ok, %{type: :suback, packet_id: packet_id, granted: :binary.bin_to_list(rest)}, tail}
    end
  end

  defp decode_body(:suback, _flags, body, tail, 5) do
    with {:ok, packet_id, r1} <- take_packet_id(1, body),
         {:ok, props, codes} <- take_properties(r1, @allowed_properties.suback) do
      {:ok,
       %{
         type: :suback,
         packet_id: packet_id,
         granted: :binary.bin_to_list(codes),
         properties: props
       }, tail}
    end
  end

  # --- UNSUBSCRIBE / UNSUBACK ----------------------------------------------

  defp decode_body(:unsubscribe, _flags, body, tail, 4) do
    with {:ok, packet_id, rest} <- take_packet_id(1, body),
         {:ok, topics} <- take_strings(rest, []) do
      if packet_id == 0 or topics == [] do
        {:error, :bad_unsubscribe}
      else
        {:ok, %{type: :unsubscribe, packet_id: packet_id, topics: topics}, tail}
      end
    end
  end

  defp decode_body(:unsubscribe, _flags, body, tail, 5) do
    with {:ok, packet_id, r1} <- take_packet_id(1, body),
         {:ok, props, r2} <- take_properties(r1, @allowed_properties.unsubscribe),
         {:ok, topics} <- take_strings(r2, []) do
      if packet_id == 0 or topics == [] do
        {:error, :bad_unsubscribe}
      else
        {:ok, %{type: :unsubscribe, packet_id: packet_id, topics: topics, properties: props},
         tail}
      end
    end
  end

  defp decode_body(:unsuback, _flags, <<packet_id::16>>, tail, 4) do
    {:ok, %{type: :unsuback, packet_id: packet_id}, tail}
  end

  defp decode_body(:unsuback, _flags, body, tail, 5) do
    with {:ok, packet_id, r1} <- take_packet_id(1, body),
         {:ok, props, codes} <- take_properties(r1, @allowed_properties.unsuback) do
      {:ok,
       %{
         type: :unsuback,
         packet_id: packet_id,
         properties: props,
         codes: :binary.bin_to_list(codes)
       }, tail}
    else
      _ -> {:error, :bad_packet_id}
    end
  end

  defp decode_body(:unsuback, _flags, _body, _tail, _version), do: {:error, :bad_packet_id}

  # --- PING / DISCONNECT / AUTH ---------------------------------------------

  defp decode_body(:pingreq, _flags, <<>>, tail, _v), do: {:ok, %{type: :pingreq}, tail}
  defp decode_body(:pingresp, _flags, <<>>, tail, _v), do: {:ok, %{type: :pingresp}, tail}

  defp decode_body(:disconnect, _flags, <<>>, tail, 4), do: {:ok, %{type: :disconnect}, tail}

  defp decode_body(:disconnect, _flags, body, tail, 5) do
    case body do
      <<>> ->
        {:ok, %{type: :disconnect, reason_code: 0, properties: %{}}, tail}

      <<reason_code>> ->
        {:ok, %{type: :disconnect, reason_code: reason_code, properties: %{}}, tail}

      <<reason_code, rest::binary>> ->
        with {:ok, props, <<>>} <- take_properties(rest, @allowed_properties.disconnect) do
          {:ok, %{type: :disconnect, reason_code: reason_code, properties: props}, tail}
        end
    end
  end

  defp decode_body(:auth, _flags, body, tail, 5) do
    case body do
      <<reason_code, rest::binary>> ->
        with {:ok, props, <<>>} <- take_properties(rest, @allowed_properties.auth) do
          {:ok, %{type: :auth, reason_code: reason_code, properties: props}, tail}
        end

      _ ->
        {:error, :bad_auth}
    end
  end

  defp decode_body(:auth, _flags, _body, _tail, 4), do: {:error, :auth_in_v3}

  defp decode_body(_type, _flags, _body, _tail, _version), do: {:error, :bad_body}

  # --- field helpers ------------------------------------------------------

  defp decode_connect_v4(r2, tail) do
    with {:ok, flags, r3} <- take_byte(r2),
         {:ok, keep_alive, r4} <- take_u16(r3),
         {:ok, client_id, r5} <- take_string(r4) do
      username_flag = (flags &&& 0x80) != 0
      password_flag = (flags &&& 0x40) != 0
      will_retain = (flags &&& 0x20) != 0
      will_qos = (flags >>> 3) &&& 0b11
      will_flag = (flags &&& 0x04) != 0
      clean_session = (flags &&& 0x02) != 0
      reserved = (flags &&& 0x01) != 0

      cond do
        reserved ->
          {:error, :reserved_flag_set}

        will_qos == 3 ->
          {:error, :bad_will_qos}

        will_flag == false and (will_retain or will_qos != 0) ->
          {:error, :bad_will_flags}

        clean_session == false and client_id == "" ->
          {:error, :empty_client_id_without_clean_session}

        true ->
          with {:ok, will_topic, will_message, r6} <-
                 take_will(will_flag, r5),
               {:ok, username, r7} <- take_optional_string(username_flag, r6),
               {:ok, password, _r8} <- take_optional_string(password_flag, r7) do
            {:ok,
             %{
               type: :connect,
               client_id: client_id,
               clean_session: clean_session,
               keep_alive: keep_alive,
               username: username,
               password: password,
               will_flag: will_flag,
               will_topic: will_topic,
               will_message: will_message,
               will_qos: will_qos,
               will_retain: will_retain
             }, tail}
          end
      end
    end
  end

  defp decode_connect_v5(r2, tail) do
    with {:ok, flags, r3} <- take_byte(r2),
         {:ok, keep_alive, r4} <- take_u16(r3),
         {:ok, props, r5} <- take_properties(r4, @allowed_properties.connect),
         {:ok, client_id, r6} <- take_string(r5) do
      username_flag = (flags &&& 0x80) != 0
      password_flag = (flags &&& 0x40) != 0
      will_retain = (flags &&& 0x20) != 0
      will_qos = (flags >>> 3) &&& 0b11
      will_flag = (flags &&& 0x04) != 0
      clean_start = (flags &&& 0x02) != 0
      reserved = (flags &&& 0x01) != 0

      cond do
        reserved ->
          {:error, :reserved_flag_set}

        will_qos == 3 ->
          {:error, :bad_will_qos}

        will_flag == false and (will_retain or will_qos != 0) ->
          {:error, :bad_will_flags}

        password_flag and not username_flag ->
          # MQTT-3.1.2.9: Password flag set with Username flag 0 is a
          # protocol error in v5.
          {:error, :password_without_username}

        true ->
          with {:ok, will_props, will_topic, will_message, r7} <-
                 take_will_v5(will_flag, r6),
               {:ok, username, r8} <- take_optional_string(username_flag, r7),
               {:ok, password, _r9} <- take_optional_string(password_flag, r8) do
            {:ok,
             %{
               type: :connect,
               version: 5,
               client_id: client_id,
               clean_session: clean_start,
               keep_alive: keep_alive,
               username: username,
               password: password,
               will_flag: will_flag,
               will_topic: will_topic,
               will_message: will_message,
               will_qos: will_qos,
               will_retain: will_retain,
               properties: props,
               will_properties: will_props
             }, tail}
          end
      end
    end
  end

  defp take_will_v5(false, rest), do: {:ok, %{}, nil, nil, rest}

  defp take_will_v5(true, rest) do
    with {:ok, props, r1} <- take_properties(rest, @allowed_properties.will),
         {:ok, topic, r2} <- take_string(r1),
         {:ok, message, r3} <- take_string(r2) do
      if valid_topic?(topic) do
        {:ok, props, topic, message, r3}
      else
        {:error, :invalid_will_topic}
      end
    end
  end


  defp take_will(false, rest), do: {:ok, nil, nil, rest}

  defp take_will(true, rest) do
    with {:ok, topic, r1} <- take_string(rest),
         {:ok, message, r2} <- take_string(r1) do
      if valid_topic?(topic) do
        {:ok, topic, message, r2}
      else
        {:error, :invalid_will_topic}
      end
    end
  end

  defp take_optional_string(false, rest), do: {:ok, nil, rest}
  defp take_optional_string(true, rest), do: take_string(rest)

  defp take_subscriptions(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp take_subscriptions(rest, acc) do
    with {:ok, filter, r1} <- take_string(rest),
         {:ok, qos, r2} <- take_byte(r1) do
      if valid_filter?(filter) and qos <= 2 do
        take_subscriptions(r2, [{filter, qos} | acc])
      else
        # A requested QoS of 3 is not a protocol error on the wire:
        # §3.8.3 — the server answers that filter with 0x80 (failure)
        # in SUBACK instead of disconnecting.
        if valid_filter?(filter) and qos == 3 do
          take_subscriptions(r2, [{filter, 3} | acc])
        else
          {:error, :invalid_subscription}
        end
      end
    end
  end

  defp take_subscriptions_v5(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp take_subscriptions_v5(rest, acc) do
    with {:ok, filter, r1} <- take_string(rest),
         {:ok, options, r2} <- take_byte(r1) do
      qos = options &&& 0b11
      retain_handling = (options >>> 4) &&& 0b11

      cond do
        # Reserved bits 6-7 must be 0 (§3.8.3.1).
        (options &&& 0xC0) != 0 ->
          {:error, :bad_subscription_options}

        qos == 3 ->
          {:error, :bad_subscription_qos}

        retain_handling == 3 ->
          {:error, :bad_retain_handling}

        true ->
          opts = %{
            no_local: (options &&& 0x04) != 0,
            retain_as_published: (options &&& 0x08) != 0,
            retain_handling: retain_handling
          }

          take_subscriptions_v5(r2, [{filter, qos, opts} | acc])
      end
    end
  end

  defp take_strings(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp take_strings(rest, acc) do
    with {:ok, string, r1} <- take_string(rest) do
      take_strings(r1, [string | acc])
    end
  end

  defp take_string(<<len::16, s::binary-size(len), rest::binary>>), do: {:ok, s, rest}
  defp take_string(_), do: {:error, :bad_string}

  defp take_byte(<<b, rest::binary>>), do: {:ok, b, rest}
  defp take_byte(_), do: {:error, :bad_byte}

  defp take_u16(<<v::16, rest::binary>>), do: {:ok, v, rest}
  defp take_u16(_), do: {:error, :bad_u16}

  defp take_packet_id(0, rest), do: {:ok, nil, rest}

  defp take_packet_id(_qos, <<packet_id::16, rest::binary>>),
    do: {:ok, packet_id, rest}

  defp take_packet_id(_qos, _), do: {:error, :bad_packet_id}

  # --- v5 properties ------------------------------------------------------

  # Properties are a Variable Byte Integer length followed by that
  # many bytes of (identifier, value) pairs (§2.2.2). Returns the
  # property map and the bytes after the block.
  defp take_properties(<<>>, _allowed), do: {:error, :bad_properties}

  defp take_properties(buffer, allowed) do
    with {:ok, length, after_len} <- decode_remaining_length(buffer, 0, 0),
         {:ok, block, rest} <- take_body(after_len, length),
         {:ok, props} <- parse_properties(block, allowed, %{}) do
      {:ok, props, rest}
    end
  end

  defp parse_properties(<<>>, _allowed, acc), do: {:ok, acc}

  defp parse_properties(<<id, rest::binary>>, allowed, acc) do
    case Map.fetch(@properties, id) do
      :error ->
        {:error, :unknown_property}

      {:ok, {key, type}} ->
        cond do
          key not in allowed ->
            {:error, :property_not_allowed}

          key == :user_property ->
            with {:ok, {name, value}, r} <- take_pair(rest) do
              acc = Map.update(acc, :user_properties, [{name, value}], &(&1 ++ [{name, value}]))
              parse_properties(r, allowed, acc)
            end

          key == :subscription_identifier ->
            with {:ok, value, r} <- take_varint(rest) do
              if value == 0 do
                {:error, :bad_property_value}
              else
                acc =
                  Map.update(acc, :subscription_identifiers, [value], &(&1 ++ [value]))

                parse_properties(r, allowed, acc)
              end
            end

          Map.has_key?(acc, key) ->
            {:error, :duplicate_property}

          true ->
            with {:ok, value, r} <- take_property_value(type, rest),
                 :ok <- validate_property(key, value) do
              parse_properties(r, allowed, Map.put(acc, key, value))
            end
        end
    end
  end

  defp parse_properties(_, _allowed, _acc), do: {:error, :bad_properties}

  defp take_pair(rest) do
    with {:ok, name, r1} <- take_string(rest),
         {:ok, value, r2} <- take_string(r1) do
      {:ok, {name, value}, r2}
    end
  end

  defp take_varint(buffer) do
    case decode_remaining_length(buffer, 0, 0) do
      {:ok, value, rest} -> {:ok, value, rest}
      {:incomplete, _} -> {:error, :bad_varint}
      {:error, reason} -> {:error, reason}
    end
  end

  defp take_property_value(:byte, <<v, rest::binary>>), do: {:ok, v, rest}
  defp take_property_value(:u16, <<v::16, rest::binary>>), do: {:ok, v, rest}
  defp take_property_value(:u32, <<v::32, rest::binary>>), do: {:ok, v, rest}
  defp take_property_value(:string, rest), do: take_string(rest)
  defp take_property_value(:binary, rest), do: take_string(rest)
  defp take_property_value(:varint, rest), do: take_varint(rest)
  defp take_property_value(_, _), do: {:error, :bad_property_value}

  # Value rules that are protocol errors when broken (§2.2.2 / §3).
  defp validate_property(:receive_maximum, 0), do: {:error, :bad_property_value}
  defp validate_property(:maximum_packet_size, 0), do: {:error, :bad_property_value}
  defp validate_property(:topic_alias, 0), do: {:error, :bad_property_value}

  defp validate_property(key, value)
       when key in [
              :payload_format_indicator,
              :request_problem_information,
              :request_response_information,
              :maximum_qos,
              :retain_available,
              :wildcard_subscription_available,
              :subscription_identifier_available,
              :shared_subscription_available
            ] and value > 1,
       do: {:error, :bad_property_value}

  defp validate_property(_key, _value), do: :ok

  # Encode a property map to (length varint <> pairs). Keys are
  # emitted in ascending identifier order for determinism.
  defp encode_properties(props) when props == %{} or is_nil(props), do: <<0>>

  defp encode_properties(props) do
    body =
      @properties
      |> Enum.sort_by(fn {id, _} -> id end)
      |> Enum.map_join(fn {id, {key, type}} -> encode_property(id, key, type, props) end)

    encode_varint(byte_size(body)) <> body
  end

  defp encode_property(0x26, :user_property, :pair, props) do
    Enum.map_join(Map.get(props, :user_properties, []), fn {name, value} ->
      <<0x26>> <> encode_string(name) <> encode_string(value)
    end)
  end

  defp encode_property(0x0B, :subscription_identifier, :varint, props) do
    ids =
      Map.get(props, :subscription_identifiers) ||
        List.wrap(Map.get(props, :subscription_identifier))

    Enum.map_join(ids, fn id -> <<0x0B>> <> encode_varint(id) end)
  end

  defp encode_property(id, key, type, props) do
    case Map.fetch(props, key) do
      :error -> ""
      {:ok, value} -> <<id>> <> encode_property_value(type, value)
    end
  end

  defp encode_property_value(:byte, v), do: <<v>>
  defp encode_property_value(:u16, v), do: <<v::16>>
  defp encode_property_value(:u32, v), do: <<v::32>>
  defp encode_property_value(:string, v), do: encode_string(v)
  defp encode_property_value(:binary, v), do: encode_string(v)
  defp encode_property_value(:varint, v), do: encode_varint(v)

  # --- encoding -------------------------------------------------------

  @doc "Encode one packet map to wire bytes (v3.1.1 form unless `version` is 5)."
  @spec encode(packet()) :: binary()
  def encode(packet), do: encode(packet, Map.get(packet, :version, 4))

  @spec encode(packet(), 4 | 5) :: binary()
  def encode(packet, version)

  # CONNACK
  def encode(%{type: :connack} = p, 5) do
    reason = Map.get(p, :reason_code, Map.get(p, :return_code, 0))
    flags = if Map.get(p, :session_present, false), do: 1, else: 0
    body = <<flags, reason>> <> encode_properties(Map.get(p, :properties, %{}))
    encode_packet(2, 0, body)
  end

  def encode(%{type: :connack, session_present: sp, return_code: rc}, _version) do
    encode_packet(2, 0, <<if(sp, do: 1, else: 0), rc>>)
  end

  # PUBLISH
  def encode(%{type: :publish} = p, 5) do
    flags =
      (if Map.get(p, :dup, false), do: 0x08, else: 0) +
        (Map.get(p, :qos, 0) <<< 1) +
        if(Map.get(p, :retain, false), do: 1, else: 0)

    body =
      encode_string(Map.get(p, :topic, "")) <>
        packet_id_bytes(p) <>
        encode_properties(Map.get(p, :properties, %{})) <>
        Map.get(p, :payload, "")

    encode_packet(3, flags, body)
  end

  def encode(%{type: :publish} = p, _version) do
    flags =
      (if Map.get(p, :dup, false), do: 0x08, else: 0) +
        (Map.get(p, :qos, 0) <<< 1) +
        if(Map.get(p, :retain, false), do: 1, else: 0)

    body = encode_string(p.topic) <> packet_id_bytes(p) <> Map.get(p, :payload, "")
    encode_packet(3, flags, body)
  end

  # PUBACK / PUBREC / PUBREL / PUBCOMP
  def encode(%{type: type, packet_id: packet_id} = p, 5)
      when type in [:puback, :pubrec, :pubrel, :pubcomp] do
    flags = if type == :pubrel, do: 0b0010, else: 0

    body =
      if Map.has_key?(p, :reason_code) or Map.has_key?(p, :properties) do
        <<packet_id::16, Map.get(p, :reason_code, 0)>> <>
          encode_properties(Map.get(p, :properties, %{}))
      else
        <<packet_id::16>>
      end

    encode_packet(@type_ids[type], flags, body)
  end

  def encode(%{type: type, packet_id: packet_id}, _version)
      when type in [:puback, :pubrec, :pubrel, :pubcomp] do
    flags = if type == :pubrel, do: 0b0010, else: 0
    encode_packet(@type_ids[type], flags, <<packet_id::16>>)
  end

  # SUBACK
  def encode(%{type: :suback, packet_id: packet_id, granted: granted} = p, 5) do
    body =
      <<packet_id::16>> <>
        encode_properties(Map.get(p, :properties, %{})) <>
        :binary.list_to_bin(granted)

    encode_packet(9, 0, body)
  end

  def encode(%{type: :suback, packet_id: packet_id, granted: granted}, _version) do
    encode_packet(9, 0, <<packet_id::16>> <> :binary.list_to_bin(granted))
  end

  # UNSUBACK
  def encode(%{type: :unsuback, packet_id: packet_id} = p, 5) do
    body =
      <<packet_id::16>> <>
        encode_properties(Map.get(p, :properties, %{})) <>
        :binary.list_to_bin(Map.get(p, :codes, []))

    encode_packet(11, 0, body)
  end

  def encode(%{type: :unsuback, packet_id: packet_id}, _version) do
    encode_packet(11, 0, <<packet_id::16>>)
  end

  def encode(%{type: :pingresp}, _version), do: encode_packet(13, 0, <<>>)
  def encode(%{type: :pingreq}, _version), do: encode_packet(12, 0, <<>>)

  # DISCONNECT
  def encode(%{type: :disconnect} = p, 5) do
    reason = Map.get(p, :reason_code, 0)
    props = Map.get(p, :properties, %{})

    body =
      if reason == 0 and (props == %{} or is_nil(props)) do
        <<>>
      else
        <<reason>> <> encode_properties(props)
      end

    encode_packet(14, 0, body)
  end

  def encode(%{type: :disconnect}, _version), do: encode_packet(14, 0, <<>>)

  # AUTH (v5 only)
  def encode(%{type: :auth} = p, 5) do
    body =
      <<Map.get(p, :reason_code, 0)>> <>
        encode_properties(Map.get(p, :properties, %{}))

    encode_packet(15, 0, body)
  end

  # CONNECT
  def encode(%{type: :connect} = p, 5) do
    flags =
      (if p[:username], do: 0x80, else: 0) +
        (if p[:password], do: 0x40, else: 0) +
        (if p[:will_retain], do: 0x20, else: 0) +
        (Map.get(p, :will_qos, 0) <<< 3) +
        (if p[:will_flag] || p[:will_topic], do: 0x04, else: 0) +
        if(Map.get(p, :clean_session, true), do: 0x02, else: 0)

    body =
      encode_string("MQTT") <>
        <<5, flags, Map.get(p, :keep_alive, 0)::16>> <>
        encode_properties(Map.get(p, :properties, %{})) <>
        encode_string(Map.get(p, :client_id, "")) <>
        will_bytes_v5(p) <>
        optional_string(p[:username]) <>
        optional_string(p[:password])

    encode_packet(1, 0, body)
  end

  def encode(%{type: :connect} = p, _version) do
    flags =
      (if p[:username], do: 0x80, else: 0) +
        (if p[:password], do: 0x40, else: 0) +
        (if p[:will_retain], do: 0x20, else: 0) +
        (Map.get(p, :will_qos, 0) <<< 3) +
        (if p[:will_flag] || p[:will_topic], do: 0x04, else: 0) +
        if(Map.get(p, :clean_session, true), do: 0x02, else: 0)

    body =
      encode_string("MQTT") <>
        <<4, flags, Map.get(p, :keep_alive, 0)::16>> <>
        encode_string(Map.get(p, :client_id, "")) <>
        will_bytes(p) <>
        optional_string(p[:username]) <>
        optional_string(p[:password])

    encode_packet(1, 0, body)
  end

  # SUBSCRIBE
  def encode(%{type: :subscribe, packet_id: packet_id, topics: topics} = p, 5) do
    body =
      <<packet_id::16>> <>
        encode_properties(Map.get(p, :properties, %{})) <>
        Enum.map_join(topics, fn
          {filter, qos, opts} ->
            encode_string(filter) <> <<subscription_options(qos, opts)>>

          {filter, qos} ->
            encode_string(filter) <> <<qos>>
        end)

    encode_packet(8, 0b0010, body)
  end

  def encode(%{type: :subscribe, packet_id: packet_id, topics: topics}, _version) do
    body =
      <<packet_id::16>> <>
        Enum.map_join(topics, fn {filter, qos} -> encode_string(filter) <> <<qos>> end)

    encode_packet(8, 0b0010, body)
  end

  # UNSUBSCRIBE
  def encode(%{type: :unsubscribe, packet_id: packet_id, topics: topics} = p, 5) do
    body =
      <<packet_id::16>> <>
        encode_properties(Map.get(p, :properties, %{})) <>
        Enum.map_join(topics, &encode_string/1)

    encode_packet(10, 0b0010, body)
  end

  def encode(%{type: :unsubscribe, packet_id: packet_id, topics: topics}, _version) do
    body = <<packet_id::16>> <> Enum.map_join(topics, &encode_string/1)
    encode_packet(10, 0b0010, body)
  end

  defp subscription_options(qos, opts) do
    qos +
      (if Map.get(opts, :no_local, false), do: 0x04, else: 0) +
      (if Map.get(opts, :retain_as_published, false), do: 0x08, else: 0) +
      (Map.get(opts, :retain_handling, 0) <<< 4)
  end

  defp packet_id_bytes(%{qos: qos, packet_id: id}) when qos > 0 and is_integer(id),
    do: <<id::16>>

  defp packet_id_bytes(_), do: <<>>

  defp will_bytes(%{will_topic: topic, will_message: message})
       when is_binary(topic) and is_binary(message) do
    encode_string(topic) <> encode_string(message)
  end

  defp will_bytes(_), do: <<>>

  defp will_bytes_v5(%{will_topic: topic, will_message: message} = p)
       when is_binary(topic) and is_binary(message) do
    encode_properties(Map.get(p, :will_properties, %{})) <>
      encode_string(topic) <> encode_string(message)
  end

  defp will_bytes_v5(_), do: <<>>

  defp optional_string(nil), do: <<>>
  defp optional_string(s), do: encode_string(s)

  defp encode_string(s) when is_binary(s), do: <<byte_size(s)::16, s::binary>>

  defp encode_packet(type_id, flags, body) do
    <<type_id <<< 4 ||| flags>> <> encode_remaining_length(byte_size(body)) <> body
  end

  defp encode_remaining_length(0), do: <<0>>

  defp encode_remaining_length(n) do
    encode_remaining_length(n, [])
  end

  defp encode_remaining_length(0, acc), do: :binary.list_to_bin(Enum.reverse(acc))

  defp encode_remaining_length(n, acc) do
    byte = rem(n, 128)
    rest = div(n, 128)
    byte = if rest > 0, do: byte + 128, else: byte
    encode_remaining_length(rest, [byte | acc])
  end

  # --- topic validation / matching (§4.7) -----------------------------

  @doc """
  A publish topic is valid when it is non-empty and contains no `+`
  or `#` wildcard (§4.7.1.2, §4.7.1.3).
  """
  @spec valid_topic?(binary()) :: boolean()
  def valid_topic?(topic) when is_binary(topic) do
    topic != "" and not String.contains?(topic, ["+", "#"]) and
      valid_utf8?(topic)
  end

  def valid_topic?(_), do: false

  @doc """
  A subscription filter is valid when every `+` occupies a whole level
  and `#` (if present) is the last level, alone (§4.7.1.2, §4.7.1.3).
  The filter `#` alone and `sport/#` are valid; `sport#`, `a/#/b`
  and `a/b+` are not. A `$share/<group>/<filter>` shared-subscription
  filter (v5 §4.8.2) is valid when the group name is non-empty and
  wildcard-free and the inner filter is valid.
  """
  @spec valid_filter?(binary()) :: boolean()
  def valid_filter?(filter) when is_binary(filter) do
    case shared_parts(filter) do
      {:ok, _group, inner} ->
        valid_filter_plain?(inner)

      :shared_invalid ->
        false

      :not_shared ->
        valid_filter_plain?(filter)
    end
  end

  def valid_filter?(_), do: false

  defp valid_filter_plain?(filter) do
    filter != "" and valid_utf8?(filter) and
      filter
      |> String.split("/")
      |> valid_levels?()
  end

  defp valid_levels?(levels) do
    levels
    |> Enum.with_index()
    |> Enum.all?(fn {level, idx} ->
      cond do
        level == "#" -> idx == length(levels) - 1
        String.contains?(level, "#") -> false
        String.contains?(level, "+") -> level == "+"
        true -> true
      end
    end)
  end

  @doc """
  Split a shared-subscription filter `$share/<group>/<filter>` into
  `{:ok, group, inner_filter}`. Returns `:not_shared` for ordinary
  filters and `:shared_invalid` for malformed `$share/` forms
  (missing group, wildcard in group, missing inner filter).
  """
  @spec shared_parts(binary()) :: {:ok, binary(), binary()} | :not_shared | :shared_invalid
  def shared_parts("$share/" <> rest) do
    case String.split(rest, "/", parts: 2) do
      [group, inner]
      when group != "" and inner != "" ->
        if String.contains?(group, ["+", "#"]) do
          :shared_invalid
        else
          {:ok, group, inner}
        end

      _ ->
        :shared_invalid
    end
  end

  def shared_parts(filter) when is_binary(filter), do: :not_shared
  def shared_parts(_), do: :shared_invalid

  @doc """
  Does topic-filter `filter` match publish topic `topic` (§4.7.1)?
  A filter whose first level is a wildcard never matches a topic
  starting with `$` (§4.7.2). Shared-subscription filters match on
  their inner filter.
  """
  @spec matches?(binary(), binary()) :: boolean()
  def matches?(filter, topic) when is_binary(filter) and is_binary(topic) do
    inner =
      case shared_parts(filter) do
        {:ok, _group, inner} -> inner
        _ -> filter
      end

    if String.starts_with?(topic, "$") and
         (String.starts_with?(inner, "+") or String.starts_with?(inner, "#")) do
      false
    else
      match_levels(String.split(inner, "/"), String.split(topic, "/"))
    end
  end

  def matches?(_, _), do: false

  defp match_levels([], []), do: true
  defp match_levels(["#"], _), do: true
  defp match_levels(["+" | f_rest], [_ | t_rest]), do: match_levels(f_rest, t_rest)
  defp match_levels([same | f_rest], [same | t_rest]), do: match_levels(f_rest, t_rest)
  defp match_levels(_, _), do: false

  defp valid_utf8?(binary), do: String.valid?(binary)
end
