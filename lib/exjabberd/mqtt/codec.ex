defmodule Exjabberd.Mqtt.Codec do
  @moduledoc """
  MQTT v3.1.1 packet codec (OASIS Standard, MQTT Version 3.1.1).

  Pure encode/decode of the wire format — no sockets, no state — so it
  is unit-testable in isolation:

  * fixed header + Remaining Length variable-byte integer (§2.2.3),
  * CONNECT / CONNACK / PUBLISH / PUBACK / PUBREC / PUBREL / PUBCOMP /
    SUBSCRIBE / SUBACK / UNSUBSCRIBE / UNSUBACK / PINGREQ / PINGRESP /
    DISCONNECT (§3),
  * topic-filter validation and matching with the `+` (single level)
    and `#` (multi level) wildcards (§4.7).

  Packets are plain maps, e.g.
  `%{type: :publish, dup: false, qos: 1, retain: false, topic: "a/b",
  packet_id: 7, payload: "hi"}`.
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
    14 => :disconnect
  }

  @type_ids Map.new(@packet_types, fn {k, v} -> {v, k} end)

  # --- decoding -------------------------------------------------------

  @doc """
  Decode one packet from the front of `buffer`.

  Returns `{:ok, packet, rest}`, `{:incomplete, buffer}` when more bytes
  are needed, or `{:error, reason}` on a malformed packet (protocol
  error — the caller must close the connection, §3.1/§3.14).
  """
  @spec decode(binary()) :: {:ok, packet(), binary()} | {:incomplete, binary()} | {:error, term()}
  def decode(buffer) when is_binary(buffer) do
    # The helpers report `:incomplete` with a partial buffer; callers
    # retry with the *original* bytes plus whatever arrives next, so
    # always hand the untouched input back on that path.
    case do_decode(buffer) do
      {:incomplete, _} -> {:incomplete, buffer}
      other -> other
    end
  end

  defp do_decode(<<>>), do: {:incomplete, <<>>}

  defp do_decode(<<first, rest::binary>>) do
    type_id = first >>> 4
    flags = first &&& 0x0F

    case Map.fetch(@packet_types, type_id) do
      :error ->
        {:error, :unknown_packet_type}

      {:ok, type} ->
        with :ok <- check_flags(type, flags),
             {:ok, length, after_len} <- decode_remaining_length(rest, 0, 0),
             {:ok, body, tail} <- take_body(after_len, length) do
          decode_body(type, flags, body, tail)
        end
    end
  end

  # Fixed-header flags that must be zero / a fixed value (§3).
  defp check_flags(:subscribe, 0b0010), do: :ok
  defp check_flags(:unsubscribe, 0b0010), do: :ok
  defp check_flags(:pubrel, 0b0010), do: :ok
  defp check_flags(:subscribe, _), do: {:error, :bad_subscribe_flags}
  defp check_flags(:unsubscribe, _), do: {:error, :bad_unsubscribe_flags}
  defp check_flags(:pubrel, _), do: {:error, :bad_pubrel_flags}
  defp check_flags(:puback, 0), do: :ok
  defp check_flags(:pubrec, 0), do: :ok
  defp check_flags(:pubcomp, 0), do: :ok
  defp check_flags(:suback, 0), do: :ok
  defp check_flags(:unsuback, 0), do: :ok
  defp check_flags(:pingreq, 0), do: :ok
  defp check_flags(:pingresp, 0), do: :ok
  defp check_flags(:disconnect, 0), do: :ok
  defp check_flags(:connack, 0), do: :ok
  defp check_flags(:connect, 0), do: :ok
  defp check_flags(:puback, _), do: {:error, :bad_flags}
  defp check_flags(:pubrec, _), do: {:error, :bad_flags}
  defp check_flags(:pubcomp, _), do: {:error, :bad_flags}
  defp check_flags(:suback, _), do: {:error, :bad_flags}
  defp check_flags(:unsuback, _), do: {:error, :bad_flags}
  defp check_flags(:pingreq, _), do: {:error, :bad_flags}
  defp check_flags(:pingresp, _), do: {:error, :bad_flags}
  defp check_flags(:disconnect, _), do: {:error, :bad_flags}
  defp check_flags(:connack, _), do: {:error, :bad_flags}
  defp check_flags(:connect, _), do: {:error, :bad_flags}
  defp check_flags(:publish, flags) do
    # QoS 3 is forbidden (§3.3.1); DUP/RETAIN are free bits.
    if ((flags >>> 1) &&& 0b11) == 3, do: {:error, :bad_qos}, else: :ok
  end

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

  defp take_body(buffer, length) do
    if byte_size(buffer) < length do
      {:incomplete, buffer}
    else
      <<body::binary-size(length), tail::binary>> = buffer
      {:ok, body, tail}
    end
  end

  # --- per-type body decoding -----------------------------------------

  defp decode_body(:connect, _flags, body, tail) do
    with {:ok, proto, r1} <- take_string(body),
         {:ok, level, r2} <- take_byte(r1),
         {:ok, flags, r3} <- take_byte(r2),
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
        proto != "MQTT" or level != 4 ->
          {:error, :unacceptable_protocol_version}

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

  defp decode_body(:connack, _flags, <<session_present, return_code>>, tail) do
    {:ok,
     %{type: :connack, session_present: session_present == 1, return_code: return_code}, tail}
  end

  defp decode_body(:connack, _flags, _body, _tail), do: {:error, :bad_connack}

  defp decode_body(:publish, flags, body, tail) do
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

  defp decode_body(type, _flags, <<packet_id::16>>, tail)
       when type in [:puback, :pubrec, :pubrel, :pubcomp] do
    {:ok, %{type: type, packet_id: packet_id}, tail}
  end

  defp decode_body(type, _flags, _body, _tail)
       when type in [:puback, :pubrec, :pubrel, :pubcomp],
       do: {:error, :bad_packet_id}

  defp decode_body(:subscribe, _flags, body, tail) do
    with {:ok, packet_id, rest} <- take_packet_id(1, body),
         {:ok, topics} <- take_subscriptions(rest, []) do
      if packet_id == 0 or topics == [] do
        {:error, :bad_subscribe}
      else
        {:ok, %{type: :subscribe, packet_id: packet_id, topics: topics}, tail}
      end
    end
  end

  defp decode_body(:suback, _flags, body, tail) do
    with {:ok, packet_id, rest} <- take_packet_id(1, body) do
      {:ok, %{type: :suback, packet_id: packet_id, granted: :binary.bin_to_list(rest)}, tail}
    end
  end

  defp decode_body(:unsubscribe, _flags, body, tail) do
    with {:ok, packet_id, rest} <- take_packet_id(1, body),
         {:ok, topics} <- take_strings(rest, []) do
      if packet_id == 0 or topics == [] do
        {:error, :bad_unsubscribe}
      else
        {:ok, %{type: :unsubscribe, packet_id: packet_id, topics: topics}, tail}
      end
    end
  end

  defp decode_body(:unsuback, _flags, <<packet_id::16>>, tail) do
    {:ok, %{type: :unsuback, packet_id: packet_id}, tail}
  end

  defp decode_body(:unsuback, _flags, _body, _tail), do: {:error, :bad_packet_id}

  defp decode_body(:pingreq, _flags, <<>>, tail), do: {:ok, %{type: :pingreq}, tail}
  defp decode_body(:pingresp, _flags, <<>>, tail), do: {:ok, %{type: :pingresp}, tail}
  defp decode_body(:disconnect, _flags, <<>>, tail), do: {:ok, %{type: :disconnect}, tail}
  defp decode_body(_type, _flags, _body, _tail), do: {:error, :bad_body}

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

  # --- encoding -------------------------------------------------------

  @doc "Encode one packet map to wire bytes."
  @spec encode(packet()) :: binary()
  def encode(%{type: :connack, session_present: sp, return_code: rc}) do
    encode_packet(2, 0, <<if(sp, do: 1, else: 0), rc>>)
  end

  def encode(%{type: :publish} = p) do
    flags =
      (if Map.get(p, :dup, false), do: 0x08, else: 0) +
        (Map.get(p, :qos, 0) <<< 1) +
        if(Map.get(p, :retain, false), do: 1, else: 0)

    body = encode_string(p.topic) <> packet_id_bytes(p) <> Map.get(p, :payload, "")
    encode_packet(3, flags, body)
  end

  def encode(%{type: type, packet_id: packet_id})
      when type in [:puback, :pubrec, :pubrel, :pubcomp] do
    flags = if type == :pubrel, do: 0b0010, else: 0
    encode_packet(@type_ids[type], flags, <<packet_id::16>>)
  end

  def encode(%{type: :suback, packet_id: packet_id, granted: granted}) do
    encode_packet(9, 0, <<packet_id::16>> <> :binary.list_to_bin(granted))
  end

  def encode(%{type: :unsuback, packet_id: packet_id}) do
    encode_packet(11, 0, <<packet_id::16>>)
  end

  def encode(%{type: :pingresp}), do: encode_packet(13, 0, <<>>)
  def encode(%{type: :pingreq}), do: encode_packet(12, 0, <<>>)

  def encode(%{type: :disconnect}), do: encode_packet(14, 0, <<>>)

  def encode(%{type: :connect} = p) do
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

  def encode(%{type: :subscribe, packet_id: packet_id, topics: topics}) do
    body =
      <<packet_id::16>> <>
        Enum.map_join(topics, fn {filter, qos} -> encode_string(filter) <> <<qos>> end)

    encode_packet(8, 0b0010, body)
  end

  def encode(%{type: :unsubscribe, packet_id: packet_id, topics: topics}) do
    body = <<packet_id::16>> <> Enum.map_join(topics, &encode_string/1)
    encode_packet(10, 0b0010, body)
  end

  defp packet_id_bytes(%{qos: qos, packet_id: id}) when qos > 0 and is_integer(id),
    do: <<id::16>>

  defp packet_id_bytes(_), do: <<>>

  defp will_bytes(%{will_topic: topic, will_message: message})
       when is_binary(topic) and is_binary(message) do
    encode_string(topic) <> encode_string(message)
  end

  defp will_bytes(_), do: <<>>

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
  and `a/b+` are not.
  """
  @spec valid_filter?(binary()) :: boolean()
  def valid_filter?(filter) when is_binary(filter) do
    filter != "" and valid_utf8?(filter) and
      filter
      |> String.split("/")
      |> valid_levels?()
  end

  def valid_filter?(_), do: false

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

  @doc "Does topic-filter `filter` match publish topic `topic` (§4.7.1)?"
  @spec matches?(binary(), binary()) :: boolean()
  def matches?(filter, topic) when is_binary(filter) and is_binary(topic) do
    match_levels(String.split(filter, "/"), String.split(topic, "/"))
  end

  def matches?(_, _), do: false

  defp match_levels([], []), do: true
  defp match_levels(["#"], _), do: true
  defp match_levels(["+" | f_rest], [_ | t_rest]), do: match_levels(f_rest, t_rest)
  defp match_levels([same | f_rest], [same | t_rest]), do: match_levels(f_rest, t_rest)
  defp match_levels(_, _), do: false

  defp valid_utf8?(binary), do: String.valid?(binary)
end
