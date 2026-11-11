defmodule Exjabberd.StunTurn do
  @moduledoc """
  STUN (RFC 5389) + TURN (RFC 5766) message codec — pure functions,
  no sockets, no processes, so every byte-level rule is unit-testable.

  A STUN message is a 20-byte header (`type`, `length`, magic cookie
  `0x2112A442`, 12-byte transaction id) followed by attributes, each
  `type` + `length` + value padded to a 4-byte boundary.

  Implemented attribute set (the ones STUN Binding and TURN need):

  * `0x0001` MAPPED-ADDRESS, `0x0020` XOR-MAPPED-ADDRESS,
    `0x0012` XOR-PEER-ADDRESS, `0x0016` XOR-RELAYED-ADDRESS
    (decoded as `{family, ip_tuple, port}`, `:ipv4` / `:ipv6`)
  * `0x0006` USERNAME, `0x0014` REALM, `0x0015` NONCE (strings)
  * `0x0008` MESSAGE-INTEGRITY (20-byte HMAC-SHA1, kept raw)
  * `0x0009` ERROR-CODE (`{code, reason}`)
  * `0x000D` LIFETIME (seconds), `0x0019` REQUESTED-TRANSPORT,
    `0x000C` CHANNEL-NUMBER, `0x0013` DATA (binary)
  * `0x8022` SOFTWARE (string), `0x8028` FINGERPRINT (integer)
  * anything else is kept as a raw binary value

  Authentication follows the RFC 5389 long-term credential mechanism
  (§10.2): the key is `MD5(username ":" realm ":" password)` and
  MESSAGE-INTEGRITY is HMAC-SHA1 over the message with the length
  field adjusted to the end of the MESSAGE-INTEGRITY attribute and
  its value zeroed. The TURN password itself is derived from the
  configured shared secret, exactly like the ephemeral credentials
  XEP-0215 hands to clients (`Base64(HMAC-SHA1(secret, username))`),
  so no per-user password store is needed and the secret never
  leaves the configuration.

  Nonces are stateless: `Base64(timestamp || HMAC-SHA1(secret,
  timestamp))`, valid for one hour, so a restart does not invalidate
  in-flight allocations the way a stored nonce table would.

  ChannelData (RFC 5766 §11) is a 4-byte header (`channel`,
  `length`) plus data, padded to 4 bytes; channel numbers are
  `0x4000..0x7FFF` and are told apart from STUN messages by their
  first two bits (`01` vs `00`).
  """

  import Bitwise

  @magic_cookie 0x2112A442
  @fingerprint_xor 0x5354554E

  # STUN message types (RFC 5389 §6, RFC 5766 §6).
  @binding_request 0x0001
  @binding_success 0x0101
  @allocate_request 0x0003
  @refresh_request 0x0004
  @send_indication 0x0006
  @data_indication 0x0007
  @create_permission_request 0x0008
  @channel_bind_request 0x0009
  @error_response 0x0111

  # Attribute types.
  @attr_mapped_address 0x0001
  @attr_username 0x0006
  @attr_message_integrity 0x0008
  @attr_error_code 0x0009
  @attr_unknown_attributes 0x000A
  @attr_channel_number 0x000C
  @attr_lifetime 0x000D
  @attr_xor_peer_address 0x0012
  @attr_data 0x0013
  @attr_realm 0x0014
  @attr_nonce 0x0015
  @attr_xor_relayed_address 0x0016
  @attr_requested_transport 0x0019
  @attr_xor_mapped_address 0x0020
  @attr_software 0x8022
  @attr_fingerprint 0x8028

  @type ip_addr :: :inet.ip_address()
  @type address :: {:ipv4 | :ipv6, ip_addr(), :inet.port_number()}
  @type attr_value ::
          address()
          | binary()
          | {non_neg_integer(), binary()}
          | non_neg_integer()
          | [non_neg_integer()]
  @type attr :: {non_neg_integer(), attr_value()}
  @type message :: %{type: non_neg_integer(), transaction_id: binary(), attrs: [attr()]}

  @doc "The STUN magic cookie (RFC 5389 §6)."
  @spec magic_cookie() :: non_neg_integer()
  def magic_cookie, do: @magic_cookie

  def binding_request, do: @binding_request
  def binding_success, do: @binding_success
  def allocate_request, do: @allocate_request
  def refresh_request, do: @refresh_request
  def send_indication, do: @send_indication
  def data_indication, do: @data_indication
  def create_permission_request, do: @create_permission_request
  def channel_bind_request, do: @channel_bind_request
  def error_response, do: @error_response

  def attr_username, do: @attr_username
  def attr_realm, do: @attr_realm
  def attr_nonce, do: @attr_nonce
  def attr_message_integrity, do: @attr_message_integrity
  def attr_error_code, do: @attr_error_code
  def attr_lifetime, do: @attr_lifetime
  def attr_requested_transport, do: @attr_requested_transport
  def attr_channel_number, do: @attr_channel_number
  def attr_data, do: @attr_data
  def attr_xor_peer_address, do: @attr_xor_peer_address
  def attr_xor_relayed_address, do: @attr_xor_relayed_address
  def attr_xor_mapped_address, do: @attr_xor_mapped_address
  def attr_mapped_address, do: @attr_mapped_address
  def attr_fingerprint, do: @attr_fingerprint
  def attr_software, do: @attr_software

  @doc "True when `binary` starts with a ChannelData header (first two bits `01`)."
  @spec channel_data?(binary()) :: boolean()
  def channel_data?(<<first::8, _::binary>>) when first >= 0x40 and first < 0x80, do: true
  def channel_data?(_), do: false

  @doc "True when `binary` starts like a STUN message (first two bits `00`)."
  @spec stun_message?(binary()) :: boolean()
  def stun_message?(<<first::8, _::binary>>) when first < 0x40, do: true
  def stun_message?(_), do: false

  @doc """
  Decode one ChannelData packet: `{:ok, channel, data, rest}`.
  Returns `:error` when the bytes are not a complete ChannelData frame.
  """
  @spec decode_channel_data(binary()) :: {:ok, non_neg_integer(), binary(), binary()} | :error
  def decode_channel_data(<<channel::16, len::16, rest::binary>>)
      when channel >= 0x4000 and channel <= 0x7FFF do
    padded = len + rem(4 - rem(len, 4), 4)

    if byte_size(rest) >= padded do
      <<data::binary-size(len), _pad::binary-size(padded - len), tail::binary>> = rest
      {:ok, channel, data, tail}
    else
      :error
    end
  end

  def decode_channel_data(_), do: :error

  @doc "Encode one ChannelData packet (4-byte aligned)."
  @spec encode_channel_data(non_neg_integer(), binary()) :: binary()
  def encode_channel_data(channel, data) when is_binary(data) do
    len = byte_size(data)
    pad = rem(4 - rem(len, 4), 4)
    <<channel::16, len::16, data::binary, 0::size(pad)-unit(8)>>
  end

  @doc """
  Parse a STUN message. Returns `{:ok, message}` or
  `{:error, :short | :bad_cookie | :bad_length | :bad_attribute}`.
  """
  @spec decode(binary()) :: {:ok, message()} | {:error, atom()}
  def decode(
        <<type::16, length::16, @magic_cookie::32, tid::binary-size(12), attrs::binary>> = raw
      ) do
    if byte_size(raw) < 20 + length do
      {:error, :bad_length}
    else
      case parse_attrs(binary_part(attrs, 0, length), []) do
        {:ok, parsed} -> {:ok, %{type: type, transaction_id: tid, attrs: parsed}}
        {:error, _} = err -> err
      end
    end
  end

  def decode(bin) when is_binary(bin) and byte_size(bin) < 20, do: {:error, :short}
  def decode(_), do: {:error, :bad_cookie}

  @doc "Fetch the first attribute of `type` from a decoded message, or `nil`."
  @spec attr(message(), non_neg_integer()) :: attr_value() | nil
  def attr(%{attrs: attrs}, type) do
    case List.keyfind(attrs, type, 0) do
      {_, value} -> value
      nil -> nil
    end
  end

  @doc "Fetch every attribute of `type` from a decoded message."
  @spec attrs(message(), non_neg_integer()) :: [attr_value()]
  def attrs(%{attrs: attrs}, type) do
    for {t, v} <- attrs, t == type, do: v
  end

  @doc """
  Encode a message. `opts` may carry `:integrity_key` (a
  MESSAGE-INTEGRITY attribute is appended and computed over the
  message with the length adjusted to its end) and
  `:fingerprint` (`true` appends a FINGERPRINT attribute, computed
  over everything before it with the length adjusted to the full
  message). Attrs are written in the order given — callers put
  USERNAME / REALM / NONCE before the integrity attribute, as the
  RFCs require the integrity to cover them.
  """
  @spec encode(message(), keyword()) :: binary()
  def encode(%{type: type, transaction_id: tid, attrs: attrs}, opts \\ []) do
    attrs_bin = Enum.map_join(attrs, "", &encode_attr/1)
    key = Keyword.get(opts, :integrity_key)
    fingerprint? = Keyword.get(opts, :fingerprint, false)

    mi_bin =
      if key do
        mi_len = byte_size(attrs_bin) + 24
        partial = <<type::16, mi_len::16, @magic_cookie::32, tid::binary>> <> attrs_bin
        partial = partial <> <<@attr_message_integrity::16, 20::16, 0::160>>
        hmac = :crypto.mac(:hmac, :sha, key, partial)
        <<@attr_message_integrity::16, 20::16, hmac::binary>>
      else
        ""
      end

    total = byte_size(attrs_bin) + byte_size(mi_bin) + if(fingerprint?, do: 8, else: 0)
    header = <<type::16, total::16, @magic_cookie::32, tid::binary>>
    body = header <> attrs_bin <> mi_bin

    if fingerprint? do
      crc = Bitwise.bxor(:erlang.crc32(body), @fingerprint_xor)
      body <> <<@attr_fingerprint::16, 4::16, crc::32>>
    else
      body
    end
  end

  @doc "Build an error response for `request` (`code`, `reason`, extra attrs)."
  @spec error_response(message(), non_neg_integer(), binary(), [attr()]) :: binary()
  def error_response(request, code, reason, extra_attrs \\ []) do
    attrs =
      [{@attr_error_code, {code, reason}}] ++
        extra_attrs ++
        [{@attr_software, "exjabberd"}]

    encode(%{request | type: @error_response, attrs: attrs})
  end

  @doc """
  Verify the MESSAGE-INTEGRITY of a raw message against `key`.
  Returns `:ok`, `:no_integrity`, or `{:error, :bad_integrity}`.
  """
  @spec verify_integrity(binary(), binary()) :: :ok | :no_integrity | {:error, :bad_integrity}
  def verify_integrity(raw, key) when is_binary(raw) and is_binary(key) do
    case find_attr_offset(raw, @attr_message_integrity) do
      nil ->
        :no_integrity

      offset ->
        <<type::16, _len::16, @magic_cookie::32, tid::binary-size(12), _::binary>> = raw
        adjusted_len = offset + 24 - 20
        head = <<type::16, adjusted_len::16, @magic_cookie::32, tid::binary>>
        middle = binary_part(raw, 20, offset - 20)
        zeroed_mi = <<@attr_message_integrity::16, 20::16, 0::160>>
        expected = :crypto.mac(:hmac, :sha, key, head <> middle <> zeroed_mi)
        <<_::binary-size(offset), _t::16, _l::16, stored::binary-size(20), _::binary>> = raw

        if expected == stored, do: :ok, else: {:error, :bad_integrity}
    end
  end

  @doc """
  Verify the FINGERPRINT of a raw message. Returns `:ok`,
  `:no_fingerprint`, or `{:error, :bad_fingerprint}`.
  """
  @spec verify_fingerprint(binary()) :: :ok | :no_fingerprint | {:error, :bad_fingerprint}
  def verify_fingerprint(raw) when is_binary(raw) do
    case find_attr_offset(raw, @attr_fingerprint) do
      nil ->
        :no_fingerprint

      offset ->
        <<_::binary-size(offset), _t::16, _l::16, stored::32, _::binary>> = raw
        expected = Bitwise.bxor(:erlang.crc32(binary_part(raw, 0, offset)), @fingerprint_xor)

        if expected == stored, do: :ok, else: {:error, :bad_fingerprint}
    end
  end

  @doc "Does the raw message carry a MESSAGE-INTEGRITY attribute?"
  @spec has_integrity?(binary()) :: boolean()
  def has_integrity?(raw), do: find_attr_offset(raw, @attr_message_integrity) != nil

  @doc "Does the raw message carry a FINGERPRINT attribute?"
  @spec has_fingerprint?(binary()) :: boolean()
  def has_fingerprint?(raw), do: find_attr_offset(raw, @attr_fingerprint) != nil

  @doc """
  The RFC 5389 long-term credential key:
  `MD5(username ":" realm ":" password)`.
  """
  @spec long_term_key(binary(), binary(), binary()) :: binary()
  def long_term_key(username, realm, password),
    do: :crypto.hash(:md5, username <> ":" <> realm <> ":" <> password)

  @doc """
  The TURN password for `username` under the shared secret — the
  same derivation XEP-0215 hands to clients, so the server can
  verify MESSAGE-INTEGRITY without storing any password.
  """
  @spec turn_password(binary(), binary()) :: binary()
  def turn_password(username, secret),
    do: Base.encode64(:crypto.mac(:hmac, :sha, secret, username))

  @doc "Mint a stateless nonce (valid for one hour, see `verify_nonce/2`)."
  @spec make_nonce(binary()) :: binary()
  def make_nonce(secret) do
    ts = System.system_time(:second)
    mac = :crypto.mac(:hmac, :sha, secret, <<ts::64>>)
    Base.encode64(<<ts::64, mac::binary>>)
  end

  @doc "Verify a stateless nonce minted by `make_nonce/1`."
  @spec verify_nonce(binary(), binary()) :: :ok | {:error, :bad_nonce | :stale_nonce}
  def verify_nonce(secret, nonce) do
    with {:ok, <<ts::64, mac::binary-size(20)>>} <- Base.decode64(nonce),
         true <- :crypto.mac(:hmac, :sha, secret, <<ts::64>>) == mac do
      now = System.system_time(:second)

      cond do
        ts > now + 60 -> {:error, :stale_nonce}
        now - ts > 3600 -> {:error, :stale_nonce}
        true -> :ok
      end
    else
      _ -> {:error, :bad_nonce}
    end
  end

  @doc "A fresh 12-byte transaction id."
  @spec new_transaction_id() :: binary()
  def new_transaction_id, do: :crypto.strong_rand_bytes(12)

  @doc "Encode a `{family, ip, port}` address attribute (XOR or plain)."
  @spec encode_address(non_neg_integer(), address(), binary()) :: binary()
  def encode_address(attr_type, {family, ip, port}, tid) do
    {family_byte, ip_bin} =
      case family do
        :ipv4 -> {0x01, ip_to_bytes(ip)}
        :ipv6 -> {0x02, ip_to_bytes(ip)}
      end

    {port_x, ip_x} =
      if attr_type in [
           @attr_xor_mapped_address,
           @attr_xor_peer_address,
           @attr_xor_relayed_address
         ] do
        {Bitwise.bxor(port, @magic_cookie >>> 16), xor_ip(ip_bin, tid)}
      else
        {port, ip_bin}
      end

    value = <<0::8, family_byte::8, port_x::16, ip_x::binary>>
    <<attr_type::16, byte_size(value)::16, value::binary, pad(value)::binary>>
  end

  # --- attribute parsing / encoding ---

  defp parse_attrs(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp parse_attrs(<<type::16, len::16, rest::binary>>, acc) do
    padded = len + rem(4 - rem(len, 4), 4)

    if byte_size(rest) < padded do
      {:error, :bad_attribute}
    else
      <<value::binary-size(len), _pad::binary-size(padded - len), tail::binary>> = rest

      case decode_attr(type, value) do
        {:ok, decoded} -> parse_attrs(tail, [{type, decoded} | acc])
        {:error, _} = err -> err
      end
    end
  end

  defp parse_attrs(_, _), do: {:error, :bad_attribute}

  defp decode_attr(type, value)
       when type in [
              @attr_mapped_address,
              @attr_xor_mapped_address,
              @attr_xor_peer_address,
              @attr_xor_relayed_address
            ] do
    # Address attributes need the transaction id to undo the XOR,
    # so the raw value is kept here and resolved by
    # `address_attr/2` / `address_attrs/2` after parsing.
    {:ok, {:raw_address, type, value}}
  end

  defp decode_attr(@attr_username, value), do: {:ok, value}
  defp decode_attr(@attr_realm, value), do: {:ok, value}
  defp decode_attr(@attr_nonce, value), do: {:ok, value}
  defp decode_attr(@attr_software, value), do: {:ok, value}
  defp decode_attr(@attr_message_integrity, value) when byte_size(value) == 20, do: {:ok, value}
  defp decode_attr(@attr_message_integrity, _), do: {:error, :bad_attribute}

  defp decode_attr(@attr_error_code, <<0::21, class::3, number::8, reason::binary>>) do
    {:ok, {class * 100 + number, reason}}
  end

  defp decode_attr(@attr_error_code, _), do: {:error, :bad_attribute}

  defp decode_attr(@attr_lifetime, <<n::32>>), do: {:ok, n}
  defp decode_attr(@attr_requested_transport, <<n::8, _::binary>>), do: {:ok, n}
  defp decode_attr(@attr_channel_number, <<n::16, _::binary>>), do: {:ok, n}
  defp decode_attr(@attr_data, value), do: {:ok, value}
  defp decode_attr(@attr_fingerprint, <<n::32>>), do: {:ok, n}

  defp decode_attr(@attr_unknown_attributes, value) do
    attrs = for <<t::16 <- value>>, do: t
    {:ok, attrs}
  end

  defp decode_attr(_type, value), do: {:ok, value}

  # Address attributes need the transaction id to undo the XOR, so
  # `decode/1` post-processes them after parsing.
  defp decode_address(type, <<0::8, 0x01::8, port_x::16, ip_x::binary-size(4)>>, tid) do
    if type in [@attr_xor_mapped_address, @attr_xor_peer_address, @attr_xor_relayed_address] do
      {:ipv4, bytes_to_ip(xor_ip(ip_x, tid)), Bitwise.bxor(port_x, @magic_cookie >>> 16)}
    else
      {:ipv4, bytes_to_ip(ip_x), port_x}
    end
  end

  defp decode_address(type, <<0::8, 0x02::8, port_x::16, ip_x::binary-size(16)>>, tid) do
    if type in [@attr_xor_mapped_address, @attr_xor_peer_address, @attr_xor_relayed_address] do
      {:ipv6, bytes_to_ip(xor_ip(ip_x, tid)), Bitwise.bxor(port_x, @magic_cookie >>> 16)}
    else
      {:ipv6, bytes_to_ip(ip_x), port_x}
    end
  end

  defp decode_address(_, _, _), do: :error

  @doc """
  Decode an address attribute value from a decoded message. The
  raw `{:raw_address, type, value}` tuples produced by `decode/1`
  are resolved here using the message's transaction id.
  """
  @spec address_attr(message(), non_neg_integer()) :: address() | nil
  def address_attr(%{transaction_id: tid} = msg, type) do
    case attr(msg, type) do
      {:raw_address, ^type, value} ->
        case decode_address(type, value, tid) do
          {:ipv4, ip, port} -> {:ipv4, ip, port}
          {:ipv6, ip, port} -> {:ipv6, ip, port}
          :error -> nil
        end

      _ ->
        nil
    end
  end

  @doc "All address attributes of `type` in a decoded message."
  @spec address_attrs(message(), non_neg_integer()) :: [address()]
  def address_attrs(%{transaction_id: tid} = msg, type) do
    msg
    |> attrs(type)
    |> Enum.map(fn
      {:raw_address, ^type, value} ->
        case decode_address(type, value, tid) do
          {:ipv4, ip, port} -> {:ipv4, ip, port}
          {:ipv6, ip, port} -> {:ipv6, ip, port}
          :error -> nil
        end

      _ ->
        nil
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp encode_attr({type, {:raw_address, _, _}}), do: encode_attr({type, <<>>})

  defp encode_attr({type, {:ipv4, ip, port}}) when type in [@attr_mapped_address] do
    encode_address(type, {:ipv4, ip, port}, <<0::96>>)
  end

  defp encode_attr({type, {:ipv6, ip, port}}) when type in [@attr_mapped_address] do
    encode_address(type, {:ipv6, ip, port}, <<0::96>>)
  end

  # XOR address attributes are encoded by callers through
  # `encode_address/3` (they need the transaction id); the tuple
  # form `{type, {:xor, address}}` is the wire-ready spelling here.
  defp encode_attr({type, {:xor, {family, ip, port}, tid}})
       when type in [@attr_xor_mapped_address, @attr_xor_peer_address, @attr_xor_relayed_address] do
    encode_address(type, {family, ip, port}, tid)
  end

  defp encode_attr({@attr_error_code, {code, reason}}) do
    class = div(code, 100)
    number = rem(code, 100)
    value = <<0::21, class::3, number::8, reason::binary>>
    <<@attr_error_code::16, byte_size(value)::16, value::binary, pad(value)::binary>>
  end

  defp encode_attr({@attr_lifetime, n}), do: encode_u32(@attr_lifetime, n)
  defp encode_attr({@attr_fingerprint, n}), do: encode_u32(@attr_fingerprint, n)

  defp encode_attr({@attr_requested_transport, n}) do
    value = <<n::8, 0::24>>
    <<@attr_requested_transport::16, 4::16, value::binary>>
  end

  defp encode_attr({@attr_channel_number, n}) do
    value = <<n::16, 0::16>>
    <<@attr_channel_number::16, 4::16, value::binary>>
  end

  defp encode_attr({@attr_unknown_attributes, list}) when is_list(list) do
    value = Enum.map_join(list, "", &<<&1::16>>)
    <<@attr_unknown_attributes::16, byte_size(value)::16, value::binary, pad(value)::binary>>
  end

  defp encode_attr({type, value}) when is_binary(value) do
    <<type::16, byte_size(value)::16, value::binary, pad(value)::binary>>
  end

  defp encode_attr({type, value}) when is_integer(value) do
    encode_u32(type, value)
  end

  defp encode_u32(type, n) do
    <<type::16, 4::16, n::32>>
  end

  defp pad(value) do
    case rem(byte_size(value), 4) do
      0 -> ""
      r -> <<0::size(4 - r)-unit(8)>>
    end
  end

  defp xor_ip(ip_bin, tid) do
    key = <<@magic_cookie::32, tid::binary>>
    key = binary_part(key <> key, 0, byte_size(ip_bin))

    :crypto.exor(ip_bin, key)
  end

  defp ip_to_bytes({a, b, c, d}), do: <<a, b, c, d>>

  defp ip_to_bytes({a, b, c, d, e, f, g, h}),
    do: <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>

  defp bytes_to_ip(<<a, b, c, d>>), do: {a, b, c, d}

  defp bytes_to_ip(<<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>),
    do: {a, b, c, d, e, f, g, h}

  # Byte offset of the attribute of `type` in a raw message, or nil.
  defp find_attr_offset(raw, wanted) do
    <<_type::16, length::16, _cookie::32, _tid::binary-size(12), attrs::binary>> = raw
    find_attr_offset(binary_part(attrs, 0, min(length, byte_size(attrs))), wanted, 20)
  end

  defp find_attr_offset(<<>>, _wanted, _offset), do: nil

  defp find_attr_offset(<<type::16, len::16, rest::binary>>, wanted, offset) do
    padded = len + rem(4 - rem(len, 4), 4)

    cond do
      type == wanted ->
        offset

      byte_size(rest) < padded ->
        nil

      true ->
        find_attr_offset(
          binary_part(rest, padded, byte_size(rest) - padded),
          wanted,
          offset + 4 + padded
        )
    end
  end

  defp find_attr_offset(_, _, _), do: nil
end
