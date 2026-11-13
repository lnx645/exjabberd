defmodule Exjabberd.PgWire do
  @moduledoc """
  A minimal PostgreSQL wire-protocol client (frontend/backend
  protocol 3.0), written natively — no external driver dependency,
  in the same spirit as the rest of this codebase.

  Scope, deliberately small and complete for what the SQL auth
  backend needs:

  * startup + authentication: trust/ok, cleartext password, MD5
    password, and SASL/SCRAM-SHA-256 (the PostgreSQL ≥ 14 default),
    verifying the server's final signature like RFC 5802 requires;
  * the extended query protocol (Parse/Bind/Describe/Execute/Sync)
    with text-format parameters and results — statements are always
    parameterized, never string-interpolated;
  * result decoding for the types the auth schema uses: `bytea`
    (returned as raw bytes), integers, booleans, text.

  One connection is one socket owned by the caller; the auth
  backend serializes access through its GenServer. Any protocol
  error closes the connection — callers reconnect lazily.
  """

  alias Exjabberd.Auth.Scram

  @type conn :: %{sock: port(), params: map(), backend: {integer(), integer()}}
  @type pg_error :: %{required(atom()) => binary()}

  @recv_timeout 15_000
  @connect_timeout 10_000

  # PostgreSQL type OIDs decoded specially; everything else is
  # returned as the raw text the server sent.
  @oid_bytea 17
  @oid_bool 16
  @oid_int2 21
  @oid_int4 23
  @oid_int8 20

  @doc """
  Connect and authenticate.

  Options: `:host`, `:port` (default 5432), `:username`,
  `:password` (default ""), `:database` (defaults to the username).
  """
  @spec connect(keyword()) :: {:ok, conn()} | {:error, term()}
  def connect(opts) do
    host = Keyword.get(opts, :host, "127.0.0.1")
    port = Keyword.get(opts, :port, 5432)
    user = Keyword.fetch!(opts, :username)
    password = Keyword.get(opts, :password, "")
    database = Keyword.get(opts, :database, user)

    with {:ok, sock} <-
           :gen_tcp.connect(
             String.to_charlist(host),
             port,
             [:binary, packet: :raw, active: false],
             @connect_timeout
           ),
         :ok <- send_startup(sock, user, database),
         {:ok, state} <- authenticate(sock, user, password, %{params: %{}, backend: nil}),
         {:ok, state} <- await_ready(sock, state) do
      {:ok, %{sock: sock, params: state.params, backend: state.backend}}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Close the connection (sends Terminate)."
  @spec close(conn()) :: :ok
  def close(%{sock: sock}) do
    _ = :gen_tcp.send(sock, frame(?X, ""))
    :gen_tcp.close(sock)
    :ok
  end

  @doc """
  Run one parameterized statement via the extended protocol.

  Parameters are encoded in text format: binaries bound for
  `bytea` positions must be passed as `{:bytea, bytes}` so they are
  sent in the `\\x...` hex form PostgreSQL expects; integers and
  plain binaries (text) are sent as-is. Returns `{:ok, rows}` with
  one list of decoded values per row, or `{:error, pg_error}` with
  the server's ErrorResponse fields (`:severity`, `:code`,
  `:message`, ...).
  """
  @spec query(conn(), binary(), [term()]) :: {:ok, [[term()]]} | {:error, term()}
  def query(%{sock: sock} = conn, sql, params) do
    encoded = Enum.map(params, &encode_param/1)

    msgs =
      frame(?P, <<0::8, sql::binary, 0::8, 0::16>>) <>
        frame(
          ?B,
          <<0::8, 0::8, 0::16, length(encoded)::16>> <>
            encode_params(encoded) <> <<0::16>>
        ) <>
        frame(?D, <<?S, 0::8>>) <>
        frame(?E, <<0::8, 0::32>>) <>
        frame(?S, "")

    case :gen_tcp.send(sock, msgs) do
      :ok -> collect_results(sock, conn, [], [])
      {:error, reason} -> {:error, reason}
    end
  end

  # --- startup / authentication -------------------------------------------

  defp send_startup(sock, user, database) do
    params =
      Enum.map_join([{"user", user}, {"database", database}, {"client_encoding", "UTF8"}], "", fn {k, v} ->
        <<k::binary, 0::8, v::binary, 0::8>>
      end) <> <<0::8>>

    payload = <<196_608::32, params::binary>>
    :gen_tcp.send(sock, <<byte_size(payload) + 4::32, payload::binary>>)
  end

  defp authenticate(sock, user, password, state) do
    case recv_msg(sock) do
      {:ok, ?R, <<0::32>>, _rest_state} ->
        {:ok, state}

      {:ok, ?R, <<3::32>>, _} ->
        with :ok <- :gen_tcp.send(sock, frame(?p, <<password::binary, 0::8>>)) do
          authenticate(sock, user, password, state)
        end

      {:ok, ?R, <<5::32, salt::binary-size(4)>>, _} ->
        stage1 =
          :crypto.hash(:md5, password <> user)
          |> Base.encode16(case: :lower)

        response = :crypto.hash(:md5, stage1 <> salt) |> Base.encode16(case: :lower)

        with :ok <- :gen_tcp.send(sock, frame(?p, <<"md5", response::binary, 0::8>>)) do
          authenticate(sock, user, password, state)
        end

      {:ok, ?R, <<10::32, mechanisms::binary>>, _} ->
        if "SCRAM-SHA-256" in String.split(mechanisms, <<0::8>>, trim: true) do
          scram_client_first(sock, user, password, state)
        else
          {:error, :no_supported_sasl_mechanism}
        end

      {:ok, ?E, payload, _} ->
        {:error, parse_error(payload)}

      {:error, reason} ->
        {:error, reason}

      other ->
        {:error, {:unexpected_auth_message, other}}
    end
  end

  # SCRAM-SHA-256 client (RFC 5802), as PostgreSQL speaks it:
  # gs2 header "n,,", no channel binding, server signature verified.
  defp scram_client_first(sock, user, password, state) do
    client_nonce = Base.encode64(:crypto.strong_rand_bytes(18))
    bare = "n=#{user},r=#{client_nonce}"
    client_first = "n,," <> bare

    initial =
      <<"SCRAM-SHA-256", 0::8, byte_size(client_first)::32, client_first::binary>>

    with :ok <- :gen_tcp.send(sock, frame(?p, initial)),
         {:ok, ?R, <<11::32, server_first::binary>>, _} <-
           recv_msg(sock) do
      scram_client_final(sock, password, state, bare, server_first)
    else
      {:ok, ?E, payload, _} -> {:error, parse_error(payload)}
      {:error, reason} -> {:error, reason}
      other -> {:error, {:unexpected_sasl_message, other}}
    end
  end

  defp scram_client_final(sock, password, state, client_first_bare, server_first) do
    attrs = parse_scram_attrs(server_first)

    with {:ok, server_nonce} <- Map.fetch(attrs, "r"),
         {:ok, salt_b64} <- Map.fetch(attrs, "s"),
         {:ok, iter_s} <- Map.fetch(attrs, "i"),
         {:ok, salt} <- Base.decode64(salt_b64),
         {iterations, ""} <- Integer.parse(iter_s) do
      salted = Scram.salted_password(password, salt, iterations)
      client_key = hmac(salted, "Client Key")
      stored_key = :crypto.hash(:sha256, client_key)
      server_key = hmac(salted, "Server Key")

      without_proof = "c=#{Base.encode64("n,,")},r=#{server_nonce}"
      auth_message = client_first_bare <> "," <> server_first <> "," <> without_proof
      proof = :crypto.exor(client_key, hmac(stored_key, auth_message))
      client_final = without_proof <> ",p=" <> Base.encode64(proof)

      with :ok <- :gen_tcp.send(sock, frame(?p, client_final)),
           {:ok, ?R, <<12::32, server_final::binary>>, _} <- recv_msg(sock) do
        expected = hmac(server_key, auth_message)

        case parse_scram_attrs(server_final) do
          %{"v" => sig_b64} ->
            case Base.decode64(sig_b64) do
              {:ok, sig} ->
                if :crypto.hash_equals(sig, expected),
                  do: authenticate(sock, "", "", state),
                  else: {:error, :scram_server_signature_mismatch}

              :error ->
                {:error, :scram_bad_server_final}
            end

          %{"e" => err} ->
            {:error, {:scram_failed, err}}

          _ ->
            {:error, :scram_bad_server_final}
        end
      else
        {:ok, ?E, payload, _} -> {:error, parse_error(payload)}
        {:error, reason} -> {:error, reason}
        other -> {:error, {:unexpected_sasl_message, other}}
      end
    else
      _ -> {:error, :scram_bad_server_first}
    end
  end

  defp await_ready(sock, state) do
    case recv_msg(sock) do
      {:ok, ?S, payload, _} ->
        [key, value] = String.split(payload, <<0::8>>, parts: 2)
        await_ready(sock, %{state | params: Map.put(state.params, key, String.trim_trailing(value, <<0::8>>))})

      {:ok, ?K, <<pid::32, secret::32>>, _} ->
        await_ready(sock, %{state | backend: {pid, secret}})

      {:ok, ?Z, _payload, _} ->
        {:ok, state}

      {:ok, ?N, _payload, _} ->
        await_ready(sock, state)

      {:ok, ?E, payload, _} ->
        {:error, parse_error(payload)}

      {:error, reason} ->
        {:error, reason}

      other ->
        {:error, {:unexpected_startup_message, other}}
    end
  end

  # --- result collection ----------------------------------------------------

  defp collect_results(sock, conn, rows, types) do
    case recv_msg(sock) do
      {:ok, ?T, payload, _} ->
        collect_results(sock, conn, rows, parse_row_description(payload))

      {:ok, ?D, payload, _} ->
        collect_results(sock, conn, [decode_row(payload, types) | rows], types)

      {:ok, ?E, payload, _} ->
        # The server skips to Sync; drain to ReadyForQuery so the
        # connection stays usable, then report the error.
        _ = drain_to_ready(sock)
        {:error, parse_error(payload)}

      {:ok, ?Z, _payload, _} ->
        {:ok, Enum.reverse(rows)}

      {:ok, _other, _payload, _} ->
        collect_results(sock, conn, rows, types)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp drain_to_ready(sock) do
    case recv_msg(sock) do
      {:ok, ?Z, _, _} -> :ok
      {:ok, _, _, _} -> drain_to_ready(sock)
      {:error, reason} -> {:error, reason}
    end
  end

  defp parse_row_description(<<count::16, rest::binary>>) do
    parse_fields(rest, count, [])
  end

  defp parse_fields(_rest, 0, acc), do: Enum.reverse(acc)

  defp parse_fields(rest, n, acc) do
    [name, after_name] =
      case :binary.split(rest, <<0::8>>) do
        [a, b] -> [a, b]
        [a] -> [a, ""]
      end

    <<_table_oid::32, _attr::16, type_oid::32, _len::16, _mod::32, _format::16,
      tail::binary>> = after_name

    parse_fields(tail, n - 1, [{name, type_oid} | acc])
  end

  defp decode_row(<<count::16, rest::binary>>, types) do
    {values, _} =
      Enum.map_reduce(types, rest, fn {_name, oid}, bin ->
        case bin do
          <<-1::signed-32, tail::binary>> ->
            {nil, tail}

          <<len::32, raw::binary-size(len), tail::binary>> ->
            {decode_value(oid, raw), tail}
        end
      end)

    _ = count
    values
  end

  defp decode_value(@oid_bytea, <<"\\x", hex::binary>>), do: Base.decode16!(hex, case: :mixed)
  defp decode_value(@oid_bytea, raw), do: raw

  defp decode_value(oid, raw) when oid in [@oid_int2, @oid_int4, @oid_int8] do
    case Integer.parse(raw) do
      {n, ""} -> n
      _ -> raw
    end
  end

  defp decode_value(@oid_bool, "t"), do: true
  defp decode_value(@oid_bool, "f"), do: false
  defp decode_value(_oid, raw), do: raw

  # --- framing ----------------------------------------------------------------

  defp frame(type, payload) when is_integer(type) do
    <<type::8, byte_size(payload) + 4::32, payload::binary>>
  end

  defp encode_params(encoded) do
    Enum.map_join(encoded, "", fn p -> <<byte_size(p)::32, p::binary>> end)
  end

  defp encode_param({:bytea, bytes}) when is_binary(bytes),
    do: "\\x" <> Base.encode16(bytes, case: :lower)

  defp encode_param(n) when is_integer(n), do: Integer.to_string(n)
  defp encode_param(b) when is_binary(b), do: b

  # One backend message: {type, payload}. The socket is in raw mode
  # with a carry buffer kept in the process dictionary, keyed by
  # socket — the client is used from a single process at a time
  # (the auth GenServer), so this stays race-free.
  defp recv_msg(sock) do
    key = {:pgwire_buf, sock}
    buf = Process.get(key, "")

    case take_msg(buf) do
      {:ok, type, payload, rest} ->
        Process.put(key, rest)
        {:ok, type, payload, nil}

      :need_more ->
        case :gen_tcp.recv(sock, 0, @recv_timeout) do
          {:ok, data} ->
            Process.put(key, buf <> data)
            recv_msg(sock)

          {:error, reason} ->
            Process.delete(key)
            {:error, reason}
        end
    end
  end

  defp take_msg(<<type::8, len::32, rest::binary>>) when len >= 4 do
    need = len - 4

    if byte_size(rest) >= need do
      <<payload::binary-size(need), tail::binary>> = rest
      {:ok, type, payload, tail}
    else
      :need_more
    end
  end

  defp take_msg(_), do: :need_more

  defp parse_error(payload) do
    payload
    |> String.split(<<0::8>>, trim: true)
    |> Enum.reduce(%{}, fn field, acc ->
      case field do
        <<code::8, value::binary>> ->
          Map.put(acc, error_field_name(code), value)

        _ ->
          acc
      end
    end)
  end

  defp error_field_name(?S), do: :severity
  defp error_field_name(?V), do: :severity_nonlocalized
  defp error_field_name(?C), do: :code
  defp error_field_name(?M), do: :message
  defp error_field_name(?D), do: :detail
  defp error_field_name(?H), do: :hint
  defp error_field_name(?t), do: :table
  defp error_field_name(_), do: :other

  defp parse_scram_attrs(str) do
    str
    |> String.split(",")
    |> Enum.reduce(%{}, fn part, acc ->
      case String.split(part, "=", parts: 2) do
        [k, v] -> Map.put_new(acc, k, v)
        _ -> acc
      end
    end)
  end

  defp hmac(key, data), do: :crypto.mac(:hmac, :sha256, key, data)
end
