defmodule Exjabberd.Auth.Scram do
  @moduledoc """
  SCRAM-SHA-256 (RFC 5802) — real SASL SCRAM, not a plain fallback.

  Credentials are stored as SCRAM verifier data only: a random salt, an
  iteration count, a StoredKey and a ServerKey. The cleartext password
  is never stored, and a PLAIN login is verified by recomputing the
  StoredKey from the presented password (RFC 5802 §4.1).

  The multi-step exchange is stateful; the C2S listener keeps the
  session returned by `server_first/2` and passes it to
  `verify_client_final/2` when the client answers the challenge.
  """

  @iterations 4096
  @salt_bytes 16
  @nonce_bytes 16

  @type credentials :: %{
          salt: binary(),
          iterations: pos_integer(),
          stored_key: binary(),
          server_key: binary()
        }

  @type session :: %{
          user: binary(),
          client_first_bare: binary(),
          server_first: binary(),
          server_nonce: binary(),
          stored_key: binary(),
          server_key: binary()
        }

  @doc "Derive SCRAM verifier data from a cleartext password."
  @spec derive_credentials(binary()) :: credentials()
  def derive_credentials(password) when is_binary(password) do
    derive_credentials(password, :crypto.strong_rand_bytes(@salt_bytes), @iterations)
  end

  @doc "Derive SCRAM verifier data with an explicit salt / iteration count."
  @spec derive_credentials(binary(), binary(), pos_integer()) :: credentials()
  def derive_credentials(password, salt, iterations)
      when is_binary(password) and is_binary(salt) and is_integer(iterations) do
    salted = salted_password(password, salt, iterations)
    client_key = hmac(salted, "Client Key")
    stored_key = :crypto.hash(:sha256, client_key)
    server_key = hmac(salted, "Server Key")
    %{salt: salt, iterations: iterations, stored_key: stored_key, server_key: server_key}
  end

  @doc "PBKDF2-HMAC-SHA-256 (RFC 5802 Hi)."
  @spec salted_password(binary(), binary(), pos_integer()) :: binary()
  def salted_password(password, salt, iterations) do
    :crypto.pbkdf2_hmac(:sha256, password, salt, iterations, 32)
  end

  @doc """
  Verify a PLAIN password against stored SCRAM credentials by
  recomputing the StoredKey. Constant-time comparison.
  """
  @spec verify_password(binary(), credentials()) :: boolean()
  def verify_password(password, %{salt: salt, iterations: iterations, stored_key: stored})
      when is_binary(password) do
    candidate =
      salted_password(password, salt, iterations)
      |> hmac("Client Key")
      |> then(&:crypto.hash(:sha256, &1))

    byte_size(candidate) == byte_size(stored) and :crypto.hash_equals(candidate, stored)
  end

  def verify_password(_, _), do: false

  @doc """
  Parse a base64 client-first-message.

  Returns `{:ok, %{user, client_nonce, client_first_bare}}` or `:error`.
  Channel binding (`p=...`) and authorization identity are not supported
  and are rejected, like ejabberd does when they cannot be satisfied.
  """
  @spec parse_client_first(binary()) ::
          {:ok, %{user: binary(), client_nonce: binary(), client_first_bare: binary()}}
          | :error
  def parse_client_first(encoded) when is_binary(encoded) do
    with {:ok, decoded} <- Base.decode64(String.trim(encoded)),
         [cb, authzid, bare] <- String.split(decoded, ",", parts: 3),
         true <- cb in ["n", "y"],
         true <- authzid == "",
         %{"n" => user, "r" => nonce} <- parse_attrs(bare),
         true <- user != "" and nonce != "" do
      {:ok, %{user: unescape(user), client_nonce: nonce, client_first_bare: bare}}
    else
      _ -> :error
    end
  end

  @doc """
  Build the server-first-message for a client nonce.

  Returns `{session, server_first_message}`; the session must be kept
  until the client answers the challenge.
  """
  @spec server_first(credentials(), binary()) :: {session(), binary()}
  def server_first(
        %{salt: salt, iterations: iterations, stored_key: stored, server_key: server},
        client_nonce
      ) do
    server_nonce = client_nonce <> Base.encode64(:crypto.strong_rand_bytes(@nonce_bytes))
    first = "r=#{server_nonce},s=#{Base.encode64(salt)},i=#{iterations}"

    session = %{
      user: nil,
      client_first_bare: nil,
      server_first: first,
      server_nonce: server_nonce,
      stored_key: stored,
      server_key: server
    }

    {session, first}
  end

  @doc """
  Verify a base64 client-final-message against the session.

  Returns `{:ok, server_final_message}` (the `v=` verifier the server
  sends inside `<success/>`) or `:error`.
  """
  @spec verify_client_final(binary(), session()) :: {:ok, binary()} | :error
  def verify_client_final(encoded, session) when is_binary(encoded) do
    with {:ok, decoded} <- Base.decode64(String.trim(encoded)),
         %{"c" => channel, "r" => nonce, "p" => proof_b64} <- parse_attrs(decoded),
         # No channel binding in use: RFC 5802 accepts both "n" (the
         # client does not support channel binding) and "y" (the client
         # supports it but believes the server does not). Only "p"
         # carries binding data, which we cannot verify and reject.
         {:ok, cb} <- Base.decode64(channel),
         true <- cb in ["n,,", "y,,"],
         true <- nonce == session.server_nonce,
         {:ok, proof} <- Base.decode64(proof_b64),
         true <- byte_size(proof) == 32 do
      client_final_wo_proof = client_final_without_proof(decoded)

      auth_message =
        session.client_first_bare <> "," <> session.server_first <> "," <> client_final_wo_proof

      client_signature = hmac(session.stored_key, auth_message)
      client_key = :crypto.exor(proof, client_signature)
      candidate_stored = :crypto.hash(:sha256, client_key)

      if byte_size(candidate_stored) == byte_size(session.stored_key) and
           :crypto.hash_equals(candidate_stored, session.stored_key) do
        server_signature = hmac(session.server_key, auth_message)
        {:ok, "v=" <> Base.encode64(server_signature)}
      else
        :error
      end
    else
      _ -> :error
    end
  end

  defp client_final_without_proof(decoded) do
    # Everything before ",p=" — the AuthMessage uses the client-final
    # message without its proof attribute.
    case :binary.split(decoded, ",p=") do
      [head, _] -> head
      _ -> decoded
    end
  end

  # "k=v,k=v,..." attribute list. Later duplicates are ignored.
  defp parse_attrs(str) do
    str
    |> String.split(",")
    |> Enum.reduce(%{}, fn part, acc ->
      case String.split(part, "=", parts: 2) do
        [k, v] -> Map.put_new(acc, k, v)
        _ -> acc
      end
    end)
  end

  # SCRAM username escaping: "=" -> "=3D", "," -> "=2C".
  defp unescape(str) do
    str |> String.replace("=2C", ",") |> String.replace("=3D", "=")
  end

  defp hmac(key, data), do: :crypto.mac(:hmac, :sha256, key, data)
end
