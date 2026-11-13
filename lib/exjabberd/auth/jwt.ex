defmodule Exjabberd.Auth.Jwt do
  @moduledoc """
  JWT auth backend — `ejabberd_auth_jwt` equivalent (Fase 16).

  Stateless: there is no account store. The password a user
  presents at SASL PLAIN time is a JSON Web Token (RFC 7519); the
  backend authenticates the login when the token

    * is signed with HMAC-SHA-256 (`alg: HS256`) using the shared
      secret from `auth_jwt_secret:` in `exjabberd.yml` (or the
      `EXJABBERD_AUTH_JWT_SECRET` environment variable, which
      wins),
    * carries a `sub` claim equal to the login username,
    * is not expired (`exp`, when present, must be in the future)
      and already valid (`nbf`, when present, must be in the past).

  Verification is implemented natively on `:crypto` — signature
  comparison is constant-time. Only HS256 is accepted; `none` and
  asymmetric algorithms are rejected, so an attacker cannot
  downgrade. Because no verifier is stored, SCRAM cannot be
  offered for this backend (same as ejabberd): PLAIN over TLS is
  the login path. Account management does not exist here — users
  are provisioned by whoever mints the tokens — so
  `create_user/3`, `remove_user/2` and `set_password/3` return
  `{:error, :not_supported}` and `user_exists/2` reports whether
  the backend is configured at all (existence is proven by a
  valid token at authentication time).
  """

  @behaviour Exjabberd.Auth.Behaviour

  require Logger

  alias Exjabberd.Config

  @impl true
  def authenticate(_host, user, token) when is_binary(token) do
    case secret() do
      nil -> false
      shared -> verify(token, user, shared)
    end
  end

  def authenticate(_host, _user, _token), do: false

  @impl true
  def user_exists(_host, _user), do: secret() != nil

  @impl true
  def create_user(_host, _user, _pass), do: {:error, :not_supported}

  @impl true
  def remove_user(_host, _user), do: {:error, :not_supported}

  @impl true
  def set_password(_host, _user, _pass), do: {:error, :not_supported}

  # ----------------------------------------------------------------

  defp secret do
    cfg =
      if Process.whereis(Config) do
        Config.auth_jwt_secret()
      else
        System.get_env("EXJABBERD_AUTH_JWT_SECRET")
      end

    case cfg do
      s when is_binary(s) and s != "" -> s
      _ -> nil
    end
  end

  defp verify(token, user, shared) do
    with [header_b64, payload_b64, sig_b64] <- String.split(token, "."),
         {:ok, header_json} <- b64url_decode(header_b64),
         {:ok, header} <- JSON.decode(header_json),
         true <- header["alg"] == "HS256",
         {:ok, signature} <- b64url_decode(sig_b64),
         true <-
           secure_compare(
             :crypto.mac(:hmac, :sha256, shared, header_b64 <> "." <> payload_b64),
             signature
           ),
         {:ok, payload_json} <- b64url_decode(payload_b64),
         {:ok, claims} <- JSON.decode(payload_json),
         true <- claims["sub"] == user,
         true <- not_expired(claims),
         true <- already_valid(claims) do
      true
    else
      _ -> false
    end
  end

  defp not_expired(%{"exp" => exp}) when is_integer(exp),
    do: exp > System.system_time(:second)

  defp not_expired(_claims), do: true

  defp already_valid(%{"nbf" => nbf}) when is_integer(nbf),
    do: nbf <= System.system_time(:second)

  defp already_valid(_claims), do: true

  defp b64url_decode(part) do
    case Base.url_decode64(part, padding: false) do
      {:ok, bin} -> {:ok, bin}
      :error -> :error
    end
  end

  # Constant-time equality for equal-length binaries.
  defp secure_compare(a, b) when byte_size(a) == byte_size(b) do
    diff =
      Enum.zip_reduce(:binary.bin_to_list(a), :binary.bin_to_list(b), 0, fn x, y, acc ->
        Bitwise.bor(acc, Bitwise.bxor(x, y))
      end)

    diff == 0
  end

  defp secure_compare(_a, _b), do: false
end
