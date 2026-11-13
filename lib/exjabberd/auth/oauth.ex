defmodule Exjabberd.Auth.Oauth do
  @moduledoc """
  OAuth 2.0 token-introspection auth backend — the
  `ejabberd_oauth` idea (Fase 16).

  Stateless like the JWT backend: the password a user presents at
  SASL PLAIN time is an OAuth 2.0 access token. The backend asks
  the configured introspection endpoint (RFC 7662) about it with
  an HTTP POST (`token=<token>`, form encoded) via `:httpc`, and
  authenticates the login when the endpoint answers 200 with a
  JSON body where

    * `active` is `true`,
    * `username`, when present, equals the login username, and
    * `exp`, when present, is in the future.

  The endpoint comes from `auth_oauth_url:` in `exjabberd.yml`
  (or the `EXJABBERD_AUTH_OAUTH_URL` environment variable, which
  wins). Every failure — no endpoint configured, timeout, non-200
  status, malformed JSON, inactive token — fails closed
  (`false`). Account management does not exist here (tokens are
  issued by the OAuth provider), so the management callbacks
  return `{:error, :not_supported}` and `user_exists/2` reports
  whether the backend is configured at all.
  """

  @behaviour Exjabberd.Auth.Behaviour

  require Logger

  alias Exjabberd.Config

  @timeout_ms 5_000

  @impl true
  def authenticate(_host, user, token) when is_binary(token) and token != "" do
    case endpoint() do
      nil -> false
      url -> introspect(url, user, token)
    end
  end

  def authenticate(_host, _user, _token), do: false

  @impl true
  def user_exists(_host, _user), do: endpoint() != nil

  @impl true
  def create_user(_host, _user, _pass), do: {:error, :not_supported}

  @impl true
  def remove_user(_host, _user), do: {:error, :not_supported}

  @impl true
  def set_password(_host, _user, _pass), do: {:error, :not_supported}

  # ----------------------------------------------------------------

  defp endpoint do
    cfg =
      if Process.whereis(Config) do
        Config.auth_oauth_url()
      else
        System.get_env("EXJABBERD_AUTH_OAUTH_URL")
      end

    case cfg do
      s when is_binary(s) and s != "" -> s
      _ -> nil
    end
  end

  defp introspect(url, user, token) do
    body = "token=" <> URI.encode_www_form(token)

    req =
      {String.to_charlist(url), [], ~c"application/x-www-form-urlencoded",
       String.to_charlist(body)}

    case :httpc.request(:post, req, [timeout: @timeout_ms], []) do
      {:ok, {{_version, 200, _reason}, _headers, resp_body}} ->
        check_body(resp_body, user)

      {:ok, {{_version, status, _reason}, _headers, _body}} ->
        Logger.debug("auth oauth: introspection answered HTTP #{status}")
        false

      {:error, reason} ->
        Logger.warning("auth oauth: introspection failed: #{inspect(reason)}")
        false
    end
  end

  defp check_body(body, user) do
    case JSON.decode(to_string(body)) do
      {:ok, %{"active" => true} = claims} ->
        username_ok?(claims, user) and not_expired?(claims)

      _ ->
        false
    end
  end

  defp username_ok?(%{"username" => name}, user), do: name == user
  defp username_ok?(_claims, _user), do: true

  defp not_expired?(%{"exp" => exp}) when is_integer(exp),
    do: exp > System.system_time(:second)

  defp not_expired?(_claims), do: true
end
