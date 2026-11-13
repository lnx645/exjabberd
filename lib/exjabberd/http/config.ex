defmodule Exjabberd.Http.Config do
  @moduledoc """
  Configuration for the HTTP stack (admin web, BOSH, WebSocket, HTTP
  File Upload, REST API) — read from the `http:` section of
  `exjabberd.yml`, with safe defaults.

  ```yaml
  http:
    api_token: "change-me"          # REST API Bearer token
    upload_secret: ""               # HMAC secret; empty = ephemeral per boot
    upload_dir: "priv/uploads"
    upload_max_size: 10485760       # bytes
    upload_expiry_seconds: 3600
    upload_url_base: ""             # empty = http://127.0.0.1:<http port>
    bosh_wait: 60                   # seconds a BOSH poll may hang
    bosh_inactivity: 60             # seconds without a request -> session ends
    paths:
      admin: "/admin"
      api: "/api"
      bosh: "/bosh"
      http_bind: "/http-bind"
      ws: "/ws"
      upload: "/upload"
  ```

  Secrets are never hardcoded in code. When `api_token` /
  `upload_secret` is absent or empty, a random value is generated
  once per boot, kept in ETS, and logged as a warning — the server
  still works, but the value changes on restart, so production
  deployments must set stable values in the config file.
  """

  require Logger

  @doc "Raw `http:` map from the config file (empty map when absent)."
  @spec http_config() :: map()
  def http_config do
    case Exjabberd.Config.get("global", :http, %{}) do
      map when is_map(map) -> map
      _ -> %{}
    end
  end

  @doc "One `http:` key, or `default`."
  @spec get(binary(), term()) :: term()
  def get(key, default \\ nil) do
    Map.get(http_config(), key, Map.get(http_config(), String.to_atom(key), default))
  end

  @doc "REST API Bearer token (configured, or a per-boot ephemeral one)."
  @spec api_token() :: binary()
  def api_token do
    case get("api_token") do
      token when is_binary(token) and token != "" ->
        token

      _ ->
        ephemeral(:api_token, fn ->
          Logger.warning(
            "http.api_token is not configured; generated an ephemeral token for this boot " <>
              "(set http.api_token in exjabberd.yml for a stable one)"
          )
        end)
    end
  end

  @doc "HMAC secret for upload URLs and admin session cookies."
  @spec signing_secret() :: binary()
  def signing_secret do
    case get("upload_secret") do
      secret when is_binary(secret) and secret != "" ->
        secret

      _ ->
        ephemeral(:upload_secret, fn ->
          Logger.warning(
            "http.upload_secret is not configured; generated an ephemeral secret for this boot " <>
              "(set http.upload_secret in exjabberd.yml for stable upload URLs)"
          )
        end)
    end
  end

  @doc "Directory uploaded files are stored in (created on demand)."
  @spec upload_dir() :: binary()
  def upload_dir do
    case get("upload_dir") do
      dir when is_binary(dir) and dir != "" -> dir
      _ -> "priv/uploads"
    end
  end

  @doc "Maximum accepted upload size in bytes."
  @spec upload_max_size() :: pos_integer()
  def upload_max_size do
    case get("upload_max_size") do
      n when is_integer(n) and n > 0 -> n
      _ -> 10 * 1024 * 1024
    end
  end

  @doc "Upload slot lifetime in seconds."
  @spec upload_expiry_seconds() :: pos_integer()
  def upload_expiry_seconds do
    case get("upload_expiry_seconds") do
      n when is_integer(n) and n > 0 -> n
      _ -> 3600
    end
  end

  @doc "Base URL used in upload slot PUT/GET URLs."
  @spec upload_url_base() :: binary()
  def upload_url_base do
    case get("upload_url_base") do
      base when is_binary(base) and base != "" ->
        String.trim_trailing(base, "/")

      _ ->
        "http://127.0.0.1:#{http_port()}"
    end
  end

  @doc """
  Per-account upload quota in bytes: the total size of one user's
  live (non-expired) upload slots may not exceed this. Read from
  `http.upload_quota`; default 100 MB.
  """
  @spec upload_quota_bytes() :: pos_integer()
  def upload_quota_bytes do
    case get("upload_quota") do
      n when is_integer(n) and n > 0 -> n
      _ -> 100 * 1024 * 1024
    end
  end

  @doc """
  ACME http-01 challenge response for a token, from the
  `http.acme_challenges` map (token => key authorization) in
  exjabberd.yml, or `nil`. This is the serving half of ACME; the
  certificate issuance/renewal itself is left to an external ACME
  client (the issued cert lands in the cert directory like any
  other).
  """
  @spec acme_challenge(binary()) :: binary() | nil
  def acme_challenge(token) do
    case get("acme_challenges") do
      map when is_map(map) ->
        case Map.get(map, token) do
          value when is_binary(value) -> value
          _ -> nil
        end

      _ ->
        nil
    end
  end

  @doc "Configured HTTP listener port (from the `exjabberd_http` listen entry, default 5280)."
  @spec http_port() :: pos_integer()
  def http_port do
    Exjabberd.Config.listen()
    |> Enum.find_value(5280, fn
      %{"module" => "exjabberd_http", "port" => port} when is_integer(port) -> port
      _ -> nil
    end)
  end

  @doc "Maximum seconds a BOSH long-poll may hang."
  @spec bosh_wait() :: pos_integer()
  def bosh_wait do
    case get("bosh_wait") do
      n when is_integer(n) and n > 0 -> min(n, 120)
      _ -> 60
    end
  end

  @doc "Seconds without a BOSH request before the session is ended."
  @spec bosh_inactivity() :: pos_integer()
  def bosh_inactivity do
    case get("bosh_inactivity") do
      n when is_integer(n) and n > 0 -> n
      _ -> 60
    end
  end

  @doc "Configured path for a route (`admin`, `api`, `bosh`, `http_bind`, `ws`, `upload`)."
  @spec path(binary(), binary()) :: binary()
  def path(name, default) do
    paths = get("paths", %{})

    case paths do
      map when is_map(map) ->
        Map.get(map, name, Map.get(map, String.to_atom(name), default))

      _ ->
        default
    end
  end

  # A random value generated once per boot, kept in `:persistent_term`
  # (NOT an ETS table owned by a short-lived process: a per-connection
  # process owns nothing that may outlive it — an ETS table created
  # by a connection process dies with it and the next request would
  # generate a *different* secret, invalidating every cookie and
  # upload URL signed before).
  defp ephemeral(key, warn) do
    full_key = {__MODULE__, key}

    case :persistent_term.get(full_key, nil) do
      nil ->
        warn.()
        value = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
        :persistent_term.put(full_key, value)
        value

      value ->
        value
    end
  end
end
