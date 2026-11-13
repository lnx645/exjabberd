defmodule Exjabberd.Config do
  @moduledoc """
  Central configuration store for exjabberd — partial `ejabberd.yml` compatibility, stabil.

  compatible dengan `ejabberd.yml` semantics (subset), parsed via `yaml_elixir`.
  Mendukung per-host `hosts:`, `listen:`, `acl:`, `access_rules:`, `shaper:`,
  `api_permissions:`, `modules:` seperti `ejabberd_config` + `ejabberd_config_transformer`
  + `ejabberd_options` + `ejabberd_option`.

  Contoh ejabberd.yml → `load_file/1` → `GenServer` state per-host.
  """

  use GenServer
  require Logger

  @type host :: binary()
  @type opts :: map()

  def start_link(_arg), do: GenServer.start_link(__MODULE__, %{}, name: __MODULE__)

  @impl true
  def init(_state) do
    initial = %{
      "localhost" => %{
        auth_method: :mnesia,
        default_db: :mnesia,
        log_level: :info,
        max_stanza_size: 262_144,
        shaper: :none,
        acl: %{},
        access_rules: %{},
        modules: %{}
      },
      :global => %{
        log_level: :info,
        s2s_use_starttls: :optional,
        listen: [],
        shaper_rules: %{},
        acme: %{},
        captcha: %{}
      }
    }

    {:ok, initial}
  end

  @doc "Get option for a host (ejabberd_config:get_option, dengan fallback :global)."
  @spec get(host(), atom() | binary(), term()) :: term()
  def get(host, key, default \\ nil) do
    key = normalize_key(key)
    GenServer.call(__MODULE__, {:get, host, key, default})
  end

  @doc "Set option for a host (ejabberd_config:set_option)."
  @spec set(host(), atom() | binary(), term()) :: :ok
  def set(host, key, value) do
    GenServer.call(__MODULE__, {:set, host, normalize_key(key), value})
  end

  @doc "List configured hosts (ejabberd_config:get_hosts)."
  @spec hosts() :: [host()]
  def hosts, do: GenServer.call(__MODULE__, :hosts)

  @doc "Get raw state (for admin/debug, like `ejabberd_config:get_state`)."
  @spec state() :: map()
  def state, do: GenServer.call(__MODULE__, :state)

  @doc "Load YAML file like `ejabberd.yml` (ejabberd_config:load_file) — real YAML via YamlElixir."
  @spec load_file(binary()) :: :ok | {:error, term()}
  def load_file(path) do
    case YamlElixir.read_from_file(path) do
      {:ok, data} -> load_map(data)
      err -> err
    end
  end

  @doc "Load config map after YAML parse (ejabberd_config:load_map) — handle `hosts`, `listen`, `acl`, `access_rules`, `modules`, `shaper`."
  @spec load_map(map()) :: :ok
  def load_map(data) when is_map(data) do
    GenServer.call(__MODULE__, {:load_map, data})
  end

  @doc "Get `hosts:` list from config."
  @spec get_hosts_from_config() :: [host()]
  def get_hosts_from_config, do: hosts()

  @doc "Get listen config (ejabberd_config:get_listen)."
  @spec listen() :: [map()]
  def listen, do: get("global", :listen, [])

  @doc "STARTTLS policy for outbound S2S (`:optional` | `:required` | `:disabled`)."
  @spec s2s_use_starttls() :: atom()
  def s2s_use_starttls, do: get("global", :s2s_use_starttls, :optional)

  @doc "Configured dialback secret (`s2s_dialback_secret`), or nil when unconfigured."
  @spec dialback_secret() :: binary() | nil
  def dialback_secret, do: get("global", :s2s_dialback_secret, nil)

  @doc """
  Configured S2S host overrides: `%{domain => {host, port}}`.

  Lets a deployment map a domain to a host/port without DNS (used
  by the two-node test setup); empty when unconfigured.
  """
  @spec s2s_host_overrides() :: map()
  def s2s_host_overrides, do: get("global", :s2s_host_overrides, %{})

  @doc "Whether SASL EXTERNAL is offered/accepted for S2S (default true)."
  @spec s2s_external?() :: boolean()
  def s2s_external?, do: get("global", :s2s_external, true) != false

  @doc "Whether outbound S2S prefers SASL EXTERNAL over dialback when offered (default false)."
  @spec s2s_prefer_external?() :: boolean()
  def s2s_prefer_external?, do: get("global", :s2s_prefer_external, false) == true

  @doc "Whether XEP-0288 bidirectional S2S streams are offered/used (default true)."
  @spec s2s_bidi?() :: boolean()
  def s2s_bidi?, do: get("global", :s2s_bidi, true) != false

  @doc "PEM file of pinned peer certificates for SASL EXTERNAL, or nil (identity-only)."
  @spec s2s_pinned_certs() :: binary() | nil
  def s2s_pinned_certs, do: get("global", :s2s_pinned_certs, nil)

  @doc "Configured auth backend for a host (`auth_method:`, default `:mnesia`)."
  @spec auth_method(host()) :: atom()
  def auth_method(host), do: get(host, :auth_method, :mnesia)

  @doc "Whether C2S requires STARTTLS before SASL auth (`starttls_required:`, default false)."
  @spec starttls_required?(host()) :: boolean()
  def starttls_required?(host), do: get(host, :starttls_required, false) == true

  @doc """
  Configured SQLite auth database path (`auth_sqlite.path` in
  `exjabberd.yml`, default `"priv/auth.sqlite3"`). The
  `EXJABBERD_AUTH_SQLITE_PATH` environment variable wins over the
  file when set — handy for tests and for pointing a deployment at
  a different file without editing the YAML.
  """
  @spec auth_sqlite_path() :: binary()
  def auth_sqlite_path do
    case System.get_env("EXJABBERD_AUTH_SQLITE_PATH") do
      path when is_binary(path) and path != "" -> path
      _ -> get(:global, :auth_sqlite_path, "priv/auth.sqlite3")
    end
  end

  @doc """
  Configured SQL auth connection (`auth_sql:` in `exjabberd.yml`).

  Returns a map with `:server` (`"postgres"` is the implemented,
  wire-verified one), `:host`, `:port`, `:database`, `:username`
  and `:password`. Every value can be overridden with an
  `EXJABBERD_AUTH_SQL_*` environment variable, which wins over the
  file — the same rule as `auth_sqlite_path/0`.
  """
  @spec auth_sql() :: map()
  def auth_sql do
    base = get(:global, :auth_sql, %{})
    server = sql_env("EXJABBERD_AUTH_SQL_SERVER", base, :server, "postgres")
    host = sql_env("EXJABBERD_AUTH_SQL_HOST", base, :host, "127.0.0.1")
    port = sql_env_port(base)
    database = sql_env("EXJABBERD_AUTH_SQL_DATABASE", base, :database, "exjabberd")
    username = sql_env("EXJABBERD_AUTH_SQL_USERNAME", base, :username, "exjabberd")
    db_secret = sql_env("EXJABBERD_AUTH_SQL_PASSWORD", base, :password, "")

    %{
      server: server,
      host: host,
      port: port,
      database: database,
      username: username
    }
    |> Map.put(:password, db_secret)
  end

  defp sql_env(var, base, key, default) do
    case System.get_env(var) do
      v when is_binary(v) and v != "" -> v
      _ -> Map.get(base, key, default)
    end
  end

  defp sql_env_port(base) do
    case System.get_env("EXJABBERD_AUTH_SQL_PORT") do
      v when is_binary(v) and v != "" ->
        case Integer.parse(v) do
          {n, ""} -> n
          _ -> Map.get(base, :port, 5432)
        end

      _ ->
        Map.get(base, :port, 5432)
    end
  end

  @doc """
  Configured JWT auth shared secret (`auth_jwt_secret:` in
  `exjabberd.yml`), or nil when unconfigured. The
  `EXJABBERD_AUTH_JWT_SECRET` environment variable wins over the
  file — the same rule as the other auth settings.
  """
  @spec auth_jwt_secret() :: binary() | nil
  def auth_jwt_secret do
    case System.get_env("EXJABBERD_AUTH_JWT_SECRET") do
      s when is_binary(s) and s != "" -> s
      _ -> get(:global, :auth_jwt_secret, nil)
    end
  end

  @doc """
  Configured OAuth introspection endpoint (`auth_oauth_url:` in
  `exjabberd.yml`), or nil when unconfigured. The
  `EXJABBERD_AUTH_OAUTH_URL` environment variable wins.
  """
  @spec auth_oauth_url() :: binary() | nil
  def auth_oauth_url do
    case System.get_env("EXJABBERD_AUTH_OAUTH_URL") do
      s when is_binary(s) and s != "" -> s
      _ -> get(:global, :auth_oauth_url, nil)
    end
  end

  @doc """
  Configured external auth script path (`auth_external_script:`
  in `exjabberd.yml`), or nil when unconfigured. The
  `EXJABBERD_AUTH_EXTERNAL_SCRIPT` environment variable wins.
  """
  @spec auth_external_script() :: binary() | nil
  def auth_external_script do
    case System.get_env("EXJABBERD_AUTH_EXTERNAL_SCRIPT") do
      s when is_binary(s) and s != "" -> s
      _ -> get(:global, :auth_external_script, nil)
    end
  end

  @doc "Configured STUN/TURN section (`turn:` in exjabberd.yml), or `%{}`."
  @spec turn() :: map()
  def turn, do: get(:global, :turn, %{})

  @doc "Configured TURN shared secret (`turn.shared_secret`), or nil when unconfigured."
  @spec turn_secret() :: binary() | nil
  def turn_secret, do: get(:global, :turn_shared_secret, nil)

  @doc "Configured MQTT section (`mqtt:` in exjabberd.yml), or `%{}`."
  @spec mqtt() :: map()
  def mqtt, do: get(:global, :mqtt, %{})

  @doc """
  Configured cluster section (`cluster:` in exjabberd.yml), or the
  defaults: `%{enabled: true, nodes: [], cookie: nil}`. `nodes` is
  a list of Erlang node names (`"exjabberd-b@hostname"`); `cookie`
  is the shared Erlang cookie (or nil — see `Exjabberd.Cluster`).
  """
  @spec cluster() :: map()
  def cluster, do: get(:global, :cluster, %{enabled: true, nodes: [], cookie: nil})

  @doc "Is clustering enabled (`cluster.enabled`, default true)?"
  @spec cluster_enabled?() :: boolean()
  def cluster_enabled?, do: cluster()[:enabled] != false and cluster()["enabled"] != false

  @doc "Configured cluster peer nodes (`cluster.nodes`), as node atoms."
  @spec cluster_nodes() :: [node()]
  def cluster_nodes do
    nodes = cluster()[:nodes] || cluster()["nodes"] || []
    List.wrap(nodes) |> Enum.map(&to_string/1) |> Enum.map(&String.to_atom/1)
  end

  @doc "Configured cluster cookie (`cluster.cookie`), or nil when unconfigured."
  @spec cluster_cookie() :: binary() | nil
  def cluster_cookie do
    cookie = cluster()[:cookie] || cluster()["cookie"]
    if is_binary(cookie) and cookie != "", do: cookie, else: nil
  end

  defp normalize_key(k) when is_binary(k), do: String.to_atom(k)
  defp normalize_key(k) when is_atom(k), do: k

  # `auth_method:` values, as atoms. Anything unknown warns and
  # falls back to `:mnesia`.
  defp parse_bool(value, _default) when value in [true, "true", "yes", :true], do: true
  defp parse_bool(value, _default) when value in [false, "false", "no", :false], do: false
  defp parse_bool(_value, default), do: default

  defp parse_auth_method(value) when value in ["mnesia", :mnesia], do: :mnesia
  defp parse_auth_method(value) when value in ["sqlite", :sqlite], do: :sqlite
  defp parse_auth_method(value) when value in ["sql", :sql], do: :sql
  defp parse_auth_method(value) when value in ["ldap", :ldap], do: :ldap
  defp parse_auth_method(value) when value in ["anonymous", :anonymous], do: :anonymous
  defp parse_auth_method(value) when value in ["jwt", :jwt], do: :jwt
  defp parse_auth_method(value) when value in ["external", :external], do: :external
  defp parse_auth_method(value) when value in ["oauth", :oauth], do: :oauth
  defp parse_auth_method(value) when value in ["pam", :pam], do: :pam

  defp parse_auth_method(other) do
    Logger.warning("config auth_method: unknown #{inspect(other)}, using :mnesia")
    :mnesia
  end

  defp parse_auth_sqlite_path(%{"path" => path}) when is_binary(path) and path != "", do: path
  defp parse_auth_sqlite_path(%{path: path}) when is_binary(path) and path != "", do: path
  defp parse_auth_sqlite_path(_), do: "priv/auth.sqlite3"

  # `auth_sql:` YAML → a settings map with atom keys. Accepts
  # string or atom keys (YAML gives strings). The port is coerced
  # to an integer; anything unusable falls back to the defaults,
  # which point at a local PostgreSQL — the backend only connects
  # when `auth_method: sql` is selected anyway.
  defp parse_auth_sql(section) when is_map(section) do
    get = fn key -> Map.get(section, key) || Map.get(section, String.to_atom(key)) end

    port =
      case get.("port") do
        n when is_integer(n) ->
          n

        s when is_binary(s) ->
          case Integer.parse(s) do
            {n, ""} -> n
            _ -> 5432
          end

        _ ->
          5432
      end

    secret = get.("password") || ""

    %{
      server: get.("server") || "postgres",
      host: get.("host") || "127.0.0.1",
      port: port,
      database: get.("database") || "exjabberd",
      username: get.("username") || "exjabberd"
    }
    |> Map.put(:password, secret)
  end

  defp parse_auth_sql(_), do: parse_auth_sql(%{})

  # `s2s_host_overrides:` YAML → `%{domain => {host, port}}`.
  # Accepts a `{host:, port:}` map per domain, or a `"host:port"`
  # string. Anything else is dropped with a warning.
  defp normalize_host_overrides(overrides) when is_map(overrides) do
    Enum.reduce(overrides, %{}, fn {domain, target}, acc ->
      domain = domain |> to_string() |> String.downcase()

      case normalize_override_target(target) do
        {:ok, pair} ->
          Map.put(acc, domain, pair)

        :error ->
          Logger.warning("config s2s_host_overrides #{domain}: ignored #{inspect(target)}")
          acc
      end
    end)
  end

  defp normalize_host_overrides(_), do: %{}

  defp normalize_override_target(%{"host" => host, "port" => port})
       when is_integer(port) do
    {:ok, {to_string(host), port}}
  end

  defp normalize_override_target(%{host: host, port: port}) when is_integer(port) do
    {:ok, {to_string(host), port}}
  end

  defp normalize_override_target(target) when is_binary(target) do
    case String.split(target, ":") do
      [host, port_s] ->
        case Integer.parse(port_s) do
          {port, ""} when port > 0 -> {:ok, {host, port}}
          _ -> :error
        end

      _ ->
        :error
    end
  end

  defp normalize_override_target(_), do: :error

  @impl true
  def handle_call({:get, host, key, default}, _from, state) do
    value = get_in(state, [host, key]) || get_in(state, [:global, key]) || default
    {:reply, value, state}
  end

  def handle_call({:set, host, key, value}, _from, state) do
    next = put_in(state, [Access.key(host, %{}), key], value)
    {:reply, :ok, next}
  end

  def handle_call(:hosts, _from, state) do
    reply = Map.keys(state) |> Enum.reject(&(&1 == :global))
    {:reply, reply, state}
  end

  def handle_call(:state, _from, state), do: {:reply, state, state}

  def handle_call({:load_map, data}, _from, state) do
    hosts = Map.get(data, "hosts", Map.get(data, :hosts, ["localhost"])) |> Enum.map(&to_string/1)

    loglevel =
      Map.get(data, "loglevel", Map.get(data, "log_level", "info"))
      |> to_string()
      |> String.to_atom()

    listen = Map.get(data, "listen", Map.get(data, :listen, []))
    acl = Map.get(data, "acl", Map.get(data, :acl, %{}))
    access_rules = Map.get(data, "access_rules", Map.get(data, :access_rules, %{}))
    shaper = Map.get(data, "shaper", Map.get(data, :shaper, %{}))
    modules = Map.get(data, "modules", Map.get(data, :modules, %{}))

    s2s_use_starttls =
      case Map.get(data, "s2s_use_starttls", Map.get(data, :s2s_use_starttls, "optional")) do
        value when value in ["optional", :optional] ->
          :optional

        value when value in ["required", :required] ->
          :required

        value when value in ["disabled", :disabled] ->
          :disabled

        other ->
          Logger.warning("config s2s_use_starttls: unknown #{inspect(other)}, using :optional")
          :optional
      end

    s2s_dialback_secret =
      case Map.get(data, "s2s_dialback_secret", Map.get(data, :s2s_dialback_secret)) do
        secret when is_binary(secret) and secret != "" -> secret
        _ -> nil
      end

    s2s_host_overrides =
      normalize_host_overrides(
        Map.get(data, "s2s_host_overrides", Map.get(data, :s2s_host_overrides, %{}))
      )

    s2s_external =
      parse_bool(Map.get(data, "s2s_external", Map.get(data, :s2s_external)), true)

    s2s_prefer_external =
      parse_bool(
        Map.get(data, "s2s_prefer_external", Map.get(data, :s2s_prefer_external)),
        false
      )

    s2s_bidi = parse_bool(Map.get(data, "s2s_bidi", Map.get(data, :s2s_bidi)), true)

    s2s_pinned_certs =
      case Map.get(data, "s2s_pinned_certs", Map.get(data, :s2s_pinned_certs)) do
        path when is_binary(path) and path != "" -> path
        _ -> nil
      end

    http_config =
      case Map.get(data, "http", Map.get(data, :http, %{})) do
        map when is_map(map) -> map
        _ -> %{}
      end

    mqtt_config =
      case Map.get(data, "mqtt", Map.get(data, :mqtt, %{})) do
        map when is_map(map) -> map
        _ -> %{}
      end

    # Clustering (Fase 7): `cluster:` — `enabled`, `nodes` (list of
    # Erlang node names, e.g. `"exjabberd-b@hostname"`) and `cookie`
    # (shared Erlang cookie; env `EXJABBERD_ERLANG_COOKIE` wins over
    # this value — see Exjabberd.Cluster).
    cluster_config =
      case Map.get(data, "cluster", Map.get(data, :cluster, %{})) do
        map when is_map(map) ->
          nodes =
            case Map.get(map, "nodes", Map.get(map, :nodes, [])) do
              list when is_list(list) -> Enum.map(list, &to_string/1)
              single when is_binary(single) -> [single]
              _ -> []
            end

          cookie =
            case Map.get(map, "cookie", Map.get(map, :cookie)) do
              c when is_binary(c) and c != "" -> c
              _ -> nil
            end

          %{
            enabled: Map.get(map, "enabled", Map.get(map, :enabled, true)) != false,
            nodes: nodes,
            cookie: cookie
          }

        _ ->
          %{enabled: true, nodes: [], cookie: nil}
      end

    # STUN/TURN (`turn:`): port/realm/lifetimes plus the shared
    # secret that signs ephemeral TURN credentials (XEP-0215) and
    # authenticates allocations (RFC 5389 long-term mechanism).
    # The secret may also be given top-level as
    # `turn_shared_secret:`; the nested key wins.
    turn_config =
      case Map.get(data, "turn", Map.get(data, :turn, %{})) do
        map when is_map(map) -> map
        _ -> %{}
      end

    # Auth backend (Fase 8): `auth_method:` — `mnesia` (default),
    # `sqlite` (real backend, `auth_sqlite.path`), or one of the
    # stub backends (`sql`, `ldap`, `anonymous`, `jwt`, `external`,
    # `oauth`, `pam`). Unknown values warn and fall back to Mnesia
    # so a typo can never lock every account out.
    auth_method =
      parse_auth_method(Map.get(data, "auth_method", Map.get(data, :auth_method, "mnesia")))

    # C2S STARTTLS policy (Fase 11): `starttls_required: true`
    # withholds SASL mechanisms until the stream is encrypted and
    # rejects plaintext auth attempts (ejabberd's listener option,
    # applied server-wide here).
    starttls_required =
      case Map.get(data, "starttls_required", Map.get(data, :starttls_required, false)) do
        true -> true
        "true" -> true
        _ -> false
      end

    # SQLite auth database (`auth_sqlite:`): only `path` for now.
    # No credentials live here — the file holds SCRAM verifier data
    # only, never cleartext passwords.
    auth_sqlite_path =
      parse_auth_sqlite_path(Map.get(data, "auth_sqlite", Map.get(data, :auth_sqlite, %{})))

    # SQL auth database (`auth_sql:`, Fase 16): connection settings
    # for the PostgreSQL backend. The password may live here or in
    # the EXJABBERD_AUTH_SQL_PASSWORD env var (which wins).
    auth_sql =
      parse_auth_sql(Map.get(data, "auth_sql", Map.get(data, :auth_sql, %{})))

    # Stateless auth backends (Fase 16): JWT shared secret, OAuth
    # introspection URL, external script path. Top-level scalars;
    # each has an EXJABBERD_AUTH_* env var that wins at read time.
    scalar = fn key ->
      case Map.get(data, key, Map.get(data, String.to_atom(key))) do
        s when is_binary(s) and s != "" -> s
        _ -> nil
      end
    end

    auth_jwt_secret = scalar.("auth_jwt_secret")
    auth_oauth_url = scalar.("auth_oauth_url")
    auth_external_script = scalar.("auth_external_script")

    turn_shared_secret =
      case Map.get(turn_config, "shared_secret", Map.get(turn_config, :shared_secret)) do
        secret when is_binary(secret) and secret != "" ->
          secret

        _ ->
          case Map.get(data, "turn_shared_secret", Map.get(data, :turn_shared_secret)) do
            secret when is_binary(secret) and secret != "" -> secret
            _ -> nil
          end
      end

    # The configured `hosts:` list is authoritative: the initial
    # state carries a placeholder "localhost" entry, which must go
    # when the file names other hosts — otherwise `hosts()` would
    # return both, modules would start twice, and "first host"
    # lookups (C2S host, S2S sender domain) would be a coin toss.
    fresh = Map.take(state, [:global])

    new_state =
      Enum.reduce(hosts, fresh, fn h, acc ->
        # `Access.key/2`: a host that is not "localhost" has no entry
        # in the initial state yet — plain `put_in([h, ...])` would
        # raise "could not put/update key on a nil value".
        acc
        |> put_in([Access.key(h, %{}), :log_level], loglevel)
        |> put_in([Access.key(h, %{}), :hosts], hosts)
        |> put_in([Access.key(h, %{}), :acl], acl)
        |> put_in([Access.key(h, %{}), :access_rules], access_rules)
        |> put_in([Access.key(h, %{}), :shaper], shaper)
        |> put_in([Access.key(h, %{}), :modules], modules)
        |> put_in([Access.key(h, %{}), :auth_method], auth_method)
        |> put_in([Access.key(h, %{}), :starttls_required], starttls_required)
      end)
      |> put_in([:global, :listen], listen)
      |> put_in([:global, :acl], acl)
      |> put_in([:global, :access_rules], access_rules)
      |> put_in([:global, :auth_sqlite_path], auth_sqlite_path)
      |> put_in([:global, :auth_sql], auth_sql)
      |> put_in([:global, :auth_jwt_secret], auth_jwt_secret)
      |> put_in([:global, :auth_oauth_url], auth_oauth_url)
      |> put_in([:global, :auth_external_script], auth_external_script)
      |> put_in([:global, :s2s_use_starttls], s2s_use_starttls)
      |> put_in([:global, :s2s_dialback_secret], s2s_dialback_secret)
      |> put_in([:global, :s2s_host_overrides], s2s_host_overrides)
      |> put_in([:global, :s2s_external], s2s_external)
      |> put_in([:global, :s2s_prefer_external], s2s_prefer_external)
      |> put_in([:global, :s2s_bidi], s2s_bidi)
      |> put_in([:global, :s2s_pinned_certs], s2s_pinned_certs)
      |> put_in([:global, :turn], turn_config)
      |> put_in([:global, :turn_shared_secret], turn_shared_secret)
      |> put_in([:global, :mqtt], mqtt_config)
      |> put_in([:global, :http], http_config)
      |> put_in([:global, :cluster], cluster_config)

    # Validate via Options like ejabberd does
    Enum.each(hosts, fn h ->
      Enum.each([:loglevel, :max_stanza_size], fn k ->
        case Exjabberd.Options.validate(k, get_in(new_state, [h, k])) do
          :ok -> :ok
          {:error, r} -> Logger.warning("config validate #{h}.#{k}: #{inspect(r)}")
        end
      end)
    end)

    Logger.info("exjabberd config loaded for hosts #{inspect(hosts)} listen=#{length(listen)}")
    {:reply, :ok, new_state}
  end
end
