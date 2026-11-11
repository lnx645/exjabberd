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

  defp normalize_key(k) when is_binary(k), do: String.to_atom(k)
  defp normalize_key(k) when is_atom(k), do: k

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

    new_state =
      Enum.reduce(hosts, state, fn h, acc ->
        acc
        |> put_in([h, :log_level], loglevel)
        |> put_in([h, :hosts], hosts)
        |> put_in([h, :acl], acl)
        |> put_in([h, :access_rules], access_rules)
        |> put_in([h, :shaper], shaper)
        |> put_in([h, :modules], modules)
      end)
      |> put_in([:global, :listen], listen)
      |> put_in([:global, :acl], acl)
      |> put_in([:global, :access_rules], access_rules)

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
