defmodule Exjabberd.Mod.GenMod do
  @moduledoc """
  Extensible module behaviour - partial implementation of `gen_mod` (ejabberd) + `gen_mod:db_type`, stabil.

  Every exjabberd feature is a `GenMod`. This is what makes ejabberd
  extensible - and exjabberd keeps that exact contract, but with
  Elixir typespecs, `mod_options` validation via `Exjabberd.Options`, and
  `depends` hard/soft.

  To create a new feature:

      defmodule MyMod do
        @behaviour Exjabberd.Mod.GenMod

        @impl true
        def start(host, opts), do: :ok

        @impl true
        def stop(host), do: :ok

        # Optional: dependencies like ejabberd `depends/2`
        def depends(_host, _opts), do: [{Exjabberd.Mod.Roster, :hard}]
      end

  And enable it in `config.exs`:

      config :exjabberd, :modules, %{"example.com" => [MyMod: []]}
  """

  @type host :: binary()
  @type opts :: keyword()

  @callback start(host(), opts()) :: :ok | {:error, term()}
  @callback stop(host()) :: :ok | {:error, term()}
  @callback reload(host(), opts(), opts()) :: :ok | {:error, term()}
  @callback depends(host(), opts()) :: [{module(), :hard | :soft}]
  @callback mod_options(host()) :: keyword()
  @callback mod_doc() :: map()
  @callback mod_opt_type(atom()) :: term()

  @optional_callbacks reload: 3, depends: 2, mod_options: 1, mod_doc: 0, mod_opt_type: 1

  defmacro __using__(_opts) do
    quote do
      @behaviour Exjabberd.Mod.GenMod

      @impl true
      def reload(_host, _new_opts, _old_opts), do: :ok

      @impl true
      def depends(_host, _opts), do: []

      @impl true
      def mod_options(_host), do: []

      @impl true
      def mod_doc, do: %{desc: "No documentation", doc: "See https://docs.ejabberd.im"}

      @impl true
      def mod_opt_type(_opt), do: :binary

      defoverridable reload: 3, depends: 2, mod_options: 1, mod_doc: 0, mod_opt_type: 1
    end
  end

  @doc "Get DB type for mod/host (like `gen_mod:db_type`)."
  @spec db_type(binary(), module()) :: :mnesia | :sql | :ldap | :redis
  def db_type(host, mod) do
    # Like ejabberd: per-mod `db_type` or global `default_db`
    mod_opts = if function_exported?(mod, :mod_options, 1), do: mod.mod_options(host), else: []
    Keyword.get(mod_opts, :db_type) || Exjabberd.Config.get(host, :default_db, :mnesia)
  end

  @doc "Is mod loaded for host? (like `gen_mod:is_loaded`)."
  @spec is_loaded?(binary(), module()) :: boolean()
  def is_loaded?(host, mod) do
    case :ets.whereis(:exjabberd_gen_mod_loaded) do
      :undefined -> false
      _ -> :ets.member(:exjabberd_gen_mod_loaded, {host, mod})
    end
  end
end

defmodule Exjabberd.Mod.Supervisor do
  @moduledoc """
  Module loader for all GenMod modules, with `is_loaded` tracking.

  Modules are plain Elixir modules, not GenServers: they are started by
  calling `mod.start(host, opts)` directly (like ejabberd's
  `gen_mod:start_module/3` calls the module's `start/2`). They used to
  be started as DynamicSupervisor children, which can never work —
  a child spec expects `{:ok, pid}` from `start/2`, but every mod
  returns plain `:ok`.
  """

  use DynamicSupervisor
  require Logger

  @table :exjabberd_gen_mod_loaded
  @opts_table :exjabberd_mod_opts

  def start_link(_arg) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end

    if :ets.whereis(@opts_table) == :undefined do
      :ets.new(@opts_table, [:named_table, :public, :set])
    end

    DynamicSupervisor.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  @impl true
  def init(:ok), do: DynamicSupervisor.init(strategy: :one_for_one, max_children: 500)

  @doc "Start a mod for a host (like `gen_mod:start_module`). Returns `:ok` or `{:error, reason}`."
  @spec start_mod(binary(), module(), keyword()) :: :ok | {:error, term()}
  def start_mod(host, mod, opts) do
    # Check depends like ejabberd does
    _ = if function_exported?(mod, :depends, 2), do: mod.depends(host, opts), else: []

    try do
      case mod.start(host, opts) do
        :ok ->
          :ets.insert(@table, {{host, mod}, true})
          :ets.insert(@opts_table, {{host, mod}, opts})
          :ok

        {:error, _} = err ->
          err

        other ->
          {:error, {:unexpected_start_return, other}}
      end
    rescue
      e ->
        Logger.error("mod #{inspect(mod)} start failed for #{host}: #{inspect(e)}")
        {:error, e}
    catch
      kind, reason -> {:error, {kind, reason}}
    end
  end

  @doc "Stop a mod for a host (like `gen_mod:stop_module`)."
  @spec stop_mod(binary(), module()) :: :ok | {:error, term()}
  def stop_mod(host, mod) do
    :ets.delete(@table, {host, mod})
    :ets.delete(@opts_table, {host, mod})

    case mod.stop(host) do
      :ok -> :ok
      other -> other
    end
  end

  @doc "Loaded mods for host."
  @spec loaded(binary()) :: [module()]
  def loaded(host) do
    :ets.match(@table, {{host, :"$1"}, :_}) |> List.flatten()
  end

  @doc "Options a mod was started with (empty list when unknown)."
  @spec get_opts(binary(), module()) :: keyword()
  def get_opts(host, mod) do
    case :ets.whereis(@opts_table) do
      :undefined ->
        []

      _ ->
        case :ets.lookup(@opts_table, {host, mod}) do
          [{_, opts}] -> opts
          [] -> []
        end
    end
  end

  @doc "Start every module configured for a host (`modules:` in exjabberd.yml). Unknown module names are logged and skipped; a failing module does not stop the others."
  @spec start_all(binary()) :: :ok
  def start_all(host) do
    modules = Exjabberd.Config.get(host, :modules, %{})

    modules =
      if modules == %{} or is_nil(modules), do: default_modules(), else: modules

    Enum.each(modules, fn {name, opts} ->
      start_mod_by_name(host, to_string(name), opts)
    end)

    :ok
  end

  @doc "Start one configured module by its `mod_*` name from exjabberd.yml."
  @spec start_mod_by_name(binary(), binary(), term()) :: :ok | {:error, term()}
  def start_mod_by_name(host, name, opts) do
    case module_for(name) do
      nil ->
        Logger.warning("mod #{name} has no implementation in this codebase, skipped")
        {:error, :unknown_module}

      mod ->
        start_mod(host, mod, to_keyword_opts(opts))
    end
  end

  @doc "Default module set (mirrors the `modules:` section of exjabberd.yml). Used when no configuration file was loaded."
  @spec default_modules() :: map()
  def default_modules do
    %{
      "mod_adhoc" => %{},
      "mod_adhoc_api" => %{},
      "mod_admin_extra" => %{},
      "mod_announce" => %{},
      "mod_avatar" => %{},
      "mod_blocking" => %{},
      "mod_bosh" => %{},
      "mod_caps" => %{},
      "mod_captcha" => %{},
      "mod_carboncopy" => %{},
      "mod_client_state" => %{max_queue: 100},
      "mod_configure" => %{},
      "mod_disco" => %{},
      "mod_fail2ban" => %{},
      "mod_http_api" => %{},
      "mod_http_upload" => %{},
      "mod_last" => %{},
      "mod_mam" => %{default: "always", max_archive_size: 500},
      "mod_mix" => %{},
      "mod_mqtt" => %{},
      "mod_jingle" => %{},
      "mod_muc" => %{},
      "mod_muc_admin" => %{},
      "mod_offline" => %{},
      "mod_omemo" => %{},
      "mod_ping" => %{},
      "mod_privacy" => %{},
      "mod_private" => %{},
      "mod_proxy65" => %{},
      "mod_pubsub" => %{},
      "mod_push" => %{},
      "mod_push_keepalive" => %{},
      "mod_register" => %{},
      "mod_roster" => %{},
      "mod_s2s_bidi" => %{},
      "mod_s2s_dialback" => %{},
      "mod_shared_roster" => %{},
      "mod_stream_mgmt" => %{max_ack_queue: 100, resume_timeout: 60},
      "mod_stun_disco" => %{},
      "mod_time" => %{},
      "mod_vcard" => %{},
      "mod_vcard_xupdate" => %{},
      "mod_version" => %{"show_os" => false}
    }
  end

  @doc "Resolve an exjabberd.yml module name (`mod_roster`) to its Elixir module, or `nil` when there is no implementation."
  @spec module_for(binary()) :: module() | nil
  def module_for("mod_adhoc"), do: Exjabberd.Mod.Adhoc
  def module_for("mod_adhoc_api"), do: Exjabberd.Mod.Adhoc.Full
  def module_for("mod_admin_extra"), do: Exjabberd.Mod.AdminExtra
  def module_for("mod_announce"), do: Exjabberd.Mod.Announce
  def module_for("mod_avatar"), do: Exjabberd.Mod.Avatar
  def module_for("mod_blocking"), do: Exjabberd.Mod.Blocking
  def module_for("mod_bosh"), do: Exjabberd.Mod.Bosh
  def module_for("mod_caps"), do: Exjabberd.Mod.Caps
  def module_for("mod_captcha"), do: Exjabberd.Mod.Captcha
  def module_for("mod_carboncopy"), do: Exjabberd.Mod.Carbons
  def module_for("mod_client_state"), do: Exjabberd.Mod.Csi
  def module_for("mod_configure"), do: Exjabberd.Mod.Configure
  def module_for("mod_disco"), do: Exjabberd.Mod.Disco
  def module_for("mod_fail2ban"), do: Exjabberd.Mod.Fail2ban
  def module_for("mod_http_api"), do: Exjabberd.Mod.HttpApi
  def module_for("mod_http_upload"), do: Exjabberd.Mod.HttpUpload
  def module_for("mod_last"), do: Exjabberd.Mod.Last
  def module_for("mod_mam"), do: Exjabberd.Mod.Mam
  def module_for("mod_mix"), do: Exjabberd.Mod.Mix
  def module_for("mod_mqtt"), do: Exjabberd.Mod.Mqtt
  def module_for("mod_mqtt_bridge"), do: Exjabberd.Mod.MqttBridge
  def module_for("mod_jingle"), do: Exjabberd.Mod.Jingle
  def module_for("mod_muc"), do: Exjabberd.Mod.Muc
  def module_for("mod_muc_admin"), do: Exjabberd.Mod.MucAdmin
  def module_for("mod_offline"), do: Exjabberd.Mod.Offline
  def module_for("mod_omemo"), do: Exjabberd.Mod.Omemo
  def module_for("mod_ping"), do: Exjabberd.Mod.Ping
  def module_for("mod_privacy"), do: Exjabberd.Mod.Privacy
  def module_for("mod_private"), do: Exjabberd.Mod.Private
  def module_for("mod_proxy65"), do: Exjabberd.Mod.Proxy65
  def module_for("mod_pubsub"), do: Exjabberd.Mod.PubSub
  def module_for("mod_push"), do: Exjabberd.Mod.Push
  def module_for("mod_push_keepalive"), do: Exjabberd.Mod.PushKeepalive
  def module_for("mod_register"), do: Exjabberd.Mod.Register
  def module_for("mod_roster"), do: Exjabberd.Mod.Roster
  def module_for("mod_s2s_bidi"), do: Exjabberd.Mod.S2sBidi
  def module_for("mod_s2s_dialback"), do: Exjabberd.Mod.S2S
  def module_for("mod_shared_roster"), do: Exjabberd.Mod.SharedRoster
  def module_for("mod_stream_mgmt"), do: Exjabberd.Mod.StreamMgmt
  def module_for("mod_stun_disco"), do: Exjabberd.Mod.StunDispatch
  def module_for("mod_time"), do: Exjabberd.Mod.Time
  def module_for("mod_vcard"), do: Exjabberd.Mod.Vcard
  def module_for("mod_vcard_xupdate"), do: Exjabberd.Mod.VcardXupdate
  def module_for("mod_version"), do: Exjabberd.Mod.Version
  # Every name in `modules:` now resolves to a real module.
  def module_for(_), do: nil

  # YAML options arrive as string-keyed maps (or nil for `mod_foo: {}`).
  # Convert them to keyword lists with atom keys; nested maps convert
  # recursively. Values that are not maps are kept as-is.
  defp to_keyword_opts(nil), do: []
  defp to_keyword_opts(opts) when is_list(opts), do: opts

  defp to_keyword_opts(opts) when is_map(opts) do
    Enum.map(opts, fn {k, v} -> {String.to_atom(to_string(k)), convert_opt(v)} end)
  end

  defp to_keyword_opts(_), do: []

  defp convert_opt(v) when is_map(v) do
    Enum.map(v, fn {k, val} -> {String.to_atom(to_string(k)), convert_opt(val)} end)
  end

  defp convert_opt(v), do: v
end
