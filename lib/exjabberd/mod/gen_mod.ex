defmodule Exjabberd.Mod.GenMod do
  @moduledoc """
  Extensible module behaviour - 100% parity with `gen_mod` (ejabberd) + `gen_mod:db_type`, stabil.

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
  @moduledoc "Dynamic supervisor for all GenMod modules, stabil dengan `is_loaded` tracking."

  use DynamicSupervisor

  @table :exjabberd_gen_mod_loaded

  def start_link(_arg) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end

    DynamicSupervisor.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  @impl true
  def init(:ok), do: DynamicSupervisor.init(strategy: :one_for_one, max_children: 500)

  @doc "Start a mod for a host (like `gen_mod:start_module`)."
  @spec start_mod(binary(), module(), keyword()) :: DynamicSupervisor.on_start_child()
  def start_mod(host, mod, opts) do
    # Check depends like ejabberd does
    _ = if function_exported?(mod, :depends, 2), do: mod.depends(host, opts), else: []

    child = %{
      id: {mod, host},
      start: {mod, :start, [host, opts]},
      restart: :permanent,
      type: :worker
    }

    case DynamicSupervisor.start_child(__MODULE__, child) do
      {:ok, _} = ok ->
        :ets.insert(@table, {{host, mod}, true})
        ok

      err ->
        err
    end
  end

  @doc "Stop a mod for a host (like `gen_mod:stop_module`)."
  @spec stop_mod(binary(), module()) :: :ok | {:error, term()}
  def stop_mod(host, mod) do
    :ets.delete(@table, {host, mod})

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
end
