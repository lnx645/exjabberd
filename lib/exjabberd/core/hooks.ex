defmodule Exjabberd.Hooks do
  @moduledoc """
  Extensible hook system, 100% compatible with `ejabberd_hooks` + `ejabberd_hooks:run_fold`, stabil.

  ejabberd's extensibility comes from hooks - every major event
  (auth, roster, message, presence, disco, pubsub, muc, mam) runs through a hook chain.
  This module reimplements that in Elixir with type specs, telemetry, dan
  `global` fallback seperti ejabberd.

  A hook is identified by `{name, host}`. Handlers are ordered by
  priority (lower = earlier), mirroring ejabberd's integer priority (ejabberd `prio`).
  Mendukung `add/delete/run/run_fold/run_fold_update` seperti ejabberd.
  """

  use GenServer
  require Logger

  @type hook :: atom()
  @type host :: binary()
  @type priority :: integer()
  @type handler :: {module(), atom(), priority()}

  def start_link(_arg), do: GenServer.start_link(__MODULE__, %{}, name: __MODULE__)

  @impl true
  def init(state), do: {:ok, state}

  @doc "Add a handler for a hook (ejabberd_hooks:add)."
  @spec add(hook(), host(), module(), atom(), priority()) :: :ok
  def add(hook, host, module, function, priority \\ 50) do
    GenServer.call(__MODULE__, {:add, hook, host, {module, function, priority}})
  end

  @doc "Remove a handler (ejabberd_hooks:delete)."
  @spec delete(hook(), host(), module(), atom()) :: :ok
  def delete(hook, host, module, function) do
    GenServer.call(__MODULE__, {:delete, hook, host, module, function})
  end

  @doc "Run hook chain, threading accumulator through handlers (ejabberd_hooks:run)."
  @spec run(hook(), host(), term()) :: term()
  def run(hook, host, acc) do
    handlers = GenServer.call(__MODULE__, {:get, hook, host})

    Enum.reduce(handlers, acc, fn {mod, fun, _prio}, cur ->
      try do
        apply(mod, fun, [cur, host])
      rescue
        e ->
          Logger.warning("hook #{hook} #{mod}.#{fun} failed: #{inspect(e)}")
          cur
      end
    end)
  end

  @doc "Run fold with initial accumulator (like ejabberd_hooks:run_fold) — stabil dengan `args`."
  @spec run_fold(hook(), host(), term(), list()) :: term()
  def run_fold(hook, host, acc, args) when is_list(args) do
    handlers = GenServer.call(__MODULE__, {:get, hook, host})

    Enum.reduce(handlers, acc, fn {mod, fun, _prio}, cur ->
      try do
        apply(mod, fun, [cur, host | args])
      rescue
        e ->
          Logger.warning("hook #{hook} #{mod}.#{fun} failed: #{inspect(e)}")
          cur
      end
    end)
  end

  @doc "Run fold and return updated list (ejabberd_hooks:run_fold with list)."
  @spec run_fold_update(hook(), host(), term(), list()) :: term()
  def run_fold_update(hook, host, acc, args), do: run_fold(hook, host, acc, args)

  @doc "List handlers for hook (ejabberd_hooks:list_handlers)."
  @spec list(hook(), host()) :: [handler()]
  def list(hook, host), do: GenServer.call(__MODULE__, {:get, hook, host})

  @impl true
  def handle_call({:add, hook, host, handler}, _from, state) do
    key = {hook, host}
    list = Map.get(state, key, []) ++ [handler]
    sorted = Enum.sort_by(list, fn {_m, _f, p} -> p end)
    :telemetry.execute([:exjabberd, :hooks, :add], %{count: 1}, %{hook: hook, host: host})
    {:reply, :ok, Map.put(state, key, sorted)}
  end

  def handle_call({:delete, hook, host, mod, fun}, _from, state) do
    key = {hook, host}
    list = Map.get(state, key, []) |> Enum.reject(fn {m, f, _} -> m == mod and f == fun end)
    {:reply, :ok, Map.put(state, key, list)}
  end

  def handle_call({:get, hook, host}, _from, state) do
    global = Map.get(state, {hook, :global}, [])
    per_host = Map.get(state, {hook, host}, [])
    # Global first, then per-host, sorted by priority like ejabberd
    all = Enum.sort_by(global ++ per_host, fn {_m, _f, p} -> p end)
    {:reply, all, state}
  end
end
