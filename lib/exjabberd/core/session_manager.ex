defmodule Exjabberd.SessionManager do
  @moduledoc """
  Session manager - partial implementation of `ejabberd_sm` + `ejabberd_sm_mnesia/redis/sql` +
  `ejabberd_sm` hooks + `ejabberd_sm:route` + `c2s` priority, stabil.

  Tracks online sessions (c2s). Backed by ETS locally, and by
  `Exjabberd.Cluster` for distributed lookups: every registration
  is mirrored cluster-wide (Fase 7), so `get_sessions/2`,
  `get_session/2`, `get_resources/1` and `all_sessions/0` see
  sessions on other nodes too, and `route_to_user/1` delivers to
  them over the Erlang distribution connection. Supports multiple
  resources per user, priority (`priority` in presence), Caps, and
  `sm` c2s resumption (XEP-0198) seperti ejabberd.

  Like ejabberd: `ejabberd_sm:register_session/4`, `unregister_session/3`, `get_sessions/2`, `route/1`, `get_user_resources`.
  """

  use GenServer
  require Logger

  @table :exjabberd_sm
  @by_jid :exjabberd_sm_jid
  @by_host :exjabberd_sm_host

  def start_link(_arg) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  @impl true
  def init(state) do
    for t <- [@table, @by_jid, @by_host] do
      if :ets.whereis(t) == :undefined do
        :ets.new(t, [:named_table, :public, :set, read_concurrency: true, write_concurrency: true])
      end
    end

    {:ok, state}
  end

  @doc """
  Register a session (ejabberd_sm:register_session/4) dengan `priority` + `caps`.

  Cluster-wide (Fase 7): the session is also entered in the
  `Exjabberd.Cluster` mirror and broadcast to every connected node,
  so `get_sessions/2` on another node finds it.
  """
  @spec register(binary(), binary(), pid(), keyword()) :: :ok
  def register(user, resource, pid, opts \\ [])
      when is_binary(user) and is_binary(resource) and is_pid(pid) do
    ensure_tables()
    bare = String.downcase(user)
    host = Keyword.get(opts, :host, "localhost")
    priority = Keyword.get(opts, :priority, 0)

    :ets.insert(
      @table,
      {{bare, resource}, pid, System.system_time(:second), Keyword.put(opts, :priority, priority)}
    )

    :ets.insert(@by_jid, {pid, {bare, resource}})
    :ets.insert(@by_host, {{host, bare, resource}, pid})
    Exjabberd.Cluster.register_session(bare, resource, pid, priority, host)
    Exjabberd.Hooks.run(:sm_register_connection, host, {bare, resource, pid})
    :telemetry.execute([:exjabberd, :sm, :register], %{count: 1}, %{user: bare, host: host})
    Logger.debug("sm register #{bare}/#{resource} prio=#{priority}")
    :ok
  end

  @doc "Unregister session (ejabberd_sm:unregister_session/3)."
  @spec unregister(binary(), binary()) :: :ok
  def unregister(user, resource) do
    ensure_tables()
    bare = String.downcase(user)

    case :ets.lookup(@table, {bare, resource}) do
      [{{_, _}, pid, _, opts}] ->
        :ets.delete(@table, {bare, resource})
        :ets.delete(@by_jid, pid)
        host = Keyword.get(opts, :host, "localhost")
        :ets.delete(@by_host, {host, bare, resource})
        Exjabberd.Cluster.unregister_session(bare, resource, pid)
        Exjabberd.Hooks.run(:sm_unregister_connection, host, {bare, resource})
        :ok

      [] ->
        # No local entry — it may still live in the cluster mirror
        # (e.g. a stale remote registration); remove it there too.
        Exjabberd.Cluster.unregister_session(bare, resource)
        :ok
    end
  end

  @doc "Get pid for user/resource (ejabberd_sm:get_session). Cluster-wide: falls back to the mirror."
  @spec get_session(binary(), binary()) :: {:ok, pid()} | :error
  def get_session(user, resource) do
    ensure_tables()
    bare = String.downcase(user)

    case :ets.lookup(@table, {bare, resource}) do
      [{{_, _}, pid, _, _}] ->
        if Process.alive?(pid),
          do: {:ok, pid},
          else:
            (
              unregister(user, resource)
              :error
            )

      [] ->
        case Exjabberd.Cluster.sessions_for(bare)
             |> Enum.find(fn {r, _, _, _, _, _} -> r == resource end) do
          {_, pid, _, _, _, _} ->
            if Exjabberd.Cluster.alive?(pid) do
              {:ok, pid}
            else
              Exjabberd.Cluster.unregister_session(bare, resource, pid)
              :error
            end

          nil ->
            :error
        end
    end
  end

  @doc "List all resources for a bare JID (ejabberd_sm:get_user_resources). Cluster-wide."
  @spec get_resources(binary()) :: [binary()]
  def get_resources(user) do
    ensure_tables()
    bare = String.downcase(user)

    local = :ets.match(@table, {{bare, :"$1"}, :_, :_, :_}) |> List.flatten()
    remote = Exjabberd.Cluster.sessions_for(bare) |> Enum.map(fn {r, _, _, _, _, _} -> r end)
    Enum.uniq(local ++ remote)
  end

  @doc """
  Get all sessions for user with priority (ejabberd_sm:get_sessions).

  Cluster-wide (Fase 7): local ETS entries plus live remote entries
  from the `Exjabberd.Cluster` mirror, deduplicated by resource
  (local wins) and sorted by priority descending. Remote pids are
  liveness-checked with an `:rpc` probe; a dead remote entry is
  purged from the mirror.
  """
  @spec get_sessions(binary(), binary()) :: [{binary(), pid(), integer()}]
  def get_sessions(user, _host) do
    ensure_tables()
    bare = String.downcase(user)

    local =
      :ets.match(@table, {{bare, :"$1"}, :"$2", :_, :"$3"})
      |> Enum.map(fn [r, pid, opts] -> {r, pid, Keyword.get(opts, :priority, 0)} end)
      |> Enum.filter(fn {_r, pid, _prio} -> Process.alive?(pid) end)

    local_resources = MapSet.new(local, fn {r, _, _} -> r end)
    local_pids = MapSet.new(local, fn {_, pid, _} -> pid end)

    remote =
      Exjabberd.Cluster.sessions_for(bare)
      |> Enum.reject(fn {r, pid, n, _, _, _} ->
        n == node() or r in local_resources or pid in local_pids
      end)
      |> Enum.flat_map(fn {r, pid, _n, prio, _host, _ts} ->
        if Exjabberd.Cluster.alive?(pid) do
          [{r, pid, prio}]
        else
          Exjabberd.Cluster.unregister_session(bare, r, pid)
          []
        end
      end)

    (local ++ remote)
    |> Enum.sort_by(fn {_r, _pid, prio} -> prio end, :desc)
  end

  @doc "Get user present resources sorted by priority (for routing)."
  @spec get_present_resources(binary()) :: [binary()]
  def get_present_resources(user) do
    get_sessions(user, "global") |> Enum.map(fn {r, _pid, _prio} -> r end)
  end

  @doc "Count online sessions on THIS node (ejabberd_sm:count). Cluster-wide counts live in `Exjabberd.Cluster.status/0`."
  @spec count() :: non_neg_integer()
  def count do
    case :ets.whereis(@table) do
      :undefined -> 0
      _ -> :ets.info(@table, :size)
    end
  end

  @doc "All online sessions as `{bare_jid, resource, pid}` — cluster-wide (Fase 7)."
  @spec all_sessions() :: [{binary(), binary(), pid()}]
  def all_sessions do
    ensure_tables()

    local =
      case :ets.whereis(@table) do
        :undefined ->
          []

        _ ->
          :ets.tab2list(@table)
          |> Enum.map(fn {{bare, resource}, pid, _, _} -> {bare, resource, pid} end)
          |> Enum.filter(fn {_bare, _res, pid} -> Process.alive?(pid) end)
      end

    local_keys = MapSet.new(local, fn {bare, res, _} -> {bare, res} end)

    remote =
      Exjabberd.Cluster.sessions_for_all()
      |> Enum.reject(fn {bare, res, pid, n} ->
        n == node() or {bare, res} in local_keys or not Exjabberd.Cluster.alive?(pid)
      end)
      |> Enum.map(fn {bare, res, pid, _n} -> {bare, res, pid} end)

    local ++ remote
  end

  @doc "Count per host."
  @spec count(binary()) :: non_neg_integer()
  def count(host) when is_binary(host) do
    case :ets.whereis(@by_host) do
      :undefined -> 0
      _ -> :ets.match(@by_host, {{host, :_, :_}, :_}) |> length()
    end
  end

  @doc "Route to all resources with highest priority (ejabberd_sm:route). For `message` type `chat` only highest, for others all."
  @spec route_to_user(binary(), map()) :: :ok
  def route_to_user(bare_jid, stanza) do
    sessions = get_sessions(bare_jid, "global")

    cond do
      sessions == [] ->
        Exjabberd.Hooks.run(:offline_message, bare_jid, stanza)

      stanza[:type] == "chat" or stanza.name == :message ->
        # Highest priority only like ejabberd does for chat
        [{_res, pid, _prio} | _] = sessions
        send(pid, {:route, stanza})

      true ->
        Enum.each(sessions, fn {_res, pid, _prio} -> send(pid, {:route, stanza}) end)
    end

    :ok
  end

  defp ensure_tables do
    for t <- [@table, @by_jid, @by_host] do
      if :ets.whereis(t) == :undefined do
        :ets.new(t, [:named_table, :public, :set, read_concurrency: true, write_concurrency: true])
      end
    end
  end
end
