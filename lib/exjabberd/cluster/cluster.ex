defmodule Exjabberd.Cluster do
  @moduledoc """
  Cluster manager — distributed Erlang multi-node support (Fase 7).

  Replaces the old single-node stub (which kept routes/sessions in
  local-only ETS and whose `broadcast/1` never actually delivered
  anything to peers) with real clustering:

  * **Node connections**: peers from the `cluster.nodes` config list
    (plus `EXJABBERD_CLUSTER_JOIN` at boot) are connected with
    `Node.connect/1` and re-tried every 5 s, so a node that comes
    back online rejoins without a manual restart. Node up/down is
    watched with `:net_kernel.monitor_nodes/1`. The Erlang cookie
    comes from `cluster.cookie` in `exjabberd.yml`, the
    `EXJABBERD_ERLANG_COOKIE` env var, or `config :exjabberd,
    cluster_cookie:` — never hardcoded; when none is configured the
    node's default cookie (`~/.erlang.cookie`, which Erlang
    generates itself when missing) stays in effect, so `:rpc`
    tooling keeps working. A real cluster needs the SAME cookie on
    every node — two nodes with different cookies cannot connect,
    and no per-boot random cookie is generated (it would break
    tooling without making clustering work).
  * **Cluster-wide sessions**: every C2S bind registers its session
    in a replicated ETS mirror (`:exjabberd_cluster_sessions`, one
    entry per `{bare_jid, resource}` with pid, node, priority and
    host). Registration/unregistration is broadcast to all connected
    nodes, a joining node exchanges full state on `:nodeup`, and a
    dead node's entries are purged on `:nodedown`. `SessionManager`
    merges the mirror with its local ETS, so routing never needs to
    know which node a user is on.
  * **Cluster-wide routes**: same mirror mechanism for
    `Router.register_route/2` (`:exjabberd_cluster_routes`).
    `Router.lookup/1` falls back to this mirror, and a remote pid is
    checked with an `:rpc` liveness probe — plain
    `Process.alive?/1` raises `ArgumentError` for remote pids, so it
    must never be used on them (verified empirically).
  * **Shared Mnesia**: when a node joins with
    `EXJABBERD_CLUSTER_JOIN` it wipes its own fresh schema directory
    and starts Mnesia with `extra_db_nodes` pointing at the peer, so
    it copies the cluster schema; the shared tables then get
    `disc_copies` on the joining node (`Exjabberd.Mnesia`).
    Tables shared this way: `:passwd`, `:offline_messages`,
    `:mam_archive`, `:pubsub_nodes`, `:pubsub_items`,
    `:pubsub_subs`, `:pubsub_affs`, `:roster`. A node that merely
    auto-connects later (both sides already have independent
    schemas) keeps session routing working, but Mnesia stays
    unshared — Mnesia cannot merge two independent schemas live,
    and the join is logged as a warning instead of failing the boot.
  * **Node down**: mirror entries for the dead node are purged, an
    `unavailable` presence is broadcast for each of its sessions
    that has no session left anywhere, and messages to its users
    fall through to the normal offline/error path (stored offline
    when the user exists, `service-unavailable` otherwise) — never
    a hang.

  Deliberately NOT shared (documented in `README.md`): MUC rooms,
  vCards, Stream Management resume state and per-host ETS caches
  stay node-local; `:pg`/`:global` are only used as a lookup
  fallback, the ETS mirror is the source of truth for routing.
  """

  use GenServer
  require Logger

  @table :exjabberd_cluster_nodes
  @route_table :exjabberd_cluster_routes
  @session_table :exjabberd_cluster_sessions

  @first_connect_delay 2_000
  @connect_interval 5_000
  @sync_delay 1_000
  @rpc_timeout 5_000
  @alive_timeout 1_000

  # Mnesia tables replicated across the cluster (see Exjabberd.Mnesia).
  @shared_tables [
    :passwd,
    :offline_messages,
    :mam_archive,
    :pubsub_nodes,
    :pubsub_items,
    :pubsub_subs,
    :pubsub_affs,
    :roster
  ]

  def start_link(_arg) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  @impl true
  def init(state) do
    ensure_tables()

    :ets.insert(
      @table,
      {node(),
       %{status: :running, started: System.system_time(:second), mnesia: mnesia_running?()}}
    )

    # Monitor node up/down like ejabberd_cluster.
    :net_kernel.monitor_nodes(true)
    Process.send_after(self(), :auto_connect, @first_connect_delay)
    # Push our (initially empty) state to any node that is already
    # connected, e.g. via the Mnesia join flow at boot.
    Process.send_after(self(), :push_state, @first_connect_delay)
    {:ok, state}
  end

  # ------------------------------------------------------------------
  # Cookie handling
  # ------------------------------------------------------------------

  @doc """
  Erlang cookie for distribution, resolved in order: the
  `EXJABBERD_ERLANG_COOKIE` env var, `config :exjabberd,
  cluster_cookie:`, then `cluster.cookie` from `exjabberd.yml`
  (only once the Config server has loaded the file). Returns `nil`
  when nothing is configured.
  """
  @spec resolve_cookie() :: binary() | nil
  def resolve_cookie do
    System.get_env("EXJABBERD_ERLANG_COOKIE") ||
      Application.get_env(:exjabberd, :cluster_cookie) ||
      config_cookie()
  end

  defp config_cookie do
    if Process.whereis(Exjabberd.Config) do
      try do
        Exjabberd.Config.cluster_cookie()
      catch
        _, _ -> nil
      end
    else
      nil
    end
  rescue
    _ -> nil
  catch
    _, _ -> nil
  end

  @doc """
  Apply the resolved cookie to this node (when configured). When
  nothing is configured, the node's default Erlang cookie is left
  alone — deliberately NOT replaced with a random ephemeral one:
  an ephemeral cookie would silently break every out-of-band tool
  that connects with the default cookie (`:rpc` probes, remote
  shells, `Node.connect` from another node), and two nodes that
  each generate their own random cookie still cannot cluster, so
  generation buys nothing. Erlang itself generates
  `~/.erlang.cookie` when it does not exist yet. For a real
  multi-node cluster, set the SAME cookie on every node (see
  `resolve_cookie/0`). Safe to call before distribution is up
  (no-op until the node is `:nonode@nohost` no more) and safe to
  call repeatedly.
  """
  @spec apply_cookie() :: :ok
  def apply_cookie do
    if node() == :nonode@nohost do
      # Distribution is not up yet (Application.start calls this
      # before Mnesia.setup starts it) — there is no cookie to set.
      # Callers must call apply_cookie/0 again once distributed.
      :ok
    else
      case resolve_cookie() do
        cookie when is_binary(cookie) and cookie != "" ->
          :erlang.set_cookie(node(), String.to_atom(cookie))
          Logger.info("cluster: Erlang cookie set from configuration/environment")
          :ok

        _ ->
          Logger.info(
            "cluster.cookie is not configured; using this node's default Erlang cookie " <>
              "(~/.erlang.cookie) — for a multi-node cluster, set the SAME cluster.cookie " <>
              "in exjabberd.yml or EXJABBERD_ERLANG_COOKIE on every node"
          )

          :ok
      end
    end
  end

  @doc "Is the cookie configured (env / app env / yml), as opposed to ephemeral?"
  @spec cookie_configured?() :: boolean()
  def cookie_configured?, do: is_binary(resolve_cookie()) and resolve_cookie() != ""

  # ------------------------------------------------------------------
  # Membership
  # ------------------------------------------------------------------

  @doc "Join cluster with node (ejabberd_cluster:join/1)."
  @spec join(node()) :: :ok | {:error, term()}
  def join(node) when is_atom(node) do
    if Process.whereis(__MODULE__) do
      GenServer.call(__MODULE__, {:join, node}, 30_000)
    else
      do_join(node)
    end
  end

  @doc "Leave cluster (ejabberd_cluster:leave/0): disconnect + purge state."
  @spec leave(node()) :: :ok
  def leave(node) when is_atom(node) do
    if Process.whereis(__MODULE__) do
      GenServer.call(__MODULE__, {:leave, node})
    else
      purge_node(node)
      :ok
    end
  end

  @doc "List cluster nodes (ejabberd_cluster:get_nodes/0) — the real connected set."
  @spec nodes() :: [node()]
  def nodes, do: Enum.uniq([node() | Node.list()])

  @doc "Is clustering enabled? (more than one node)."
  @spec clustered?() :: boolean()
  def clustered?, do: length(nodes()) > 1

  @doc """
  Cluster status for RPC / admin: this node, connected nodes, cookie
  state, Mnesia state and session counts. The cookie VALUE is never
  exposed here.
  """
  @spec status() :: map()
  def status do
    %{
      node: node(),
      nodes: nodes(),
      connected: Node.list(),
      clustered: clustered?(),
      cookie_configured: cookie_configured?(),
      mnesia: %{
        running: mnesia_running?(),
        tables: if(mnesia_running?(), do: :mnesia.system_info(:tables), else: []),
        db_nodes: if(mnesia_running?(), do: :mnesia.system_info(:db_nodes), else: []),
        extra_db_nodes: if(mnesia_running?(), do: :mnesia.system_info(:extra_db_nodes), else: [])
      },
      sessions: %{local: local_session_count(), remote: remote_session_count()},
      routes: route_count()
    }
  end

  defp local_session_count do
    case :ets.whereis(@session_table) do
      :undefined -> 0
      _ -> :ets.tab2list(@session_table) |> Enum.count(fn {_, _, n, _, _, _} -> n == node() end)
    end
  end

  defp remote_session_count do
    case :ets.whereis(@session_table) do
      :undefined -> 0
      _ -> :ets.tab2list(@session_table) |> Enum.count(fn {_, _, n, _, _, _} -> n != node() end)
    end
  end

  defp route_count do
    case :ets.whereis(@route_table) do
      :undefined -> 0
      _ -> :ets.info(@route_table, :size)
    end
  end

  # ------------------------------------------------------------------
  # Session mirror (cluster-wide SM registry)
  # ------------------------------------------------------------------

  @doc "Register a session in the cluster mirror (called by SessionManager)."
  @spec register_session(binary(), binary(), pid(), integer(), binary()) :: :ok
  def register_session(bare, resource, pid, priority, host)
      when is_binary(bare) and is_binary(resource) and is_pid(pid) do
    ensure_tables()
    ts = System.system_time(:millisecond)
    :ets.insert(@session_table, {{bare, resource}, pid, node(), priority, host, ts})
    fan_out({:register_session, bare, resource, pid, node(), priority, host, ts})
    :ok
  end

  @doc """
  Unregister a session from the cluster mirror. When `pid` is given,
  a peer only deletes its entry when it still points at that pid —
  so tearing down a session on node A never removes a live session
  for the same `{bare, resource}` on node B.
  """
  @spec unregister_session(binary(), binary(), pid() | nil) :: :ok
  def unregister_session(bare, resource, pid \\ nil)
      when is_binary(bare) and is_binary(resource) do
    ensure_tables()
    delete_session_entry(bare, resource, pid)
    fan_out({:unregister_session, bare, resource, pid})
    :ok
  end

  defp delete_session_entry(bare, resource, nil) do
    :ets.delete(@session_table, {bare, resource})
  end

  defp delete_session_entry(bare, resource, pid) do
    case :ets.lookup(@session_table, {bare, resource}) do
      [{{_, _}, ^pid, _, _, _, _}] -> :ets.delete(@session_table, {bare, resource})
      _ -> :ok
    end
  end

  @doc "Mirror entries for a bare JID: `[{resource, pid, node, priority, host, ts}]`."
  @spec sessions_for(binary()) :: [{binary(), pid(), node(), integer(), binary(), integer()}]
  def sessions_for(bare) when is_binary(bare) do
    ensure_tables()

    :ets.match(@session_table, {{bare, :"$1"}, :"$2", :"$3", :"$4", :"$5", :"$6"})
    |> Enum.map(fn [resource, pid, n, priority, host, ts] ->
      {resource, pid, n, priority, host, ts}
    end)
  end

  @doc "All mirror entries: `[{bare, resource, pid, node}]`."
  @spec sessions_for_all() :: [{binary(), binary(), pid(), node()}]
  def sessions_for_all do
    ensure_tables()

    :ets.tab2list(@session_table)
    |> Enum.map(fn {{bare, res}, pid, n, _prio, _host, _ts} -> {bare, res, pid, n} end)
  end

  @doc """
  Purge every mirror entry (sessions + routes) that belongs to `node`
  and return the bare JIDs whose sessions were removed, so the caller
  can broadcast `unavailable` presence for them.
  """
  @spec purge_node(node()) :: [binary()]
  def purge_node(dead_node) when is_atom(dead_node) do
    ensure_tables()

    bares =
      :ets.tab2list(@session_table)
      |> Enum.filter(fn {_, _, n, _, _, _} -> n == dead_node end)
      |> Enum.map(fn {{bare, _res}, _, _, _, _, _} -> bare end)
      |> Enum.uniq()

    :ets.match_delete(@session_table, {{:_, :_}, :_, dead_node, :_, :_, :_})
    :ets.match_delete(@route_table, {:_, :_, dead_node})
    bares
  end

  # ------------------------------------------------------------------
  # Route mirror
  # ------------------------------------------------------------------

  @doc "Register route in cluster (ejabberd_router_mnesia:register_route)."
  @spec register_route(binary(), pid()) :: :ok
  def register_route(jid, pid) when is_binary(jid) and is_pid(pid) do
    ensure_tables()
    :ets.insert(@route_table, {jid, pid, node()})
    fan_out({:register_route, jid, pid, node()})
    :ok
  end

  @doc "Unregister route. When `pid` is given, only delete when the entry still points at it."
  @spec unregister_route(binary(), pid() | nil) :: :ok
  def unregister_route(jid, pid \\ nil) when is_binary(jid) do
    ensure_tables()
    delete_route_entry(jid, pid)
    fan_out({:unregister_route, jid, pid})
    :ok
  end

  defp delete_route_entry(jid, nil), do: :ets.delete(@route_table, jid)

  defp delete_route_entry(jid, pid) do
    case :ets.lookup(@route_table, jid) do
      [{_, ^pid, _}] -> :ets.delete(@route_table, jid)
      _ -> :ok
    end
  end

  @doc "Lookup route in cluster (mirror first, then `:global`)."
  @spec lookup_route(binary()) :: {:ok, pid(), node()} | :error
  def lookup_route(jid) when is_binary(jid) do
    ensure_tables()

    case :ets.lookup(@route_table, jid) do
      [{_, pid, n}] ->
        {:ok, pid, n}

      [] ->
        # Fallback :global (ejabberd uses :global whereis_name for SM)
        case :global.whereis_name({:route, jid}) do
          pid when is_pid(pid) -> {:ok, pid, node(pid)}
          :undefined -> :error
        end
    end
  end

  @doc "Register global route (ejabberd `global:register_name`)."
  @spec register_global(binary(), pid()) :: :ok
  def register_global(jid, pid) when is_binary(jid) and is_pid(pid) do
    :global.register_name({:route, jid}, pid)
    :ok
  catch
    _, _ -> :ok
  end

  @doc """
  Is `pid` alive? `Process.alive?/1` raises `ArgumentError` for
  remote pids, so remote pids are checked with an `:rpc` probe
  (1 s timeout — a dead/unreachable node answers `false`, never a
  hang).
  """
  @spec alive?(pid()) :: boolean()
  def alive?(pid) when is_pid(pid) do
    if node(pid) == node() do
      Process.alive?(pid)
    else
      :rpc.call(node(pid), :erlang, :is_process_alive, [pid], @alive_timeout) == true
    end
  catch
    _, _ -> false
  end

  # ------------------------------------------------------------------
  # State exchange
  # ------------------------------------------------------------------

  @doc "Full mirror state, for a joining node."
  @spec export_state() :: map()
  def export_state do
    ensure_tables()

    %{
      node: node(),
      sessions:
        :ets.tab2list(@session_table)
        |> Enum.map(fn {{bare, res}, pid, n, prio, host, ts} ->
          {bare, res, pid, n, prio, host, ts}
        end),
      routes: :ets.tab2list(@route_table)
    }
  end

  @doc "Merge a peer's exported state into the local mirrors."
  @spec apply_state(map()) :: :ok
  def apply_state(%{sessions: sessions, routes: routes}) do
    ensure_tables()

    Enum.each(sessions, fn {bare, res, pid, n, prio, host, ts} ->
      :ets.insert(@session_table, {{bare, res}, pid, n, prio, host, ts})
    end)

    Enum.each(routes, fn {jid, pid, n} -> :ets.insert(@route_table, {jid, pid, n}) end)
    :ok
  end

  def apply_state(_), do: :ok

  @doc "Exchange full state with a peer (best effort)."
  @spec sync_with(node()) :: :ok | {:error, term()}
  def sync_with(peer) when is_atom(peer) do
    case :rpc.call(peer, __MODULE__, :export_state, [], @rpc_timeout) do
      %{sessions: _, routes: _} = state ->
        apply_state(state)
        send({__MODULE__, peer}, {:cluster_state, export_state()})
        :ok

      {:badrpc, reason} ->
        {:error, reason}

      other ->
        {:error, other}
    end
  catch
    _, reason -> {:error, reason}
  end

  @doc "Wait for Mnesia sync (ejabberd_cluster_mnesia:wait_for_sync)."
  @spec wait_for_sync(integer()) :: :ok | {:error, term()}
  def wait_for_sync(timeout \\ 30_000) do
    if mnesia_running?() do
      tables = [:schema | @shared_tables]

      case :mnesia.wait_for_tables(tables, timeout) do
        :ok -> :ok
        {:timeout, remaining} -> {:error, {:timeout, remaining}}
        {:error, reason} -> {:error, reason}
      end
    else
      :ok
    end
  end

  @doc "Wait for sync with :global sync (ejabberd `wait_for_sync` + global)."
  @spec wait_for_global_sync(integer()) :: :ok
  def wait_for_global_sync(timeout \\ 5_000) do
    try do
      :global.sync()
      _ = timeout
      :ok
    catch
      _, _ -> :ok
    end
  end

  @doc "Consistent hashing for sharding MUC/PubSub across cluster (ejabberd `consistent_hash`)."
  @spec hash_node(binary()) :: node()
  def hash_node(key) when is_binary(key) do
    ns = nodes()
    if length(ns) <= 1, do: node(), else: Enum.at(ns, :erlang.phash2(key, length(ns)))
  end

  @doc "Is key local to this node via consistent hash? Like ejabberd_cluster routing."
  @spec local?(binary()) :: boolean()
  def local?(key) when is_binary(key), do: hash_node(key) == node()

  @doc "Broadcast to all nodes (ejabberd_cluster:send_to_all/1)."
  @spec broadcast(term()) :: :ok
  def broadcast(msg) do
    fan_out({:cluster_broadcast, msg})
    :ok
  end

  @doc "Cluster call via :rpc (ejabberd_cluster:call)."
  @spec call(node(), atom(), atom(), [term()]) :: term() | {:error, term()}
  def call(node, mod, fun, args) do
    :rpc.call(node, mod, fun, args)
  catch
    _, r -> {:error, r}
  end

  @doc """
  Mnesia extra_db_nodes sync (ejabberd_cluster_mnesia:join). Only
  works when the peer does not already carry an independent schema;
  two independent schemas cannot be merged live, so a failure here
  is logged (session routing still works) and the operator is told
  to restart the node with `EXJABBERD_CLUSTER_JOIN`.
  """
  @spec mnesia_join(node()) :: :ok | {:error, term()}
  def mnesia_join(peer) when is_atom(peer) do
    if not mnesia_running?() do
      {:error, :mnesia_not_running}
    else
      # `change_config(:extra_db_nodes, ...)` alone does NOT verify
      # the peer is reachable (it happily records a dead node), so
      # check connectivity first — otherwise a typo would silently
      # pollute the schema's extra_db_nodes list.
      connected? = peer in Node.list() or Node.connect(peer) == true

      if not connected? do
        {:error, :cannot_connect}
      else
        do_mnesia_join(peer)
      end
    end
  end

  defp do_mnesia_join(peer) do
    db_nodes = :mnesia.system_info(:db_nodes)

    if peer in db_nodes do
      :ok
    else
      case :mnesia.change_config(:extra_db_nodes, [peer]) do
        {:ok, _} ->
          for t <- @shared_tables, t in :mnesia.system_info(:tables) do
            try do
              :mnesia.add_table_copy(t, peer, :disc_copies)
            catch
              _, _ -> :ok
            end
          end

          try do
            :mnesia.change_table_copy_type(:schema, peer, :disc_copies)
          catch
            _, _ -> :ok
          end

          Logger.info("cluster: mnesia joined #{peer}")
          :ok

        {:error, reason} = err ->
          Logger.warning(
            "cluster: mnesia join with #{peer} failed (#{inspect(reason)}); " <>
              "session routing still works, but Mnesia tables stay unshared — " <>
              "restart this node with EXJABBERD_CLUSTER_JOIN=#{peer} to share them"
          )

          err
      end
    end
  end

  @doc "Tables replicated across the cluster."
  @spec shared_tables() :: [atom()]
  def shared_tables, do: @shared_tables

  # ------------------------------------------------------------------
  # GenServer callbacks
  # ------------------------------------------------------------------

  @impl true
  def handle_call({:join, peer}, _from, state) do
    {:reply, do_join(peer), state}
  end

  def handle_call({:leave, peer}, _from, state) do
    _ = purge_node(peer)
    :ets.delete(@table, peer)
    Node.disconnect(peer)
    Logger.info("exjabberd left cluster node #{peer}")
    {:reply, :ok, Map.delete(state, peer)}
  end

  def handle_call(_msg, _from, state), do: {:reply, :ok, state}

  @impl true
  def handle_info(:auto_connect, state) do
    apply_cookie_from_config()
    peers = configured_peers()

    if cluster_enabled?() do
      Enum.each(peers, fn peer ->
        if peer != node() and peer not in Node.list() do
          case Node.connect(peer) do
            true -> Logger.info("cluster: connected to #{peer}")
            false -> Logger.debug("cluster: cannot connect to #{peer} yet, retrying")
            :ignored -> Logger.debug("cluster: connect to #{peer} ignored (not distributed?)")
          end
        end
      end)
    end

    Process.send_after(self(), :auto_connect, @connect_interval)
    {:noreply, state}
  end

  def handle_info(:push_state, state) do
    fan_out({:cluster_state, export_state()})
    {:noreply, state}
  end

  def handle_info({:sync_node, peer, attempt}, state) do
    if peer in Node.list() do
      case sync_with(peer) do
        :ok ->
          Logger.info("cluster: state synced with #{peer}")

        {:error, reason} when attempt < 2 ->
          Logger.debug("cluster: sync with #{peer} failed (#{inspect(reason)}), retrying")
          Process.send_after(self(), {:sync_node, peer, attempt + 1}, 3_000)

        {:error, reason} ->
          Logger.warning("cluster: sync with #{peer} failed: #{inspect(reason)}")
      end
    end

    {:noreply, state}
  end

  # `:net_kernel.monitor_nodes(true)` sends 2-tuples
  # `{:nodeup | :nodedown, node}`; the 3-tuple form (with an info
  # element) exists when extra monitoring options are enabled.
  # Both must be handled — matching only the 3-tuple silently
  # disables purge/sync (found live: nodeup fell through to the
  # generic clause and no sync ever ran).
  def handle_info({:nodeup, peer}, state), do: handle_nodeup(peer, state)
  def handle_info({:nodeup, peer, _info}, state), do: handle_nodeup(peer, state)
  def handle_info({:nodedown, peer}, state), do: handle_nodedown(peer, state)
  def handle_info({:nodedown, peer, _info}, state), do: handle_nodedown(peer, state)

  def handle_info({:cluster_state, remote_state}, state) do
    apply_state(remote_state)
    {:noreply, state}
  end

  def handle_info({:cluster_broadcast, msg}, state) do
    Logger.debug("Cluster broadcast: #{inspect(msg)}")
    {:noreply, state}
  end

  def handle_info({:register_route, jid, pid, n}, state) do
    :ets.insert(@route_table, {jid, pid, n})
    {:noreply, state}
  end

  def handle_info({:unregister_route, jid, pid}, state) do
    delete_route_entry(jid, pid)
    {:noreply, state}
  end

  # Backwards-compatible shape (no pid) from older peers.
  def handle_info({:unregister_route, jid}, state) do
    :ets.delete(@route_table, jid)
    {:noreply, state}
  end

  def handle_info({:register_session, bare, resource, pid, n, priority, host, ts}, state) do
    :ets.insert(@session_table, {{bare, resource}, pid, n, priority, host, ts})
    {:noreply, state}
  end

  def handle_info({:unregister_session, bare, resource, pid}, state) do
    delete_session_entry(bare, resource, pid)
    {:noreply, state}
  end

  # Backwards-compatible shape (no pid) from older peers.
  def handle_info({:unregister_session, bare, resource}, state) do
    :ets.delete(@session_table, {bare, resource})
    {:noreply, state}
  end

  def handle_info(msg, state) do
    Logger.debug("Cluster msg: #{inspect(msg)}")
    {:noreply, state}
  end

  # ------------------------------------------------------------------
  # Private helpers
  # ------------------------------------------------------------------

  defp handle_nodeup(peer, state) do
    Logger.info("exjabberd node up #{peer}")

    :ets.insert(
      @table,
      {peer,
       %{status: :connected, joined: System.system_time(:second), mnesia: mnesia_running?()}}
    )

    # Let the peer finish booting before asking for its state, and
    # try to share Mnesia with it (no-op when already shared).
    Process.send_after(self(), {:sync_node, peer, 0}, @sync_delay)
    _ = mnesia_join(peer)
    {:noreply, Map.put(state, peer, :connected)}
  end

  defp handle_nodedown(peer, state) do
    Logger.warning("exjabberd node down #{peer}")
    :ets.delete(@table, peer)
    bares = purge_node(peer)

    # Presence `unavailable` for sessions that have nowhere left.
    Enum.each(bares, fn bare ->
      if sessions_for(bare) == [] and Exjabberd.SessionManager.get_sessions(bare, "global") == [] do
        broadcast_unavailable(bare)
      end
    end)

    {:noreply, Map.delete(state, peer)}
  end

  defp do_join(peer) do
    Logger.info("exjabberd joining cluster node #{peer}")

    :ets.insert(
      @table,
      {peer,
       %{status: :connected, joined: System.system_time(:second), mnesia: mnesia_running?()}}
    )

    case Node.connect(peer) do
      true ->
        _ = mnesia_join(peer)
        _ = wait_for_sync()
        Process.send_after(self(), {:sync_node, peer, 0}, @sync_delay)
        :ok

      false ->
        :ets.delete(@table, peer)
        {:error, :cannot_connect}

      :ignored ->
        # Distribution is not running on this node, so connecting is
        # impossible — report it as a connection failure, like `false`.
        :ets.delete(@table, peer)
        {:error, :cannot_connect}
    end
  end

  defp fan_out(msg) do
    Enum.each(Node.list(), fn peer ->
      send({__MODULE__, peer}, msg)
    end)

    :ok
  end

  defp configured_peers do
    if Process.whereis(Exjabberd.Config) do
      try do
        Exjabberd.Config.cluster_nodes()
      catch
        _, _ -> []
      end
    else
      []
    end
  rescue
    _ -> []
  catch
    _, _ -> []
  end

  defp cluster_enabled? do
    if Process.whereis(Exjabberd.Config) do
      try do
        Exjabberd.Config.cluster_enabled?()
      catch
        _, _ -> true
      end
    else
      true
    end
  rescue
    _ -> true
  catch
    _, _ -> true
  end

  defp apply_cookie_from_config do
    if Process.whereis(Exjabberd.Config) do
      try do
        case Exjabberd.Config.cluster_cookie() do
          cookie when is_binary(cookie) and cookie != "" ->
            :erlang.set_cookie(node(), String.to_atom(cookie))

          _ ->
            :ok
        end
      catch
        _, _ -> :ok
      end
    end
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  defp broadcast_unavailable(bare) do
    case Exjabberd.Xmpp.Jid.parse(bare) do
      {:ok, jid} ->
        stanza = %{name: :presence, type: "unavailable", from: jid, to: nil, id: nil, payload: []}
        Exjabberd.Router.route(stanza)

      _ ->
        :ok
    end
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  defp mnesia_running?, do: :mnesia.system_info(:is_running) == :yes

  defp ensure_tables do
    for {t, opts} <- [
          {@table,
           [:named_table, :public, :set, read_concurrency: true, write_concurrency: true]},
          {@route_table,
           [:named_table, :public, :set, read_concurrency: true, write_concurrency: true]},
          {@session_table,
           [:named_table, :public, :set, read_concurrency: true, write_concurrency: true]}
        ] do
      if :ets.whereis(t) == :undefined do
        :ets.new(t, opts)
      end
    end

    :ok
  end
end
