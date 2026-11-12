defmodule Exjabberd.Mnesia do
  @moduledoc """
  Mnesia wrapper - partial implementation of `ejabberd_mnesia` + `mnesia` setup + `ejabberd_cluster_mnesia`, stabil.

  Handles table creation (ram/disc), schema, backup/restore (ejabberd_mnesia:backup/restore),
  subscribe (ejabberd_mnesia:subscribe), dump, and cluster `extra_db_nodes`/`copy_type`.
  """

  require Logger

  @doc "Create table (ejabberd_mnesia:create) dengan `ram_copies`/`disc_copies` + `type`."
  @spec create(atom(), keyword()) :: :ok | {:error, term()}
  def create(table, opts) do
    attrs = Keyword.get(opts, :attributes, [:key, :value])
    type = Keyword.get(opts, :type, :set)
    ram_copies = Keyword.get(opts, :ram_copies, [node()])
    disc_copies = Keyword.get(opts, :disc_copies, [])

    args =
      [attributes: attrs, type: type] ++
        if disc_copies != [], do: [disc_copies: disc_copies], else: [ram_copies: ram_copies]

    case :mnesia.create_table(table, args) do
      {:atomic, :ok} -> :ok
      {:aborted, {:already_exists, _}} -> :ok
      {:aborted, {:already_exists, _, _}} -> :ok
      other -> other
    end
  end

  @doc "Subscribe to table events (ejabberd_mnesia:subscribe)."
  @spec subscribe(atom()) :: :ok | {:error, term()}
  def subscribe(table) do
    case :mnesia.subscribe({:table, table, :simple}) do
      {:ok, _} -> :ok
      other -> other
    end
  end

  @doc "Backup (ejabberd_mnesia:backup) — `mnesia:backup`."
  @spec backup(binary()) :: :ok | {:error, term()}
  def backup(path) do
    case :mnesia.backup(String.to_charlist(path)) do
      :ok -> :ok
      other -> other
    end
  end

  @doc "Restore (ejabberd_mnesia:restore) — `mnesia:restore`."
  @spec restore(binary()) :: :ok | {:error, term()}
  def restore(path) do
    case :mnesia.restore(String.to_charlist(path), []) do
      {:atomic, _} -> :ok
      {:aborted, _} = err -> err
      other -> other
    end
  end

  @doc "Dump ETS table to file (ejabberd dump)."
  @spec dump(atom(), binary()) :: :ok
  def dump(table, path) do
    data = :ets.tab2list(table) |> :erlang.term_to_binary()
    File.write!(path, data)
    :ok
  rescue
    _ -> :ok
  end

  @doc "Load dump."
  @spec load(atom(), binary()) :: :ok | {:error, term()}
  def load(table, path) do
    case File.read(path) do
      {:ok, bin} ->
        list = :erlang.binary_to_term(bin)
        :ets.delete_all_objects(table)
        Enum.each(list, fn {k, v} -> :ets.insert(table, {k, v}) end)
        :ok

      err ->
        err
    end
  end

  @doc "Copy table to node (ejabberd_cluster_mnesia)."
  @spec copy_to_node(atom(), node(), atom()) :: :ok | {:error, term()}
  def copy_to_node(table, node, type \\ :ram_copies) do
    case :mnesia.add_table_copy(table, node, type) do
      {:atomic, :ok} -> :ok
      {:aborted, {:already_exists, _, _}} -> :ok
      other -> other
    end
  end

  @doc "Info (mnesia:info)."
  @spec info() :: map()
  def info do
    %{
      is_running: :mnesia.system_info(:is_running),
      tables: :mnesia.system_info(:tables),
      extra_db_nodes: :mnesia.system_info(:extra_db_nodes)
    }
  end

  @doc """
  Start Mnesia with a persistent on-disk schema (called once at
  application boot, before any module that uses it).

  Without this, Mnesia was never started and every account lived only
  in ETS, disappearing on restart. Tables are created with
  `disc_copies` under `mnesia_data/` in the working directory.
  """
  @spec setup() :: :ok
  def setup do
    # `disc_copies` tables (durable accounts) require a named node;
    # a plain `mix run` leaves the VM as `:nonode@nohost`, where
    # `create_table` fails with `{:bad_type, _, :disc_copies, _}`.
    # Start distribution as a short-named node when needed; if that
    # fails (no epmd), fall back to ram_copies and warn loudly —
    # accounts then live only until the next restart.
    if node() == :nonode@nohost do
      case :net_kernel.start([:exjabberd, :shortnames]) do
        {:ok, _} ->
          Logger.info("mnesia: distribution started as #{node()}")

        {:error, reason} ->
          Logger.warning(
            "mnesia: cannot start distribution (#{inspect(reason)}); accounts will not survive restart"
          )
      end
    end

    # Load (but do not start) the :mnesia application so its modules
    # are on the code path; setup/0 starts it below, after the schema
    # directory is configured.
    :ok = Application.ensure_loaded(:mnesia)

    # OTP auto-starts :mnesia (extra_applications) BEFORE this runs,
    # with the default directory and an in-memory schema. That must go:
    # with Mnesia already running, create_schema is a no-op and
    # disc_copies tables fail with {:bad_type, _, :disc_copies, _},
    # leaving accounts in ETS only (lost on restart). Stop it first,
    # then configure the directory and start it again properly.
    case :mnesia.system_info(:is_running) do
      :yes -> :stopped = :mnesia.stop()
      _ -> :ok
    end

    dir = mnesia_dir()
    File.mkdir_p!(dir)
    Application.put_env(:mnesia, :dir, String.to_charlist(dir))

    case :mnesia.create_schema([node()]) do
      :ok -> :ok
      {:error, {_, {:already_exists, _}}} -> :ok
      {:error, reason} -> Logger.warning("mnesia create_schema: #{inspect(reason)}")
    end

    :ok = :mnesia.start()
    ensure_table(:passwd, [:user, :scram])
    ensure_table(:offline_messages, [:key, :stanza])
    :ok
  end

  @doc """
  Tables replicated across the cluster (Fase 7). Attributes are the
  source of truth for `setup_cluster_join/1`; modules that own one
  of these tables must keep the same attributes in their own
  `ensure_table` calls.
  """
  @spec cluster_tables() :: [{atom(), [atom()]}]
  def cluster_tables do
    [
      passwd: [:user, :scram],
      offline_messages: [:key, :stanza],
      mam_archive: [:key, :record],
      pubsub_nodes: [:key, :value],
      pubsub_items: [:key, :value],
      pubsub_subs: [:key, :value],
      pubsub_affs: [:key, :value],
      roster: [:key, :item]
    ]
  end

  @doc """
  Start Mnesia JOINED to an existing cluster node (Fase 7).

  Called at boot when `EXJABBERD_CLUSTER_JOIN` (or `config
  :exjabberd, cluster_join:`) names a peer. Steps:

  1. Make sure distribution is running and the Erlang cookie is
     applied (env/app-env sources — the YAML file is not loaded yet
     at this point in the boot).
  2. `Node.connect/1` the peer with retries (up to ~20 s). If the
     peer cannot be reached, return `{:error, reason}` and the
     caller falls back to standalone `setup/0` — the node still
     boots, keeps its own schema, and retries the Erlang-level
     connection via the Cluster auto-connect loop.
  3. Only AFTER the peer answers: stop Mnesia, wipe this node's own
     schema directory (a fresh join has nothing worth keeping; a
     node that already shared this cluster's schema re-copies it
     from the peer), and start Mnesia with `extra_db_nodes` set so
     it copies the cluster schema from the peer.
  4. Add `disc_copies` of every shared table on this node, so the
     data is durable here too and survives a peer outage.

  Returns `:ok` or `{:error, reason}`.
  """
  @spec setup_cluster_join(node()) :: :ok | {:error, term()}
  def setup_cluster_join(peer) when is_atom(peer) do
    ensure_distribution()
    Exjabberd.Cluster.apply_cookie()

    case connect_with_retry(peer, 20_000) do
      :ok ->
        join_mnesia_schema(peer)

      {:error, reason} = err ->
        Logger.warning(
          "mnesia: cannot reach cluster peer #{peer} (#{inspect(reason)}); " <>
            "falling back to standalone schema — restart with EXJABBERD_CLUSTER_JOIN=#{peer} " <>
            "once #{peer} is up to share Mnesia tables"
        )

        err
    end
  end

  # Steps 3-4 of the join, split out so setup_cluster_join/1 stays
  # under Credo's complexity limit.
  defp join_mnesia_schema(peer) do
    :ok = Application.ensure_loaded(:mnesia)

    case :mnesia.system_info(:is_running) do
      :yes -> :stopped = :mnesia.stop()
      _ -> :ok
    end

    dir = mnesia_dir()
    File.rm_rf!(dir)
    File.mkdir_p!(dir)
    Application.put_env(:mnesia, :dir, String.to_charlist(dir))
    Application.put_env(:mnesia, :extra_db_nodes, [peer])

    :ok = :mnesia.start()

    case :mnesia.wait_for_tables([:schema], 10_000) do
      :ok ->
        :ok

      other ->
        Logger.warning("mnesia cluster join: wait_for_tables :schema: #{inspect(other)}")
    end

    # The schema itself must become a disc schema FIRST: Mnesia
    # refuses `disc_copies` table replicas on a node whose
    # schema is still `ram_copies` ("has no disc"). The schema
    # copied from the peer via extra_db_nodes starts as ram.
    case :mnesia.change_table_copy_type(:schema, node(), :disc_copies) do
      {:atomic, :ok} ->
        Logger.info("mnesia: local schema is now disc_copies")

      {:aborted, reason} ->
        Logger.warning("mnesia: cannot make schema disc_copies (#{inspect(reason)})")
    end

    for {table, attrs} <- cluster_tables(), table in :mnesia.system_info(:tables) do
      ensure_table(table, attrs)
    end

    Logger.info("mnesia: joined cluster via #{peer} (schema + shared tables copied)")
    :ok
  end

  defp ensure_distribution do
    if node() == :nonode@nohost do
      name =
        (System.get_env("EXJABBERD_NODE_NAME") || "exjabberd")
        |> String.to_atom()

      case :net_kernel.start([name, :shortnames]) do
        {:ok, _} ->
          Logger.info("mnesia: distribution started as #{node()}")

        {:error, reason} ->
          Logger.warning("mnesia: cannot start distribution (#{inspect(reason)})")
      end
    end

    :ok
  end

  defp connect_with_retry(peer, timeout_ms) do
    deadline = System.monotonic_time(:millisecond) + timeout_ms
    connect_loop(peer, deadline)
  end

  defp connect_loop(peer, deadline) do
    case Node.connect(peer) do
      true ->
        :ok

      _ ->
        if System.monotonic_time(:millisecond) < deadline do
          Process.sleep(1_000)
          connect_loop(peer, deadline)
        else
          {:error, :cannot_connect}
        end
    end
  end

  @spec mnesia_dir() :: binary()
  def mnesia_dir do
    Application.get_env(:exjabberd, :mnesia_dir) ||
      Path.join(File.cwd!(), "mnesia_data")
  end

  @doc """
  Ensure a persistent (`disc_copies`) table exists with the given
  attributes. A pre-existing `:passwd` table in the old plaintext
  format (`[:user, :password]`) is migrated to SCRAM verifier data so
  accounts created by the old code keep working.
  """
  @spec ensure_table(atom(), [atom()]) :: :ok
  def ensure_table(table, attributes) do
    case :mnesia.create_table(table, attributes: attributes, disc_copies: [node()]) do
      {:atomic, :ok} ->
        :ok

      {:aborted, {:already_exists, _}} ->
        ensure_copy_type(table, attributes)

      {:aborted, {:already_exists, _, _}} ->
        ensure_copy_type(table, attributes)

      {:aborted, reason} ->
        Logger.warning("mnesia create_table #{table}: #{inspect(reason)}")
        :ok
    end
  end

  defp ensure_copy_type(table, attributes) do
    current = :mnesia.table_info(table, :attributes)

    if current == attributes do
      disc = :mnesia.table_info(table, :disc_copies)
      ram = :mnesia.table_info(table, :ram_copies)

      cond do
        node() in disc ->
          :ok

        node() in ram ->
          change_to_disc_copies(table)

        true ->
          # The table exists cluster-wide but this node holds no
          # copy yet (fresh cluster join): add a local disc_copies
          # replica. `change_table_copy_type` cannot do this — it
          # only retypes an EXISTING copy (and fails with
          # `{:badarg, table, :unknown}` when there is none).
          case :mnesia.add_table_copy(table, node(), :disc_copies) do
            {:atomic, :ok} ->
              :ok

            {:aborted, {:already_exists, _, _}} ->
              :ok

            {:aborted, reason} ->
              Logger.warning("mnesia add_table_copy #{table}: #{inspect(reason)}")
          end
      end
    else
      migrate_table(table, current, attributes)
    end
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  defp change_to_disc_copies(table) do
    case :mnesia.change_table_copy_type(table, node(), :disc_copies) do
      {:atomic, :ok} -> :ok
      {:aborted, reason} -> Logger.warning("mnesia disc_copies #{table}: #{inspect(reason)}")
    end
  end

  # Old :passwd stored {:passwd, user, cleartext_password}; derive SCRAM
  # verifier data from it and rewrite the table in the new format.
  defp migrate_table(:passwd, [:user, :password], [:user, :scram]) do
    rows = :mnesia.dirty_match_object({:passwd, :_, :_})

    :mnesia.delete_table(:passwd)
    ensure_table(:passwd, [:user, :scram])

    Enum.each(rows, fn {:passwd, user, password} ->
      creds = Exjabberd.Auth.Scram.derive_credentials(password)
      :mnesia.dirty_write({:passwd, user, creds})
    end)

    Logger.info("mnesia migrated :passwd (#{length(rows)} users) to SCRAM storage")
    :ok
  end

  defp migrate_table(table, _current, _attributes) do
    Logger.warning("mnesia table #{table} has unexpected attributes, left as-is")
    :ok
  end
end
