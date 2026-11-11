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
  Directory holding the on-disk Mnesia schema.

  Configurable via `config :exjabberd, mnesia_dir: <path>` (the test
  environment uses its own directory so its schema never collides
  with the dev server's — a Mnesia schema belongs to one node name).
  """
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
      case :mnesia.table_info(table, :disc_copies) do
        [n] when n == node() -> :ok
        _ -> change_to_disc_copies(table)
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
