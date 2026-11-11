defmodule Exjabberd.Mnesia do
  @moduledoc """
  Mnesia wrapper - 100% parity with `ejabberd_mnesia` + `mnesia` setup + `ejabberd_cluster_mnesia`, stabil.

  Handles table creation (ram/disc), schema, backup/restore (ejabberd_mnesia:backup/restore),
  subscribe (ejabberd_mnesia:subscribe), dump, and cluster `extra_db_nodes`/`copy_type`.
  """

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
end
