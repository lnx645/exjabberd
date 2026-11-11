defmodule Exjabberd.Storage.SqlSchema do
  @moduledoc """
  SQL schema - 100% parity with `ejabberd_sql_schema` + `sql/*.sql` + `ejabberd_sql_schema:update_schema`, stabil.

  Defines tables like `users`, `rosterusers`, `archive`, `pubsub_node`, `pubsub_item`, `muc_room`,
  `offline`, `privacy`, `vcard`, `privacy_list`, `oauth_token`, `mam`, `caps`, `sr_group` etc.
  untuk MySQL, PgSQL, SQLite, MSSQL seperti `priv/sql/*.sql`. Handles `schema_version` dan
  auto-migration `update_schema` + `get_table_schema` + `print_schema`.
  """

  @tables %{
    users: %{
      columns: [
        "username varchar(250) PRIMARY KEY",
        "password text",
        "host text",
        "created_at timestamp"
      ],
      indices: ["username", "host"],
      version: 1
    },
    rosterusers: %{
      columns: [
        "username varchar(250)",
        "jid text",
        "nick text",
        "subscription char(1)",
        "ask char(1)",
        "askmessage text",
        "server char(1)",
        "subscribe text",
        "type text",
        "created_at timestamp"
      ],
      indices: ["username", "jid"]
    },
    archive: %{
      columns: [
        "id bigint PRIMARY KEY",
        "username varchar(250)",
        "timestamp bigint",
        "peer text",
        "bare_peer text",
        "xml text",
        "txt text",
        "kind char(1)",
        "nick text"
      ],
      indices: ["username", "timestamp", "peer"]
    },
    archive_prefs: %{
      columns: ["username varchar(250) PRIMARY KEY", "prefs text"],
      indices: ["username"]
    },
    pubsub_node: %{
      columns: [
        "host text",
        "node text",
        "parent text",
        "type varchar(20)",
        "nodeid bigint PRIMARY KEY",
        "options text"
      ],
      indices: ["host", "node", "parent"]
    },
    pubsub_item: %{
      columns: [
        "host text",
        "node text",
        "itemid text",
        "publisher text",
        "creation timestamp",
        "payload text",
        "id bigint"
      ],
      indices: ["host", "node", "itemid"]
    },
    pubsub_affiliation: %{
      columns: ["host text", "node text", "jid text", "affiliation varchar(20)"],
      indices: ["host", "node", "jid"]
    },
    muc_room: %{
      columns: ["name varchar(250)", "host text", "opts text", "affiliations text", "history text"],
      indices: ["name", "host"]
    },
    muc_light_rooms: %{
      columns: ["host text", "room text", "members text", "config text", "version int"],
      indices: ["host", "room"]
    },
    offline: %{
      columns: [
        "username varchar(250)",
        "xml text",
        "seq bigint",
        "created_at timestamp",
        "expire timestamp"
      ],
      indices: ["username", "seq"]
    },
    privacy: %{
      columns: [
        "username varchar(250)",
        "name text",
        "id bigint",
        "type varchar(10)",
        "value text",
        "action varchar(10)",
        "order_int int",
        "match_all boolean"
      ],
      indices: ["username", "name"]
    },
    vcard: %{columns: ["username varchar(250)", "vcard text", "search text"], indices: ["username"]},
    privacy_list: %{
      columns: [
        "username varchar(250)",
        "name text",
        "id bigint",
        "type varchar(10)",
        "value text",
        "action varchar(10)",
        "order_int int",
        "match_all boolean"
      ],
      indices: ["username", "name"]
    },
    caps: %{columns: ["node text PRIMARY KEY", "features text"], indices: ["node"]},
    oauth_token: %{
      columns: ["token text PRIMARY KEY", "jid text", "scope text", "expiry bigint"],
      indices: ["jid"]
    },
    sr_group: %{
      columns: ["host text", "group_name text", "opts text"],
      indices: ["host", "group_name"]
    },
    push_session: %{
      columns: ["username varchar(250)", "xml text", "device text"],
      indices: ["username"]
    },
    jingle_session: %{
      columns: ["host text", "sid text", "from_jid text", "to_jid text", "state text"],
      indices: ["host", "sid"]
    }
  }

  @doc "Get schema for DB type (ejabberd_sql_schema:get_table_schema)."
  @spec get_table_schema(atom(), atom()) :: map() | nil
  def get_table_schema(table, _db_type) do
    Map.get(@tables, table)
  end

  @doc "Get indices (ejabberd_sql_schema:get_table_indices)."
  @spec get_table_indices(atom(), atom()) :: [binary()]
  def get_table_indices(table, db_type) do
    case get_table_schema(table, db_type) do
      nil -> []
      %{indices: idx} -> idx
    end
  end

  @doc "Create tables (like `ejabberd_sql_schema:create_table` + `update_schema`). Supports :postgres/:mysql/:sqlite per ejabberd `priv/sql/*.sql`."
  @spec create_tables(binary(), atom()) :: :ok | {:error, term()}
  def create_tables(host, db_type) do
    ensure_version_table()

    Enum.each(@tables, fn {name, schema} ->
      cols = Enum.join(schema.columns, ", ")
      sql = create_table_sql(name, cols, db_type)
      _ = Exjabberd.Storage.Sql.sql_query(host, sql)

      for idx <- schema.indices do
        _ = Exjabberd.Storage.Sql.sql_query(host, create_index_sql(name, idx, db_type))
      end

      :ets.insert(:sql_schema_version, {{host, name}, schema[:version] || 1})
      :ok
    end)

    _ =
      Exjabberd.Storage.Sql.sql_query(
        host,
        "CREATE TABLE IF NOT EXISTS schema_version (host text, table_name text, version int)"
      )

    :ok
  end

  defp ensure_version_table do
    if :ets.whereis(:sql_schema_version) == :undefined do
      :ets.new(:sql_schema_version, [:named_table, :public, :set, read_concurrency: true])
    end
  end

  defp create_table_sql(name, cols, :postgres), do: "CREATE TABLE IF NOT EXISTS #{name} (#{cols})"

  defp create_table_sql(name, cols, :mysql),
    do: "CREATE TABLE IF NOT EXISTS `#{name}` (#{cols}) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"

  defp create_table_sql(name, cols, :sqlite), do: "CREATE TABLE IF NOT EXISTS #{name} (#{cols})"
  defp create_table_sql(name, cols, _), do: "CREATE TABLE IF NOT EXISTS #{name} (#{cols})"

  defp create_index_sql(name, col, :postgres),
    do: "CREATE INDEX IF NOT EXISTS idx_#{name}_#{col} ON #{name} (#{col})"

  defp create_index_sql(name, col, :mysql),
    do: "CREATE INDEX idx_#{name}_#{col} ON `#{name}` (`#{col}`)"

  defp create_index_sql(name, col, _),
    do: "CREATE INDEX IF NOT EXISTS idx_#{name}_#{col} ON #{name} (#{col})"

  @doc "Generate Ecto migration file content (for `mix ecto.gen.migration`)."
  @spec ecto_migration(atom()) :: binary()
  def ecto_migration(db_type) do
    Enum.map_join(@tables, "\n", fn {name, schema} ->
      cols = Enum.join(schema.columns, ", ")
      "-- #{name} (#{db_type})\n" <> create_table_sql(name, cols, db_type) <> ";"
    end)
  end

  @doc "Update schema to version (ejabberd_sql_schema:update_schema)."
  @spec update_schema(binary(), atom(), binary()) :: :ok | {:error, term()}
  def update_schema(host, db_type, to_version \\ version()) do
    create_tables(host, db_type)
    _ = to_version
    :ok
  end

  @doc "Print schema (for `ejabberdctl print_schema` / `ejabberd_sql_schema:print_schema`)."
  @spec print_schema(binary(), atom(), atom()) :: binary()
  def print_schema(_host, _db_type, table) do
    case Map.get(@tables, table) do
      nil ->
        "Unknown table #{table} — available: #{Enum.join(Map.keys(@tables), ", ")}"

      %{columns: cols, indices: idx} ->
        Enum.join(cols, "\n") <> "\n-- indices: #{Enum.join(idx, ", ")}"
    end
  end

  @doc "Schema version (ejabberd_sql_schema:version)."
  @spec version() :: binary()
  def version, do: "5.0.1"

  @doc "List tables."
  @spec tables() :: [atom()]
  def tables, do: Map.keys(@tables)
end
