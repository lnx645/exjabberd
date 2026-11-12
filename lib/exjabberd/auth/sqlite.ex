defmodule Exjabberd.Auth.Sqlite do
  @moduledoc """
  SQLite auth backend — `ejabberd_auth_sql` equivalent for SQLite
  (Fase 8, the first real non-Mnesia backend).

  Stores exactly the same SCRAM-SHA-256 verifier data as the Mnesia
  backend (salt, iteration count, StoredKey, ServerKey) — one row per
  `(host, user)` in a `passwd` table — so an account can move between
  backends with `Exjabberd.Auth.Migrate` without resetting its
  password, and a PLAIN or SCRAM-SHA-256 login verifies identically
  whichever backend is active.

  The database file comes from configuration only, never from a
  hardcoded path: `auth_sqlite.path` in `exjabberd.yml`
  (`Exjabberd.Config.auth_sqlite_path/0`), or the
  `EXJABBERD_AUTH_SQLITE_PATH` environment variable, which wins over
  the file. Default: `priv/auth.sqlite3` (relative to the working
  directory). No credentials are involved — the file holds verifier
  data only, never cleartext passwords.

  All access is serialized through this GenServer (one `Exqlite`
  connection, `busy_timeout` 5000, WAL journal mode), so concurrent
  C2S logins cannot hit `SQLITE_BUSY`.
  """
  @behaviour Exjabberd.Auth.Behaviour
  use GenServer

  require Logger

  alias Exjabberd.Auth.Scram
  alias Exqlite.Sqlite3

  @default_path "priv/auth.sqlite3"
  @busy_timeout_ms 5_000
  @call_timeout 15_000

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    {:ok, %{conn: nil, path: Keyword.get(opts, :path)}}
  end

  @impl true
  def terminate(_reason, %{conn: conn}) when conn != nil do
    _ = Sqlite3.close(conn)
    :ok
  end

  def terminate(_reason, _state), do: :ok

  @impl true
  def authenticate(host, user, password) do
    case get_scram(host, user) do
      {:ok, creds} -> Scram.verify_password(password, creds)
      :error -> false
    end
  end

  @impl true
  def user_exists(host, user) do
    case call({:user_exists, host, user}) do
      {:ok, exists?} -> exists?
      {:error, _} -> false
    end
  end

  @impl true
  def create_user(host, user, password) do
    store_scram_verifier(host, user, Scram.derive_credentials(password))
  end

  @impl true
  def remove_user(host, user) do
    case call({:remove_user, host, user}) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def set_password(host, user, password), do: create_user(host, user, password)

  @doc "SCRAM verifier data for a user, or `:error`."
  @spec get_scram(binary(), binary()) :: {:ok, Scram.credentials()} | :error
  @impl true
  def get_scram(host, user) do
    case call({:get_scram, host, user}) do
      {:ok, creds} -> {:ok, creds}
      :error -> :error
      {:error, _} -> :error
    end
  end

  @doc "Store SCRAM verifier data verbatim (used by migration)."
  @spec store_scram_verifier(binary(), binary(), Scram.credentials()) ::
          :ok | {:error, term()}
  @impl true
  def store_scram_verifier(host, user, creds)
      when is_binary(host) and is_binary(user) and is_map(creds) do
    case call({:store_scram, host, user, creds}) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "All users with stored credentials for a host."
  @spec get_users(binary()) :: [binary()]
  @impl true
  def get_users(host) do
    case call({:get_users, host}) do
      {:ok, users} -> users
      {:error, _} -> []
    end
  end

  @doc "Configured database path (config file, env override wins)."
  @spec configured_path() :: binary()
  def configured_path do
    case System.get_env("EXJABBERD_AUTH_SQLITE_PATH") do
      path when is_binary(path) and path != "" ->
        path

      _ ->
        if Process.whereis(Exjabberd.Config) != nil do
          Exjabberd.Config.get(:global, :auth_sqlite_path, @default_path)
        else
          Application.get_env(:exjabberd, :auth_sqlite_path, @default_path)
        end
    end
  end

  @doc """
  Close the open database connection, if any. The next call reopens
  it lazily (and re-resolves the path from configuration). This is
  NOT a server restart — stopping the supervised server repeatedly
  would trip the supervisor's restart intensity and take the whole
  application down, so tests and the migration task use this.
  """
  @spec close() :: :ok
  def close do
    if Process.whereis(__MODULE__) != nil do
      GenServer.call(__MODULE__, :close, @call_timeout)
    else
      :ok
    end
  end

  # --- GenServer internals -------------------------------------------------

  @impl true
  def handle_call(:close, _from, %{conn: conn} = state) do
    if conn != nil, do: Sqlite3.close(conn)
    {:reply, :ok, %{state | conn: nil, path: nil}}
  end

  def handle_call({:user_exists, host, user}, _from, state) do
    {state, reply} =
      with_conn(state, fn conn ->
        case query_one(
               conn,
               "SELECT 1 FROM passwd WHERE host = ? AND user = ?",
               [host, user]
             ) do
          {:ok, _} -> {:ok, true}
          :error -> {:ok, false}
          {:error, reason} -> {:error, reason}
        end
      end)

    {:reply, reply, state}
  end

  def handle_call({:remove_user, host, user}, _from, state) do
    {state, reply} =
      with_conn(state, fn conn ->
        exec(conn, "DELETE FROM passwd WHERE host = ? AND user = ?", [host, user])
      end)

    {:reply, reply, state}
  end

  def handle_call({:get_scram, host, user}, _from, state) do
    {state, reply} =
      with_conn(state, fn conn ->
        case query_one(
               conn,
               "SELECT salt, iterations, stored_key, server_key FROM passwd WHERE host = ? AND user = ?",
               [host, user]
             ) do
          {:ok, [salt, iterations, stored_key, server_key]} ->
            {:ok,
             %{
               salt: salt,
               iterations: iterations,
               stored_key: stored_key,
               server_key: server_key
             }}

          :error ->
            :error

          {:error, reason} ->
            {:error, reason}
        end
      end)

    {:reply, reply, state}
  end

  def handle_call({:store_scram, host, user, creds}, _from, state) do
    {state, reply} =
      with_conn(state, fn conn ->
        # SCRAM fields are raw bytes, not text: bind them as blobs
        # (`{:blob, value}`), otherwise Exqlite binds a binary as
        # TEXT and SQLite counts/stores it as UTF-8 text.
        exec(
          conn,
          "INSERT OR REPLACE INTO passwd (host, user, salt, iterations, stored_key, server_key) VALUES (?, ?, ?, ?, ?, ?)",
          [
            host,
            user,
            {:blob, creds[:salt]},
            creds[:iterations],
            {:blob, creds[:stored_key]},
            {:blob, creds[:server_key]}
          ]
        )
      end)

    {:reply, reply, state}
  end

  def handle_call({:get_users, host}, _from, state) do
    {state, reply} =
      with_conn(state, fn conn ->
        case query_all(conn, "SELECT user FROM passwd WHERE host = ? ORDER BY user", [host]) do
          {:ok, rows} -> {:ok, Enum.map(rows, fn [user] -> user end)}
          {:error, reason} -> {:error, reason}
        end
      end)

    {:reply, reply, state}
  end

  # Open the connection lazily (the config file loads after the
  # supervision tree starts, so the path is not known at init) and
  # keep it in state; a failed open is logged and retried on the
  # next call instead of crashing the server.
  defp with_conn(%{conn: nil, path: path_opt} = state, fun) do
    path = path_opt || configured_path()

    case open_db(path) do
      {:ok, conn} ->
        {%{state | conn: conn, path: path}, run_guarded(fun, conn)}

      {:error, reason} ->
        Logger.error("auth sqlite: cannot open #{path}: #{inspect(reason)}")
        {state, {:error, reason}}
    end
  end

  defp with_conn(%{conn: conn} = state, fun) do
    {state, run_guarded(fun, conn)}
  end

  defp run_guarded(fun, conn) do
    fun.(conn)
  rescue
    e -> {:error, e}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp open_db(path) do
    dir = Path.dirname(path)
    if dir not in [".", ""], do: File.mkdir_p!(dir)

    with {:ok, conn} <- Sqlite3.open(path),
         :ok <- Sqlite3.execute(conn, "PRAGMA journal_mode=WAL"),
         :ok <- Sqlite3.execute(conn, "PRAGMA busy_timeout=#{@busy_timeout_ms}"),
         :ok <-
           Sqlite3.execute(
             conn,
             "CREATE TABLE IF NOT EXISTS passwd (" <>
               "host TEXT NOT NULL, user TEXT NOT NULL, " <>
               "salt BLOB NOT NULL, iterations INTEGER NOT NULL, " <>
               "stored_key BLOB NOT NULL, server_key BLOB NOT NULL, " <>
               "PRIMARY KEY (host, user))"
           ) do
      {:ok, conn}
    else
      {:error, reason} -> {:error, reason}
      error -> {:error, error}
    end
  rescue
    e -> {:error, e}
  end

  defp query_one(conn, sql, params) do
    case Sqlite3.prepare(conn, sql) do
      {:ok, stmt} ->
        try do
          :ok = Sqlite3.bind(stmt, params)

          case Sqlite3.step(conn, stmt) do
            {:row, row} -> {:ok, row}
            :done -> :error
            {:error, reason} -> {:error, reason}
          end
        after
          Sqlite3.release(conn, stmt)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp query_all(conn, sql, params) do
    case Sqlite3.prepare(conn, sql) do
      {:ok, stmt} ->
        try do
          :ok = Sqlite3.bind(stmt, params)
          {:ok, collect_rows(conn, stmt, [])}
        after
          Sqlite3.release(conn, stmt)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp collect_rows(conn, stmt, acc) do
    case Sqlite3.step(conn, stmt) do
      {:row, row} -> collect_rows(conn, stmt, [row | acc])
      :done -> Enum.reverse(acc)
    end
  end

  defp exec(conn, sql, params) do
    case Sqlite3.prepare(conn, sql) do
      {:ok, stmt} ->
        try do
          :ok = Sqlite3.bind(stmt, params)

          case Sqlite3.step(conn, stmt) do
            :done -> :ok
            {:row, _} -> :ok
            {:error, reason} -> {:error, reason}
          end
        after
          Sqlite3.release(conn, stmt)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # The server is a supervised child in production; start it
  # unlinked on demand when a caller finds it missing (tests, or a
  # mix task that boots only part of the stack).
  defp call(msg) do
    ensure_started()
    GenServer.call(__MODULE__, msg, @call_timeout)
  end

  defp ensure_started do
    if Process.whereis(__MODULE__) == nil do
      case GenServer.start(__MODULE__, [], name: __MODULE__) do
        {:ok, _} -> :ok
        {:error, {:already_started, _}} -> :ok
        {:error, reason} -> Logger.warning("auth sqlite: start failed: #{inspect(reason)}")
      end
    else
      :ok
    end
  end
end
