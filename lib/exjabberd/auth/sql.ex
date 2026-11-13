defmodule Exjabberd.Auth.Sql do
  @moduledoc """
  SQL auth backend — `ejabberd_auth_sql` equivalent (Fase 16).

  PostgreSQL is implemented and verified over the wire: accounts
  live in a `passwd` table reached through `Exjabberd.PgWire`, a
  native wire-protocol client (SCRAM-SHA-256 connection auth
  included), with every statement parameterized. MySQL is NOT
  implemented — no MySQL server exists in the development sandbox,
  so there is no honest way to wire-verify it; selecting
  `server: mysql` logs an error and every login fails closed
  rather than pretending to work.

  The table stores exactly the same SCRAM-SHA-256 verifier data as
  the Mnesia and SQLite backends (salt, iteration count, StoredKey,
  ServerKey — one row per `(host, user)`), so an account moves
  between backends with `Exjabberd.Auth.Migrate` without a password
  reset, and PLAIN / SCRAM-SHA-256 logins verify identically.

  Connection settings come from configuration only: the `auth_sql:`
  section of `exjabberd.yml` (`Exjabberd.Config.auth_sql/0`), with
  `EXJABBERD_AUTH_SQL_SERVER` / `_HOST` / `_PORT` / `_DATABASE` /
  `_USERNAME` / `_PASSWORD` environment variables winning over the
  file. No credential is hardcoded here.

  All access is serialized through this GenServer (one connection),
  so concurrent C2S logins cannot interleave protocol frames; a
  failed query drops the connection and the next call reconnects.
  """
  @behaviour Exjabberd.Auth.Behaviour
  use GenServer

  require Logger

  alias Exjabberd.Auth.Scram
  alias Exjabberd.PgWire

  @call_timeout 15_000

  @create_table """
  CREATE TABLE IF NOT EXISTS passwd (
    host TEXT NOT NULL,
    "user" TEXT NOT NULL,
    salt BYTEA NOT NULL,
    iterations INTEGER NOT NULL,
    stored_key BYTEA NOT NULL,
    server_key BYTEA NOT NULL,
    PRIMARY KEY (host, "user")
  )
  """

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    {:ok, %{conn: nil}}
  end

  @impl true
  def terminate(_reason, %{conn: conn}) when conn != nil do
    _ = PgWire.close(conn)
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

  @doc """
  Connection settings in force (config file, env overrides win).
  Mirrors `Exjabberd.Auth.Sqlite.configured_path/0`'s fallback so
  the migration task and tests work before the config server is up.
  """
  @spec configured() :: map()
  def configured do
    if Process.whereis(Exjabberd.Config) != nil do
      Exjabberd.Config.auth_sql()
    else
      secret_value = System.get_env("EXJABBERD_AUTH_SQL_PASSWORD", "")

      %{
        server: System.get_env("EXJABBERD_AUTH_SQL_SERVER", "postgres"),
        host: System.get_env("EXJABBERD_AUTH_SQL_HOST", "127.0.0.1"),
        port: env_port(),
        database: System.get_env("EXJABBERD_AUTH_SQL_DATABASE", "exjabberd"),
        username: System.get_env("EXJABBERD_AUTH_SQL_USERNAME", "exjabberd")
      }
      |> Map.put(:password, secret_value)
    end
  end

  defp env_port do
    case System.get_env("EXJABBERD_AUTH_SQL_PORT") do
      nil -> 5432
      "" -> 5432
      v -> String.to_integer(v)
    end
  end

  @doc """
  Drop the open connection, if any. The next call reconnects lazily
  (and re-resolves the settings). Like the SQLite backend's
  `close/0`, this avoids supervisor restart-intensity trips when
  tests or the migration task switch targets.
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
    if conn != nil, do: PgWire.close(conn)
    {:reply, :ok, %{state | conn: nil}}
  end

  def handle_call({:user_exists, host, user}, _from, state) do
    {state, reply} =
      with_conn(state, fn conn ->
        case PgWire.query(conn, ~s|SELECT 1 FROM passwd WHERE host = $1 AND "user" = $2|, [host, user]) do
          {:ok, [_row]} -> {:ok, true}
          {:ok, []} -> {:ok, false}
          {:error, reason} -> {:error, reason}
        end
      end)

    {:reply, reply, state}
  end

  def handle_call({:remove_user, host, user}, _from, state) do
    {state, reply} =
      with_conn(state, fn conn ->
        case PgWire.query(conn, ~s|DELETE FROM passwd WHERE host = $1 AND "user" = $2|, [host, user]) do
          {:ok, _} -> :ok
          {:error, reason} -> {:error, reason}
        end
      end)

    {:reply, reply, state}
  end

  def handle_call({:get_scram, host, user}, _from, state) do
    {state, reply} =
      with_conn(state, fn conn ->
        case PgWire.query(
               conn,
               ~s|SELECT salt, iterations, stored_key, server_key FROM passwd WHERE host = $1 AND "user" = $2|,
               [host, user]
             ) do
          {:ok, [[salt, iterations, stored_key, server_key]]} ->
            {:ok,
             %{
               salt: salt,
               iterations: iterations,
               stored_key: stored_key,
               server_key: server_key
             }}

          {:ok, []} ->
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
        case PgWire.query(
               conn,
               """
               INSERT INTO passwd (host, "user", salt, iterations, stored_key, server_key)
               VALUES ($1, $2, $3, $4, $5, $6)
               ON CONFLICT (host, "user") DO UPDATE SET
                 salt = EXCLUDED.salt, iterations = EXCLUDED.iterations,
                 stored_key = EXCLUDED.stored_key, server_key = EXCLUDED.server_key
               """,
               [
                 host,
                 user,
                 {:bytea, creds[:salt]},
                 creds[:iterations],
                 {:bytea, creds[:stored_key]},
                 {:bytea, creds[:server_key]}
               ]
             ) do
          {:ok, _} -> :ok
          {:error, reason} -> {:error, reason}
        end
      end)

    {:reply, reply, state}
  end

  def handle_call({:get_users, host}, _from, state) do
    {state, reply} =
      with_conn(state, fn conn ->
        case PgWire.query(conn, ~s|SELECT "user" FROM passwd WHERE host = $1 ORDER BY "user"|, [host]) do
          {:ok, rows} -> {:ok, Enum.map(rows, fn [user] -> user end)}
          {:error, reason} -> {:error, reason}
        end
      end)

    {:reply, reply, state}
  end

  # Open the connection lazily (the config file loads after the
  # supervision tree starts) and keep it in state. A failed query
  # poisons the protocol stream, so on any error the connection is
  # dropped and the next call reconnects from scratch.
  defp with_conn(%{conn: nil} = state, fun) do
    case open_conn() do
      {:ok, conn} ->
        run_and_maybe_drop(%{state | conn: conn}, conn, fun)

      {:error, reason} ->
        {state, {:error, reason}}
    end
  end

  defp with_conn(%{conn: conn} = state, fun) do
    run_and_maybe_drop(state, conn, fun)
  end

  defp run_and_maybe_drop(state, conn, fun) do
    reply = run_guarded(fun, conn)

    case reply do
      {:error, _} ->
        _ = PgWire.close(conn)
        {%{state | conn: nil}, reply}

      _ ->
        {state, reply}
    end
  end

  defp run_guarded(fun, conn) do
    fun.(conn)
  rescue
    e -> {:error, e}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp open_conn do
    cfg = configured()

    if cfg.server not in ["postgres", "postgresql"] do
      Logger.error(
        "auth sql: server #{inspect(cfg.server)} is not implemented " <>
          "(only PostgreSQL is wire-verified); logins will fail"
      )

      {:error, :unsupported_server}
    else
      connect_opts =
        [
          host: cfg.host,
          port: cfg.port,
          username: cfg.username,
          database: cfg.database
        ]
        |> Keyword.put(:password, cfg.password)

      with {:ok, conn} <- PgWire.connect(connect_opts),
           {:ok, _} <- PgWire.query(conn, @create_table, []) do
        {:ok, conn}
      else
        {:error, reason} ->
          Logger.error("auth sql: cannot connect: #{inspect(reason)}")
          {:error, reason}
      end
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
        {:error, reason} -> Logger.warning("auth sql: start failed: #{inspect(reason)}")
      end
    else
      :ok
    end
  end
end
