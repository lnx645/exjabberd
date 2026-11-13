defmodule Exjabberd.Auth.Mnesia do
  @moduledoc """
  Mnesia auth backend - `ejabberd_auth_mnesia` equivalent.

  Passwords are stored as SCRAM-SHA-256 verifier data only (salt,
  iteration count, StoredKey, ServerKey) in the Mnesia `:passwd` table
  with `disc_copies`, so accounts survive a server restart. The
  cleartext password is never stored. PLAIN logins are verified by
  recomputing the StoredKey from the presented password.

  An ETS table mirrors the same records as a read cache; the Mnesia
  table is the source of truth.
  """
  @behaviour Exjabberd.Auth.Behaviour
  use GenServer

  alias Exjabberd.Auth.Scram

  @table :exjabberd_passwd
  @mnesia_table :passwd

  def start_link(_), do: GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  @impl true
  def init(s) do
    ensure_ets()
    ensure_mnesia()
    {:ok, s}
  end

  defp ensure_ets do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [
        :named_table,
        :public,
        :set,
        read_concurrency: true,
        write_concurrency: true
      ])
    end
  end

  defp ensure_mnesia do
    Exjabberd.Mnesia.ensure_table(@mnesia_table, [:user, :scram])
  end

  @impl true
  def authenticate(_host, user, password) do
    ensure_ets()

    case get_scram(user) do
      {:ok, creds} -> Scram.verify_password(password, creds)
      :error -> false
    end
  end

  @impl true
  def user_exists(_host, user) do
    ensure_ets()
    exists_mnesia?(user) || exists_ets?(user)
  end

  @impl true
  def create_user(_host, user, password) do
    ensure_ets()
    ensure_mnesia()
    creds = Scram.derive_credentials(password)

    case :mnesia.transaction(fn -> :mnesia.write({@mnesia_table, user, creds}) end) do
      {:atomic, :ok} ->
        :ets.insert(@table, {user, creds})
        :ok

      {:aborted, reason} ->
        # A failed write must fail loudly: silently returning :ok is
        # how accounts used to vanish on restart.
        {:error, reason}
    end
  end

  @impl true
  def remove_user(_host, user) do
    ensure_ets()
    :ets.delete(@table, user)

    case :mnesia.transaction(fn -> :mnesia.delete({@mnesia_table, user}) end) do
      {:atomic, :ok} -> :ok
      {:aborted, reason} -> {:error, reason}
    end
  end

  @impl true
  def set_password(_host, user, password), do: create_user(nil, user, password)

  @doc "SCRAM verifier data for a user, or `:error`."
  @spec get_scram(binary()) :: {:ok, Scram.credentials()} | :error
  def get_scram(user) when is_binary(user) do
    ensure_ets()

    case lookup_mnesia(user) do
      {:ok, creds} -> {:ok, creds}
      :error -> lookup_ets(user)
    end
  end

  @doc "SCRAM verifier data for a user on a host (host is ignored: the Mnesia table is global)."
  @spec get_scram(binary(), binary()) :: {:ok, Scram.credentials()} | :error
  @impl true
  def get_scram(_host, user) when is_binary(user), do: get_scram(user)

  @doc "Store SCRAM verifier data verbatim (used by migration)."
  @spec store_scram_verifier(binary(), binary(), Scram.credentials()) ::
          :ok | {:error, term()}
  @impl true
  def store_scram_verifier(_host, user, creds) when is_binary(user) and is_map(creds) do
    ensure_ets()
    ensure_mnesia()

    if valid_creds?(creds) do
      case write_scram(user, creds) do
        :ok ->
          :ets.insert(@table, {user, creds})
          :ok

        {:error, reason} ->
          {:error, reason}
      end
    else
      {:error, :invalid_credentials}
    end
  end

  defp write_scram(user, creds) do
    case :mnesia.transaction(fn -> :mnesia.write({@mnesia_table, user, creds}) end) do
      {:atomic, :ok} -> :ok
      {:aborted, reason} -> {:error, reason}
    end
  end

  defp valid_creds?(%{salt: s, iterations: i, stored_key: sk, server_key: sv})
       when is_binary(s) and is_integer(i) and is_binary(sk) and is_binary(sv),
       do: true

  defp valid_creds?(_), do: false

  @doc "All users with stored credentials."
  @spec get_users(binary()) :: [binary()]
  @impl true
  def get_users(_host) do
    ensure_ets()

    case :mnesia.dirty_all_keys(@mnesia_table) do
      keys when is_list(keys) -> keys
      _ -> :ets.tab2list(@table) |> Enum.map(fn {user, _} -> user end)
    end
  rescue
    _ -> :ets.tab2list(@table) |> Enum.map(fn {user, _} -> user end)
  catch
    _, _ -> :ets.tab2list(@table) |> Enum.map(fn {user, _} -> user end)
  end

  defp lookup_mnesia(user) do
    case :mnesia.dirty_read(@mnesia_table, user) do
      [{@mnesia_table, ^user, creds}] when is_map(creds) -> {:ok, creds}
      _ -> :error
    end
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end

  defp lookup_ets(user) do
    case :ets.lookup(@table, user) do
      [{^user, creds}] when is_map(creds) -> {:ok, creds}
      _ -> :error
    end
  end

  defp exists_mnesia?(user) do
    case :mnesia.dirty_read(@mnesia_table, user) do
      [] -> false
      _ -> true
    end
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  defp exists_ets?(user) do
    case :ets.lookup(@table, user) do
      [] -> false
      _ -> true
    end
  end
end

# The real SQL backend (PostgreSQL, wire-verified) lives in
# lib/exjabberd/auth/sql.ex (`Exjabberd.Auth.Sql`, Fase 16).

defmodule Exjabberd.Auth.Ldap do
  @moduledoc "LDAP auth backend - `ejabberd_auth_ldap` equivalent."
  @behaviour Exjabberd.Auth.Behaviour
  @impl true
  def authenticate(_host, _user, _pass), do: false
  @impl true
  def user_exists(_host, _user), do: false
  @impl true
  def create_user(_host, _user, _pass), do: {:error, :not_supported}
  @impl true
  def remove_user(_host, _user), do: {:error, :not_supported}
  @impl true
  def set_password(_host, _user, _pass), do: {:error, :not_supported}
end

defmodule Exjabberd.Auth.Anonymous do
  @moduledoc "Anonymous auth - `ejabberd_auth_anonymous` (XEP-0078)."
  @behaviour Exjabberd.Auth.Behaviour
  @impl true
  def authenticate(_host, _user, _pass), do: true
  @impl true
  def user_exists(_host, _user), do: true
  @impl true
  def create_user(_host, _user, _pass), do: :ok
  @impl true
  def remove_user(_host, _user), do: :ok
  @impl true
  def set_password(_host, _user, _pass), do: :ok
end

defmodule Exjabberd.Auth.Pam do
  @moduledoc "PAM auth - `ejabberd_auth_pam` equivalent."
  @behaviour Exjabberd.Auth.Behaviour
  @impl true
  def authenticate(_host, _user, _pass), do: false
  @impl true
  def user_exists(_host, _user), do: false
  @impl true
  def create_user(_host, _user, _pass), do: {:error, :not_supported}
  @impl true
  def remove_user(_host, _user), do: {:error, :not_supported}
  @impl true
  def set_password(_host, _user, _pass), do: {:error, :not_supported}
end
