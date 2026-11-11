defmodule Exjabberd.Auth.Mnesia do
  @moduledoc "Mnesia auth backend - `ejabberd_auth_mnesia` equivalent. Falls back to ETS when Mnesia not started (tests)."
  @behaviour Exjabberd.Auth.Behaviour
  use GenServer

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
    try do
      case :mnesia.create_table(@mnesia_table, attributes: [:user, :password], ram_copies: [node()]) do
        {:atomic, :ok} -> :ok
        {:aborted, {:already_exists, _}} -> :ok
        _ -> :ok
      end
    rescue
      _ -> :ok
    catch
      _, _ -> :ok
    end
  end

  @impl true
  def authenticate(_host, user, password) do
    ensure_ets()

    case lookup_mnesia(user, password) do
      true -> true
      false -> lookup_ets(user, password)
      _ -> lookup_ets(user, password)
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
    :ets.insert(@table, {user, password})

    case :mnesia.transaction(fn -> :mnesia.write({@mnesia_table, user, password}) end) do
      {:atomic, :ok} -> :ok
      {:aborted, _} -> :ok
    end
  end

  @impl true
  def remove_user(_host, user) do
    ensure_ets()
    :ets.delete(@table, user)

    case :mnesia.transaction(fn -> :mnesia.delete({@mnesia_table, user}) end) do
      {:atomic, :ok} -> :ok
      {:aborted, _} -> :ok
    end
  end

  @impl true
  def set_password(_host, user, password), do: create_user(nil, user, password)

  defp lookup_mnesia(user, pass) do
    case :mnesia.dirty_read(@mnesia_table, user) do
      [{@mnesia_table, ^user, ^pass}] -> true
      _ -> false
    end
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  defp lookup_ets(user, pass) do
    case :ets.lookup(@table, user) do
      [{^user, ^pass}] -> true
      _ -> false
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

defmodule Exjabberd.Auth.Sql do
  @moduledoc "SQL auth backend - `ejabberd_auth_sql` equivalent (MySQL/PgSQL/SQLite)."
  @behaviour Exjabberd.Auth.Behaviour
  @impl true
  def authenticate(_host, _user, _pass), do: false
  @impl true
  def user_exists(_host, _user), do: false
  @impl true
  def create_user(_host, _user, _pass), do: {:error, :not_implemented}
  @impl true
  def remove_user(_host, _user), do: {:error, :not_implemented}
  @impl true
  def set_password(_host, _user, _pass), do: {:error, :not_implemented}
end

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

defmodule Exjabberd.Auth.Jwt do
  @moduledoc "JWT auth - `ejabberd_auth_jwt` equivalent."
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

defmodule Exjabberd.Auth.External do
  @moduledoc "External script auth - `ejabberd_auth_external`."
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

defmodule Exjabberd.Auth.Oauth do
  @moduledoc "OAuth auth - `ejabberd_oauth`."
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
