defmodule Exjabberd.Auth do
  @moduledoc """
  Authentication facade - partial implementation of `ejabberd_auth` + `ejabberd_auth:check_password`, stabil.

  Dispatches to configured backend per-host. Supports all ejabberd backends:
  * `:mnesia` - internal (default, `ejabberd_auth_mnesia`)
  * `:sql` - MySQL, PgSQL, SQLite (`ejabberd_auth_sql`)
  * `:ldap` - LDAP (`ejabberd_auth_ldap`)
  * `:anonymous` - XEP-0078 (`ejabberd_auth_anonymous`)
  * `:jwt` - JWT Bearer (`ejabberd_auth_jwt`)
  * `:external` - external script (`ejabberd_auth_external` + `extauth`)
  * `:oauth` - OAuth2 (`ejabberd_oauth`)
  * `:pam` - PAM (`ejabberd_auth_pam`)
  Also handles `check_password` with `plain`/`scram` like ejabberd.
  """

  @type host :: binary()
  @type user :: binary()
  @type password :: binary()

  @doc "Authenticate user (ejabberd_auth:check_password with plain)."
  @spec authenticate(host(), user(), password()) :: boolean()
  def authenticate(host, user, password) do
    backend = backend_for(host)
    backend.authenticate(host, user, password)
  end

  @doc "Check password with method (ejabberd_auth:check_password)."
  @spec check_password(host(), user(), password(), binary()) :: boolean()
  def check_password(host, user, password, method \\ "plain") do
    backend = backend_for(host)

    case method do
      "plain" -> backend.authenticate(host, user, password)
      "scram" -> verify_scram_password(host, user, password)
      _ -> backend.authenticate(host, user, password)
    end
  end

  @doc "Verify a password against the stored SCRAM verifier data."
  @spec verify_scram_password(host(), user(), password()) :: boolean()
  def verify_scram_password(host, user, password) do
    case get_scram(host, user) do
      {:ok, creds} -> Exjabberd.Auth.Scram.verify_password(password, creds)
      :error -> false
    end
  end

  @doc "SCRAM verifier data for a user, or `:error` when unknown."
  @spec get_scram(host(), user()) ::
          {:ok, Exjabberd.Auth.Scram.credentials()} | :error
  def get_scram(host, user) do
    backend = backend_for(host)

    cond do
      function_exported?(backend, :get_scram, 2) -> backend.get_scram(host, user)
      function_exported?(backend, :get_scram, 1) -> backend.get_scram(user)
      true -> :error
    end
  end

  @doc "Check if user exists (ejabberd_auth:is_user_exists)."
  @spec user_exists(host(), user()) :: boolean()
  def user_exists(host, user) do
    backend = backend_for(host)
    backend.user_exists(host, user)
  end

  @doc "Create user (ejabberd_auth:try_register)."
  @spec create_user(host(), user(), password()) :: :ok | {:error, term()}
  def create_user(host, user, password) do
    backend = backend_for(host)

    case backend.create_user(host, user, password) do
      :ok ->
        :telemetry.execute([:exjabberd, :auth, :register], %{count: 1}, %{host: host})
        :ok

      err ->
        err
    end
  end

  @doc "Remove user (ejabberd_auth:remove_user)."
  @spec remove_user(host(), user()) :: :ok | {:error, term()}
  def remove_user(host, user) do
    backend = backend_for(host)
    backend.remove_user(host, user)
  end

  @doc "Set password (ejabberd_auth:set_password)."
  @spec set_password(host(), user(), password()) :: :ok | {:error, term()}
  def set_password(host, user, password) do
    backend = backend_for(host)
    backend.set_password(host, user, password)
  end

  @doc "Get all users for host (ejabberd_auth:get_users)."
  @spec get_users(host()) :: [binary()]
  def get_users(host) do
    backend = backend_for(host)
    if function_exported?(backend, :get_users, 1), do: backend.get_users(host), else: []
  end

  defp backend_for(host) do
    case Exjabberd.Config.get(host, :auth_method, :mnesia) do
      :mnesia -> Exjabberd.Auth.Mnesia
      :sql -> Exjabberd.Auth.Sql
      :ldap -> Exjabberd.Auth.Ldap
      :anonymous -> Exjabberd.Auth.Anonymous
      :jwt -> Exjabberd.Auth.Jwt
      :external -> Exjabberd.Auth.External
      :oauth -> Exjabberd.Auth.Oauth
      :pam -> Exjabberd.Auth.Pam
      other when is_binary(other) -> backend_for(String.to_atom(other))
      _ -> Exjabberd.Auth.Mnesia
    end
  end
end

defmodule Exjabberd.Auth.Behaviour do
  @moduledoc "Behaviour every auth backend must implement (ejabberd_auth behaviour)."

  @callback authenticate(binary(), binary(), binary()) :: boolean()
  @callback user_exists(binary(), binary()) :: boolean()
  @callback create_user(binary(), binary(), binary()) :: :ok | {:error, term()}
  @callback remove_user(binary(), binary()) :: :ok | {:error, term()}
  @callback set_password(binary(), binary(), binary()) :: :ok | {:error, term()}
end
