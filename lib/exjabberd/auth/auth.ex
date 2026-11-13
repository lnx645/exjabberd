defmodule Exjabberd.Auth do
  @moduledoc """
  Authentication facade - partial implementation of `ejabberd_auth` + `ejabberd_auth:check_password`, stabil.

  Dispatches to configured backend per-host. Supports all ejabberd backends:
  * `:mnesia` - internal (default, `ejabberd_auth_mnesia`)
  * `:sqlite` - SQLite file (Fase 8, real backend, `ejabberd_auth_sql` for SQLite)
  * `:sql` - PostgreSQL (`ejabberd_auth_sql`) — real backend (Fase 16); MySQL not implemented
  * `:ldap` - LDAP (`ejabberd_auth_ldap`) — stub, not implemented
  * `:anonymous` - XEP-0078 (`ejabberd_auth_anonymous`)
  * `:jwt` - JWT Bearer (`ejabberd_auth_jwt`) — real backend (Fase 16)
  * `:external` - external script (`ejabberd_auth_external` + `extauth`) — real backend (Fase 16)
  * `:oauth` - OAuth2 introspection (`ejabberd_oauth`) — real backend (Fase 16)
  * `:pam` - PAM (`ejabberd_auth_pam`) — stub, not implemented
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

  @doc "Store SCRAM verifier data verbatim (used by migration)."
  @spec store_scram_verifier(host(), user(), Exjabberd.Auth.Scram.credentials()) ::
          :ok | {:error, term()}
  def store_scram_verifier(host, user, creds) do
    backend = backend_for(host)

    if function_exported?(backend, :store_scram_verifier, 3) do
      backend.store_scram_verifier(host, user, creds)
    else
      {:error, :not_supported}
    end
  end

  @doc "Get all users for host (ejabberd_auth:get_users)."
  @spec get_users(host()) :: [binary()]
  def get_users(host) do
    backend = backend_for(host)
    if function_exported?(backend, :get_users, 1), do: backend.get_users(host), else: []
  end

  @backends %{
    mnesia: Exjabberd.Auth.Mnesia,
    sqlite: Exjabberd.Auth.Sqlite,
    sql: Exjabberd.Auth.Sql,
    ldap: Exjabberd.Auth.Ldap,
    anonymous: Exjabberd.Auth.Anonymous,
    jwt: Exjabberd.Auth.Jwt,
    external: Exjabberd.Auth.External,
    oauth: Exjabberd.Auth.Oauth,
    pam: Exjabberd.Auth.Pam
  }

  defp backend_for(host) do
    case Exjabberd.Config.get(host, :auth_method, :mnesia) do
      method when is_atom(method) ->
        Map.get(@backends, method, Exjabberd.Auth.Mnesia)

      method when is_binary(method) ->
        Map.get(@backends, String.to_atom(method), Exjabberd.Auth.Mnesia)

      _ ->
        Exjabberd.Auth.Mnesia
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
  # Optional: backends that store SCRAM verifiers (Mnesia, SQLite)
  # expose them so the SCRAM exchange and migration can read/write
  # verifier data verbatim. Backends that cannot (LDAP, external,
  # anonymous) simply do not implement them.
  @callback get_scram(binary(), binary()) ::
              {:ok, Exjabberd.Auth.Scram.credentials()} | :error
  @callback get_users(binary()) :: [binary()]
  @callback store_scram_verifier(binary(), binary(), Exjabberd.Auth.Scram.credentials()) ::
              :ok | {:error, term()}
  @optional_callbacks get_scram: 2, get_users: 1, store_scram_verifier: 3
end
