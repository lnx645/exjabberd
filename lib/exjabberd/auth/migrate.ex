defmodule Exjabberd.Auth.Migrate do
  @moduledoc """
  Move accounts between auth backends (Fase 8) — `ejabberd_auth` has
  no such tool; ejabberd operators export/import SQL dumps by hand.

  Copies every user of a host from the source backend to the target
  backend by copying the SCRAM verifier data verbatim (salt,
  iteration count, StoredKey, ServerKey), so passwords keep working
  on the new backend with no reset. Only backends that store SCRAM
  verifiers can be a source (`:mnesia`, `:sqlite`); anything else
  returns `{:error, :source_has_no_verifiers}` honestly instead of
  copying half an account.

  Typical use — move Mnesia accounts to SQLite, then switch the
  server over (`auth_method: sqlite` in `exjabberd.yml`):

      mix exjabberd.auth.migrate --from mnesia --to sqlite

  The command is idempotent (re-running it overwrites the same
  verifier data) and never deletes from the source, so the old
  backend stays usable as a rollback until the operator removes it.
  """

  require Logger

  @type backend :: :mnesia | :sqlite
  @type summary :: %{
          copied: non_neg_integer(),
          skipped: [binary()],
          failed: [{binary(), term()}]
        }

  @doc """
  Copy all users of `host` from `from` to `to`.

  Options: `:host` (default `"localhost"`), `:dry_run` (count only,
  write nothing). Returns `{:ok, summary}`.
  """
  @spec run(keyword()) :: {:ok, summary()} | {:error, term()}
  def run(opts \\ []) do
    from = Keyword.get(opts, :from, :mnesia)
    to = Keyword.get(opts, :to, :sqlite)
    host = Keyword.get(opts, :host, "localhost")
    dry_run? = Keyword.get(opts, :dry_run, false)

    with {:ok, source} <- backend_module(from),
         {:ok, target} <- backend_module(to),
         :ok <- check_verifiers(source, from) do
      users = source_users(source, host)

      summary =
        Enum.reduce(users, %{copied: 0, skipped: [], failed: []}, fn user, acc ->
          copy_user(source, target, host, user, acc, dry_run?)
        end)

      summary = %{
        summary
        | skipped: Enum.reverse(summary.skipped),
          failed: Enum.reverse(summary.failed)
      }

      Logger.info(
        "auth migrate #{from} -> #{to} host=#{host}: #{summary.copied} copied, #{length(summary.skipped)} skipped, #{length(summary.failed)} failed"
      )

      {:ok, summary}
    end
  end

  defp copy_user(source, target, host, user, acc, dry_run?) do
    case source_scram(source, host, user) do
      {:ok, creds} -> store_user(target, host, user, creds, acc, dry_run?)
      :error -> %{acc | skipped: [user | acc.skipped]}
    end
  end

  defp store_user(_target, _host, _user, _creds, acc, true),
    do: %{acc | copied: acc.copied + 1}

  defp store_user(target, host, user, creds, acc, false) do
    case target_store(target, host, user, creds) do
      :ok -> %{acc | copied: acc.copied + 1}
      {:error, reason} -> %{acc | failed: [{user, reason} | acc.failed]}
    end
  end

  @doc "Backend module for an `auth_method` name, or an error for unknown/stub ones."
  @spec backend_module(atom() | binary()) :: {:ok, module()} | {:error, term()}
  def backend_module(:mnesia), do: {:ok, Exjabberd.Auth.Mnesia}
  def backend_module("mnesia"), do: {:ok, Exjabberd.Auth.Mnesia}
  def backend_module(:sqlite), do: {:ok, Exjabberd.Auth.Sqlite}
  def backend_module("sqlite"), do: {:ok, Exjabberd.Auth.Sqlite}
  def backend_module(other), do: {:error, {:unsupported_backend, other}}

  defp check_verifiers(source, name) do
    if function_exported?(source, :get_scram, 2) or function_exported?(source, :get_scram, 1) do
      :ok
    else
      {:error, {:source_has_no_verifiers, name}}
    end
  end

  defp source_users(source, host) do
    if function_exported?(source, :get_users, 1), do: source.get_users(host), else: []
  end

  defp source_scram(source, host, user) do
    cond do
      function_exported?(source, :get_scram, 2) -> source.get_scram(host, user)
      function_exported?(source, :get_scram, 1) -> source.get_scram(user)
      true -> :error
    end
  end

  defp target_store(target, host, user, creds) do
    if function_exported?(target, :store_scram_verifier, 3) do
      target.store_scram_verifier(host, user, creds)
    else
      {:error, :target_cannot_store_verifiers}
    end
  end
end
