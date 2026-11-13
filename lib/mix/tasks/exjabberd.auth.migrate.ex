defmodule Mix.Tasks.Exjabberd.Auth.Migrate do
  @moduledoc """
  Copy accounts between auth backends without resetting passwords.

      mix exjabberd.auth.migrate --from mnesia --to sqlite [--host localhost] [--path priv/auth.sqlite3] [--dry-run]

  Boots only the pieces migration needs (Mnesia schema, Config,
  the two auth backends) — not the listeners — so it is safe to run
  while the server is stopped. The source is never modified, so the
  old backend stays usable as a rollback; switch the server over
  afterwards with `auth_method:` in `exjabberd.yml`.
  """
  use Mix.Task

  alias Exjabberd.Auth.Migrate
  alias Exjabberd.Auth.Mnesia, as: AuthMnesia
  alias Exjabberd.Auth.Sql, as: AuthSql
  alias Exjabberd.Auth.Sqlite, as: AuthSqlite
  alias Exjabberd.Config
  alias Exjabberd.Mnesia

  @shortdoc "Migrate auth accounts between backends (e.g. mnesia -> sqlite)"

  @impl Mix.Task
  def run(args) do
    {opts, _, _} =
      OptionParser.parse(args,
        strict: [from: :string, to: :string, host: :string, path: :string, dry_run: :boolean]
      )

    from = Keyword.get(opts, :from, "mnesia")
    to = Keyword.get(opts, :to, "sqlite")
    host = Keyword.get(opts, :host, "localhost")
    dry_run? = Keyword.get(opts, :dry_run, false)

    # Minimal boot: no listeners, no modules — just storage + config
    # + the two auth backends.
    :ok = Mnesia.setup()
    {:ok, _} = Config.start_link([])
    load_config_file()
    {:ok, _} = AuthMnesia.start_link([])

    sqlite_opts =
      case Keyword.get(opts, :path) do
        nil -> []
        path -> [path: path]
      end

    {:ok, _} = AuthSqlite.start_link(sqlite_opts)
    {:ok, _} = AuthSql.start_link([])

    case Migrate.run(from: from, to: to, host: host, dry_run: dry_run?) do
      {:ok, %{copied: copied, skipped: skipped, failed: failed}} ->
        Mix.shell().info(
          "migrated #{copied} user(s) #{from} -> #{to} (host #{host})" <>
            if(dry_run?, do: " [dry run]", else: "")
        )

        unless skipped == [] do
          Mix.shell().info("skipped (no verifier data): #{Enum.join(skipped, ", ")}")
        end

        unless failed == [] do
          Mix.shell().error("failed: #{inspect(failed)}")
          exit({:shutdown, 1})
        end

      {:error, reason} ->
        Mix.shell().error("migration failed: #{inspect(reason)}")
        exit({:shutdown, 1})
    end
  end

  defp load_config_file do
    config_file =
      ["config/exjabberd.yml", "exjabberd.yml", "nxmpps.yml"]
      |> Enum.map(&Path.join(File.cwd!(), &1))
      |> Enum.find(&File.exists?/1)

    if config_file do
      case Config.load_file(config_file) do
        :ok ->
          Mix.shell().info("config loaded from #{config_file}")

        {:error, reason} ->
          Mix.shell().info("config load failed (#{inspect(reason)}), using defaults")
      end
    end
  end
end
