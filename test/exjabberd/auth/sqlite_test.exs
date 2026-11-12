defmodule Exjabberd.Auth.SqliteTest do
  @moduledoc """
  ExUnit tests for Fase 8 — the SQLite auth backend and migration.

  The application boots in the test env, so the supervised
  `Exjabberd.Auth.Sqlite` server already runs; these tests point it
  at a throwaway file through `Config` (its connection opens lazily
  on first use) and restore the default path afterwards. The live
  end-to-end proof (real XMPP clients, server restart) lives in
  `test_auth_sqlite_phase8.py`.
  """
  use ExUnit.Case, async: false

  alias Exjabberd.Auth.Migrate
  alias Exjabberd.Auth.Mnesia
  alias Exjabberd.Auth.Scram
  alias Exjabberd.Auth.Sqlite

  @host "localhost"

  setup do
    dir =
      Path.join(System.tmp_dir!(), "exjabberd-sqlite-test-#{System.unique_integer([:positive])}")

    File.mkdir_p!(dir)
    path = Path.join(dir, "auth.sqlite3")

    saved_method = Exjabberd.Config.get(@host, :auth_method, :mnesia)
    saved_path = Exjabberd.Config.get(:global, :auth_sqlite_path, "priv/auth.sqlite3")
    :ok = Exjabberd.Config.set(:global, :auth_sqlite_path, path)
    :ok = Exjabberd.Config.set(@host, :auth_method, :sqlite)

    on_exit(fn ->
      # Release the connection (no server restart — repeated
      # restarts would trip the supervisor's restart intensity)
      # before the files are removed; the supervisor keeps the
      # server itself alive.
      Sqlite.close()
      :ok = Exjabberd.Config.set(:global, :auth_sqlite_path, saved_path)
      :ok = Exjabberd.Config.set(@host, :auth_method, saved_method)
      File.rm_rf!(dir)
    end)

    {:ok, path: path}
  end

  defp uniq(prefix), do: "#{prefix}-#{System.unique_integer([:positive])}"

  defp wait_for_server do
    Enum.find_value(1..50, fn _ ->
      case Process.whereis(Sqlite) do
        nil ->
          Process.sleep(100)
          nil

        pid ->
          pid
      end
    end) || flunk("sqlite auth server did not restart")
  end

  test "config: auth_method + auth_sqlite.path parse from a map" do
    saved = Exjabberd.Config.state()

    try do
      :ok =
        Exjabberd.Config.load_map(%{
          "hosts" => ["localhost"],
          "auth_method" => "sqlite",
          "auth_sqlite" => %{"path" => "/tmp/from-yml.sqlite3"}
        })

      assert Exjabberd.Config.auth_method("localhost") == :sqlite
      assert Exjabberd.Config.auth_sqlite_path() == "/tmp/from-yml.sqlite3"
    after
      :sys.replace_state(Exjabberd.Config, fn _old -> saved end)
    end
  end

  test "config: unknown auth_method falls back to mnesia" do
    saved = Exjabberd.Config.state()

    try do
      :ok = Exjabberd.Config.load_map(%{"hosts" => ["localhost"], "auth_method" => "bogus"})
      assert Exjabberd.Config.auth_method("localhost") == :mnesia
    after
      :sys.replace_state(Exjabberd.Config, fn _old -> saved end)
    end
  end

  test "sqlite backend: create, exists, PLAIN auth, wrong password fails" do
    user = uniq("sqlite-user")
    refute Sqlite.user_exists(@host, user)
    assert :ok = Sqlite.create_user(@host, user, "secret")
    assert Sqlite.user_exists(@host, user)
    assert Sqlite.authenticate(@host, user, "secret")
    refute Sqlite.authenticate(@host, user, "wrong")
    refute Sqlite.authenticate(@host, "nobody-here", "secret")
  end

  test "sqlite backend: SCRAM verifier round-trips and set_password rotates" do
    user = uniq("sqlite-scram")
    assert :ok = Sqlite.create_user(@host, user, "secret")
    assert {:ok, creds} = Sqlite.get_scram(@host, user)
    assert Scram.verify_password("secret", creds)
    refute Scram.verify_password("wrong", creds)

    assert :ok = Sqlite.set_password(@host, user, "newsecret")
    assert Sqlite.authenticate(@host, user, "newsecret")
    refute Sqlite.authenticate(@host, user, "secret")
  end

  test "sqlite backend: get_users lists users, remove_user deletes" do
    user = uniq("sqlite-list")
    assert :ok = Sqlite.create_user(@host, user, "secret")
    assert user in Sqlite.get_users(@host)
    assert :ok = Sqlite.remove_user(@host, user)
    refute Sqlite.user_exists(@host, user)
    refute user in Sqlite.get_users(@host)
    refute Sqlite.authenticate(@host, user, "secret")
  end

  test "sqlite backend: accounts survive a server restart" do
    user = uniq("sqlite-persist")
    assert :ok = Sqlite.create_user(@host, user, "secret")
    assert Sqlite.authenticate(@host, user, "secret")

    pid = Process.whereis(Sqlite)
    assert pid != nil
    :ok = GenServer.stop(pid)
    wait_for_server()

    assert Sqlite.user_exists(@host, user)
    assert Sqlite.authenticate(@host, user, "secret")
  end

  test "verifier format: a Mnesia-derived verifier works verbatim in SQLite" do
    user = uniq("sqlite-compat")
    creds = Scram.derive_credentials("secret")
    assert :ok = Sqlite.store_scram_verifier(@host, user, creds)
    assert Sqlite.authenticate(@host, user, "secret")
    assert {:ok, ^creds} = Sqlite.get_scram(@host, user)
  end

  test "facade routes to SQLite when auth_method is sqlite" do
    user = uniq("sqlite-facade")
    assert :ok = Exjabberd.Auth.create_user(@host, user, "secret")
    assert Exjabberd.Auth.user_exists(@host, user)
    assert Exjabberd.Auth.authenticate(@host, user, "secret")
    assert Exjabberd.Auth.check_password(@host, user, "secret", "scram")
    refute Exjabberd.Auth.check_password(@host, user, "wrong", "scram")
    assert user in Exjabberd.Auth.get_users(@host)
    assert :ok = Exjabberd.Auth.remove_user(@host, user)
    refute Exjabberd.Auth.user_exists(@host, user)
  end

  test "migrate: mnesia -> sqlite keeps the password working" do
    user = uniq("mig-user")
    assert :ok = Mnesia.create_user(@host, user, "secret")
    assert Mnesia.authenticate(@host, user, "secret")

    assert {:ok, %{copied: copied, skipped: [], failed: []}} =
             Migrate.run(from: :mnesia, to: :sqlite, host: @host)

    # Other test files may have left users in Mnesia too; what
    # matters is that THIS user was copied with a working password.
    assert copied >= 1

    assert Sqlite.authenticate(@host, user, "secret")
    # Source is untouched: the old backend still logs the user in.
    assert Mnesia.authenticate(@host, user, "secret")

    assert :ok = Mnesia.remove_user(@host, user)
    assert :ok = Sqlite.remove_user(@host, user)
  end

  test "migrate: dry run copies nothing, unsupported source errors" do
    user = uniq("mig-dry")
    assert :ok = Mnesia.create_user(@host, user, "secret")

    assert {:ok, %{copied: copied}} =
             Migrate.run(from: :mnesia, to: :sqlite, host: @host, dry_run: true)

    assert copied >= 1
    # Dry run must not have written anything to SQLite.
    refute Sqlite.user_exists(@host, user)

    assert {:error, {:unsupported_backend, :ldap}} =
             Migrate.run(from: :ldap, to: :sqlite, host: @host)

    assert {:error, {:unsupported_backend, :bogus}} =
             Migrate.run(from: :bogus, to: :sqlite, host: @host)

    assert :ok = Mnesia.remove_user(@host, user)
  end
end
