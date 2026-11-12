defmodule Exjabberd.ClusterTest do
  @moduledoc """
  ExUnit tests for Fase 7 clustering — only the logic that can be
  tested without a second node: config parsing, the session/route
  mirrors, purge, liveness of local pids, and the join-failure path.
  The real two-node proof (message + presence across nodes, node
  down/up, shared Mnesia) lives in `test_cluster_phase7.py`.
  """
  use ExUnit.Case, async: false

  alias Exjabberd.Cluster
  alias Exjabberd.SessionManager

  setup do
    # The app boots in the test env (test_helper starts it via the
    # application); make sure the mirrors exist and are clean.
    :ok = Cluster.register_session("probe@localhost", "clean", self(), 0, "localhost")
    :ok = Cluster.unregister_session("probe@localhost", "clean")
    :ok
  end

  # `load_map/1` replaces the whole Config state, so config tests
  # save it first and restore it afterwards — other test files read
  # the same global config (listen ports, modules).
  defp with_config(map, fun) do
    saved = Exjabberd.Config.state()
    :ok = Exjabberd.Config.load_map(map)

    try do
      fun.()
    after
      :sys.replace_state(Exjabberd.Config, fn _old -> saved end)
    end
  end

  test "config: cluster section parses nodes + cookie + enabled" do
    with_config(
      %{
        "hosts" => ["localhost"],
        "cluster" => %{
          "enabled" => true,
          "nodes" => ["exjabberd-b@somehost", "exjabberd-c@somehost"],
          "cookie" => "test-cookie-123"
        }
      },
      fn ->
        assert Exjabberd.Config.cluster_enabled?()

        assert Exjabberd.Config.cluster_nodes() == [
                 :"exjabberd-b@somehost",
                 :"exjabberd-c@somehost"
               ]

        assert Exjabberd.Config.cluster_cookie() == "test-cookie-123"
      end
    )
  end

  test "config: cluster defaults are enabled with no peers" do
    with_config(%{"hosts" => ["localhost"]}, fn ->
      assert Exjabberd.Config.cluster_enabled?()
      assert Exjabberd.Config.cluster_nodes() == []
      assert Exjabberd.Config.cluster_cookie() == nil
    end)
  end

  test "single node: nodes() is just this node, not clustered" do
    assert Cluster.nodes() == [node()]
    refute Cluster.clustered?()
  end

  test "status() reports this node and no peers" do
    status = Cluster.status()
    assert status.node == node()
    assert status.nodes == [node()]
    assert status.clustered == false
    assert is_boolean(status.cookie_configured)
    assert is_map(status.mnesia)
  end

  test "session mirror: register/unregister round-trips via SessionManager" do
    :ok =
      SessionManager.register("mirroruser@localhost", "res1", self(),
        priority: 5,
        host: "localhost"
      )

    assert [{_, pid, _, _, _, _}] =
             Cluster.sessions_for("mirroruser@localhost")
             |> Enum.filter(fn {r, _, _, _, _, _} -> r == "res1" end)

    assert pid == self()
    assert {"res1", self(), 5} in SessionManager.get_sessions("mirroruser@localhost", "localhost")
    assert {:ok, self()} == SessionManager.get_session("mirroruser@localhost", "res1")
    assert "res1" in SessionManager.get_resources("mirroruser@localhost")

    :ok = SessionManager.unregister("mirroruser@localhost", "res1")
    assert SessionManager.get_sessions("mirroruser@localhost", "localhost") == []
    assert Cluster.sessions_for("mirroruser@localhost") == []
  end

  test "session mirror: unregister only removes the entry when the pid matches" do
    other =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    :ok = Cluster.register_session("guard@localhost", "r1", other, 0, "localhost")
    :ok = Cluster.register_session("guard@localhost", "r1", self(), 0, "localhost")

    # The mirror now points at self(); removing `other` must not delete it.
    :ok = Cluster.unregister_session("guard@localhost", "r1", other)
    assert [{_, pid, _, _, _, _}] = Cluster.sessions_for("guard@localhost")
    assert pid == self()

    # Removing with the matching pid deletes it.
    :ok = Cluster.unregister_session("guard@localhost", "r1", self())
    assert Cluster.sessions_for("guard@localhost") == []
    send(other, :stop)
  end

  test "route mirror: register/lookup/unregister round-trips" do
    :ok = Cluster.register_route("routed@localhost/res", self())
    assert {:ok, pid, n} = Cluster.lookup_route("routed@localhost/res")
    assert pid == self()
    assert n == node()

    :ok = Cluster.unregister_route("routed@localhost/res", self())
    assert Cluster.lookup_route("routed@localhost/res") == :error
  end

  test "route mirror: unregister with a non-matching pid keeps the entry" do
    other =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    :ok = Cluster.register_route("keepme@localhost", self())
    :ok = Cluster.unregister_route("keepme@localhost", other)
    assert {:ok, pid, _} = Cluster.lookup_route("keepme@localhost")
    assert pid == self()
    :ok = Cluster.unregister_route("keepme@localhost", self())
    send(other, :stop)
  end

  test "purge_node removes only that node's entries and returns its bare JIDs" do
    fake_node = :ghost@nowhere
    # Inject entries as if they came from another node (via state merge).
    :ok =
      Cluster.apply_state(%{
        sessions: [{"ghostuser@localhost", "r", self(), fake_node, 0, "localhost", 0}],
        routes: [{"ghostuser@localhost/r", self(), fake_node}]
      })

    :ok = Cluster.register_session("localuser@localhost", "r", self(), 0, "localhost")

    assert ["ghostuser@localhost"] == Cluster.purge_node(fake_node) |> Enum.sort()
    assert Cluster.sessions_for("ghostuser@localhost") == []
    assert Cluster.lookup_route("ghostuser@localhost/r") == :error
    # Local entries survive the purge.
    assert [_] = Cluster.sessions_for("localuser@localhost")
    :ok = Cluster.unregister_session("localuser@localhost", "r")
  end

  test "apply_state/export_state round-trips sessions and routes" do
    :ok = Cluster.register_session("export@localhost", "r1", self(), 3, "localhost")
    :ok = Cluster.register_route("export@localhost/r1", self())
    state = Cluster.export_state()
    assert %{node: _, sessions: _, routes: _} = state
    assert Enum.any?(state.sessions, fn {b, _, _, _, _, _, _} -> b == "export@localhost" end)
    assert Enum.any?(state.routes, fn {jid, _, _} -> jid == "export@localhost/r1" end)
    :ok = Cluster.apply_state(state)
    assert [_] = Cluster.sessions_for("export@localhost")
    :ok = Cluster.unregister_session("export@localhost", "r1")
    :ok = Cluster.unregister_route("export@localhost/r1")
  end

  test "alive?/1: true for a live local pid, false for a dead one" do
    assert Cluster.alive?(self())
    dead = spawn(fn -> :ok end)
    # Let it exit.
    :timer.sleep(50)
    refute Process.alive?(dead)
    refute Cluster.alive?(dead)
  end

  test "join of an unreachable node returns an error, never a hang" do
    assert {:error, :cannot_connect} = Cluster.join(:"no-such-node@nowhere.invalid")
  end

  test "mnesia_join of a node outside the schema returns an error tuple" do
    # A node that shares no schema cannot be joined live; the call
    # must fail fast with a tuple, not raise or hang.
    assert match?({:error, _}, Cluster.mnesia_join(:"no-such-node@nowhere.invalid"))
  end

  test "hash_node/local? stay consistent on a single node" do
    assert Cluster.hash_node("andi@localhost") == node()
    assert Cluster.local?("andi@localhost")
  end

  test "shared_tables covers accounts, roster, offline, MAM and PubSub" do
    tables = Cluster.shared_tables()
    assert :passwd in tables
    assert :roster in tables
    assert :offline_messages in tables
    assert :mam_archive in tables
    assert :pubsub_nodes in tables
    assert :pubsub_items in tables
  end

  test "roster items are stored in Mnesia as well as ETS" do
    :ok =
      Exjabberd.Mod.Roster.add_item("localhost", "rosterprobe", "friend@localhost", [],
        subscription: :both
      )

    assert [%{jid: "friend@localhost"}] =
             Exjabberd.Mod.Roster.get_roster("localhost", "rosterprobe")

    assert [{:roster, {"rosterprobe@localhost", "friend@localhost"}, %{jid: "friend@localhost"}}] =
             :mnesia.dirty_read(:roster, {"rosterprobe@localhost", "friend@localhost"})

    :ok = Exjabberd.Mod.Roster.remove_item("localhost", "rosterprobe", "friend@localhost")
    assert [] = Exjabberd.Mod.Roster.get_roster("localhost", "rosterprobe")
  end
end
