defmodule Exjabberd.Application do
  @moduledoc """
  OTP Application for exjabberd.

  Supervision strategy mirrors ejabberd's fault-tolerant design but with
  Elixir idioms. Every core subsystem is isolated so a crash in one MUC
  room never brings down c2s connections.

  Boot order:
  1. `Exjabberd.Mnesia.setup/0` — schema + `:passwd` / `:offline_messages`
     disc_copies tables, so accounts survive a restart.
  2. `Exjabberd.Config.load_file/1` — `config/exjabberd.yml` when it
     exists (hosts, listen ports, `modules:`), falling back to built-in
     defaults.
  3. Core GenServers (Config, Hooks, Router, SessionManager, Cluster,
     S2S, Iq, ListenerSupervisor, Mod.Supervisor, Auth.Mnesia).
  4. Listeners from the config's `listen:` list — C2S (plain and
     direct-TLS) plus the S2S inbound listener (port 5269). With no
     `listen:` entries at all, a plain C2S listener on 5222 is started
     so the test environment (no config file) still boots.
  5. `Exjabberd.Mod.Supervisor.start_all/1` for every configured host —
     modules are plain Elixir modules started with `mod.start(host, opts)`
     directly, not as supervisor children (their `start/2` returns
     `:ok`, not `{:ok, pid}`).
  """
  use Application
  require Logger

  @impl true
  def start(_type, _args) do
    :ok = Exjabberd.Mnesia.setup()

    children = [
      {Exjabberd.Config, []},
      {Exjabberd.Hooks, []},
      {Exjabberd.Router, []},
      {Exjabberd.SessionManager, []},
      {Exjabberd.Cluster, []},
      {Exjabberd.S2S, %{}},
      {Exjabberd.Iq, []},
      {Exjabberd.ListenerSupervisor, []},
      {Exjabberd.Mod.Supervisor, []},
      {Exjabberd.Mod.Muc.Supervisor, []},
      {Exjabberd.Auth.Mnesia, []}
    ]

    opts = [strategy: :one_for_one, name: Exjabberd.Supervisor]
    {:ok, sup} = Supervisor.start_link(children, opts)

    # Config file needs the Config GenServer, so it loads after the
    # supervisor is up (hosts, listen ports, `modules:`). ejabberd
    # searches /etc/ejabberd/ejabberd.yml, ./ejabberd.yml and
    # ./nxmpps.yml; this server looks in the same places, in order:
    # `config/exjabberd.yml` first (the documented location), then
    # `exjabberd.yml` in the working directory, then `nxmpps.yml`.
    # (Before this fix only `config/exjabberd.yml` was tried, but the
    # file actually lives at the repo root — so `modules:` was never
    # loaded and every boot silently fell back to `default_modules/0`.)
    config_file =
      ["config/exjabberd.yml", "exjabberd.yml", "nxmpps.yml"]
      |> Enum.map(&Path.join(File.cwd!(), &1))
      |> Enum.find(&File.exists?/1)

    if config_file do
      case Exjabberd.Config.load_file(config_file) do
        :ok ->
          Logger.info("exjabberd config loaded from #{config_file}")

        {:error, reason} ->
          Logger.warning("config load failed (#{inspect(reason)}), using defaults")
      end
    end

    # Dialback needs a secret: use the configured one, or generate a
    # random ephemeral secret for this boot (a restart then
    # invalidates only in-flight dialback exchanges, which the peer
    # retries — see Exjabberd.S2S.Dialback).
    ensure_dialback_secret()

    # TURN needs a shared secret too (same pattern: configured, or a
    # random ephemeral one for this boot).
    ensure_turn_secret()

    # Listeners from the config's `listen:` list (C2S plain/TLS and
    # S2S inbound). No `listen:` entries → plain C2S on 5222.
    start_listeners()

    # STUN/TURN on its own UDP (+TCP) port, from the `turn:` section.
    start_stun_turn()

    # Start the configured modules for every host.
    for host <- Exjabberd.Config.hosts() do
      Exjabberd.Mod.Supervisor.start_all(host)
    end

    {:ok, sup}
  end

  defp ensure_dialback_secret do
    case Exjabberd.Config.dialback_secret() do
      secret when is_binary(secret) and secret != "" ->
        :ok

      _ ->
        generated = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)
        :ok = Exjabberd.Config.set(:global, :s2s_dialback_secret, generated)

        Logger.warning(
          "s2s_dialback_secret is not configured; generated an ephemeral secret for this boot " <>
            "(set s2s_dialback_secret in exjabberd.yml for a stable one)"
        )

        :ok
    end
  end

  defp ensure_turn_secret do
    case Exjabberd.Config.turn_secret() do
      secret when is_binary(secret) and secret != "" ->
        :ok

      _ ->
        generated = :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)
        :ok = Exjabberd.Config.set(:global, :turn_shared_secret, generated)

        Logger.warning(
          "turn.shared_secret is not configured; generated an ephemeral secret for this boot " <>
            "(set turn.shared_secret in exjabberd.yml for a stable one — TURN credentials issued before a restart stop working otherwise)"
        )

        :ok
    end
  end

  defp start_stun_turn do
    turn = Exjabberd.Config.turn()

    if turn["enabled"] == false or turn[:enabled] == false do
      Logger.info("STUN/TURN disabled by configuration (turn.enabled: false)")
      :ok
    else
      start_listener(
        {Exjabberd.StunTurn.Server, [name: Exjabberd.StunTurn.Server]},
        "STUN/TURN on #{turn["port"] || turn[:port] || 5478} (UDP + TCP)"
      )
    end
  end

  defp start_listeners do
    host = List.first(Exjabberd.Config.hosts()) || "localhost"

    entries =
      case Exjabberd.Config.listen() do
        [] -> [%{"port" => 5222, "module" => "exjabberd_c2s"}]
        list -> list
      end

    Enum.each(entries, fn entry ->
      port = Map.get(entry, "port")
      module = Map.get(entry, "module")

      cond do
        not is_integer(port) ->
          Logger.warning("listen entry without a port, skipped: #{inspect(entry)}")

        module == "exjabberd_c2s" ->
          tls = Map.get(entry, "tls") == true
          name = if tls, do: Exjabberd.Listener.C2S.TLS, else: Exjabberd.Listener.C2S

          start_listener(
            {Exjabberd.Listener.C2S, [port: port, tls: tls, host: host, name: name]},
            "C2S on #{port}#{if tls, do: " (direct TLS)", else: ""}"
          )

        module == "exjabberd_s2s_in" ->
          start_listener(
            {Exjabberd.Listener.S2S, [port: port, host: host]},
            "S2S on #{port}"
          )

        module == "exjabberd_http" ->
          start_listener(
            {Exjabberd.Http.Server, [port: port, host: host, name: Exjabberd.Http.Server]},
            "HTTP on #{port} (admin/BOSH/WS/upload/API)"
          )

        true ->
          Logger.warning("listen entry with unknown module #{inspect(module)}, skipped")
      end
    end)
  end

  defp start_listener(child, label) do
    case DynamicSupervisor.start_child(Exjabberd.ListenerSupervisor, child) do
      {:ok, _} -> Logger.info("exjabberd listener started: #{label}")
      {:error, reason} -> Logger.warning("listener #{label} failed: #{inspect(reason)}")
    end
  end
end

defmodule Exjabberd.ListenerSupervisor do
  @moduledoc "Dynamic supervisor for c2s/s2s/http listeners."
  use DynamicSupervisor

  def start_link(_arg), do: DynamicSupervisor.start_link(__MODULE__, :ok, name: __MODULE__)

  @impl true
  def init(:ok), do: DynamicSupervisor.init(strategy: :one_for_one)
end
