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
  4. The C2S listener (port 5222) — plus direct-TLS 5223 when the
     config enables it.
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
      {Exjabberd.Auth.Mnesia, []},
      {Exjabberd.Listener.C2S, [port: 5222]}
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

    # Direct-TLS C2S (port 5223) when the config's `listen:` enables it.
    tls_c2s =
      Enum.any?(Exjabberd.Config.listen(), fn entry ->
        Map.get(entry, "port") == 5223 and Map.get(entry, "tls") == true
      end)

    if tls_c2s do
      case DynamicSupervisor.start_child(
             Exjabberd.ListenerSupervisor,
             {Exjabberd.Listener.C2S, [port: 5223, tls: true, name: Exjabberd.Listener.C2S.TLS]}
           ) do
        {:ok, _} -> Logger.info("exjabberd direct-TLS C2S on 5223")
        {:error, reason} -> Logger.warning("direct-TLS C2S failed: #{inspect(reason)}")
      end
    end

    # Start the configured modules for every host.
    for host <- Exjabberd.Config.hosts() do
      Exjabberd.Mod.Supervisor.start_all(host)
    end

    {:ok, sup}
  end
end

defmodule Exjabberd.ListenerSupervisor do
  @moduledoc "Dynamic supervisor for c2s/s2s/http listeners."
  use DynamicSupervisor

  def start_link(_arg), do: DynamicSupervisor.start_link(__MODULE__, :ok, name: __MODULE__)

  @impl true
  def init(:ok), do: DynamicSupervisor.init(strategy: :one_for_one)
end
