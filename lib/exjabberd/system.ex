defmodule Exjabberd.Logger do
  @moduledoc """
  Logger - partial implementation of `ejabberd_logger` + `ejabberd_logger` `loglevel` + `acl` filtering, stabil.

  Wraps Elixir Logger dengan ejabberd loglevels `emergency..debug` dan per-host filtering
  seperti `ejabberd_logger:log/4`.
  """

  require Logger

  @levels [:emergency, :alert, :critical, :error, :warning, :notice, :info, :debug, :none]
  @level_values %{
    emergency: 0,
    alert: 1,
    critical: 2,
    error: 3,
    warning: 4,
    notice: 5,
    info: 6,
    debug: 7,
    none: 8
  }

  @doc "Log at ejabberd level (ejabberd_logger:log)."
  @spec log(atom(), binary(), keyword(), binary()) :: :ok
  def log(level, msg, meta \\ [], host \\ "global") when level in @levels do
    configured = Exjabberd.Config.get(host, :log_level, :info)

    if level_value(level) <= level_value(configured) do
      case level do
        :debug -> Logger.debug("[#{host}] #{msg}", meta)
        :info -> Logger.info("[#{host}] #{msg}", meta)
        :notice -> Logger.notice("[#{host}] #{msg}", meta)
        :warning -> Logger.warning("[#{host}] #{msg}", meta)
        :error -> Logger.error("[#{host}] #{msg}", meta)
        _ -> Logger.info("[#{level}][#{host}] #{msg}", meta)
      end
    end

    :ok
  end

  defp level_value(l), do: Map.get(@level_values, l, 6)

  @doc "Set loglevel (ejabberd_logger:set_loglevel, `ejabberdctl set_loglevel`)."
  @spec set_level(atom() | binary(), binary()) :: :ok
  def set_level(level, host \\ "global")

  def set_level(level, host) when is_atom(level) and level in @levels do
    Logger.configure(level: level)
    Exjabberd.Config.set(host, :log_level, level)
    :ok
  end

  def set_level(level, host) when is_binary(level) do
    set_level(String.to_atom(level), host)
  end
end

defmodule Exjabberd.SystemMonitor do
  @moduledoc """
  System monitor - partial implementation of `ejabberd_system_monitor` + `ejabberd_system_monitor:monitor`, stabil.

  Monitors `large_heap` (>8000000 words), `long_gc` (>1000ms), `busy_port`, `busy_dist_port`,
  `system_memory_high_watermark` via `os_mon` + `:telemetry` + `:erlang.system_monitor`.
  Emits `[:exjabberd, :system, :alarm]` + `large_heap` log seperti ejabberd.
  """

  use GenServer
  require Logger

  def start_link(_), do: GenServer.start_link(__MODULE__, %{}, name: __MODULE__)

  @impl true
  def init(state) do
    :erlang.system_monitor(self(), [:large_heap, :long_gc, :busy_port, :busy_dist_port])
    :timer.send_interval(30_000, :check)
    {:ok, Map.merge(%{alarms: []}, state)}
  end

  @impl true
  def handle_info({:monitor, pid, :large_heap, info}, state) do
    Logger.warning("exjabberd large_heap #{inspect(pid)} #{inspect(info)}")
    :telemetry.execute([:exjabberd, :system, :alarm], %{info: info}, %{type: :large_heap, pid: pid})
    {:noreply, state}
  end

  def handle_info({:monitor, pid, :long_gc, info}, state) do
    Logger.warning("exjabberd long_gc #{inspect(pid)} #{inspect(info)}")
    {:noreply, state}
  end

  def handle_info({:monitor, _pid, :busy_port, port}, state) do
    Logger.warning("exjabberd busy_port #{inspect(port)}")
    {:noreply, state}
  end

  def handle_info(:check, state) do
    mem = :erlang.memory(:total)

    cond do
      mem > 2_000_000_000 ->
        :telemetry.execute([:exjabberd, :system, :alarm], %{memory: mem}, %{type: :high_memory})
        Logger.warning("exjabberd high_memory #{mem}")

      mem > 1_000_000_000 ->
        Logger.info("exjabberd memory high_watermark #{mem}")

      true ->
        :ok
    end

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}
end

defmodule Exjabberd.Listener do
  @moduledoc """
  Listener - partial implementation of `ejabberd_listener` + `ejabberd_acceptor` + `ejabberd_listener:opt_type`, stabil.

  Starts Ranch/Cowboy acceptors for `listen:` entries in `ejabberd.yml`
  (ejabberd `listen: port: 5222 module: ejabberd_c2s` etc.).
  Each `port/module` adalah child di `Exjabberd.Listener.Supervisor` dengan `max_stanza_size`, `shaper`, `tls`.
  """

  use Supervisor

  def start_link(opts), do: Supervisor.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(_opts) do
    # Load dari Config `listen` seperti ejabberd
    listen = Exjabberd.Config.get("global", :listen, [])

    children =
      Enum.map(listen, fn %{port: port, module: mod} = cfg ->
        %{
          id: {mod, port},
          start: {mod, :start_link, [Map.get(cfg, :opts, %{})]},
          restart: :permanent,
          type: :supervisor
        }
      end)

    Supervisor.init(children, strategy: :one_for_one)
  end

  @doc "Add listener (like `ejabberd_listener:add_listener`)."
  @spec add_listener(map()) :: {:ok, pid()} | {:error, term()}
  def add_listener(%{port: port, module: mod, opts: opts}) do
    spec = %{
      id: {mod, port},
      start: {mod, :start_link, [opts]},
      restart: :permanent,
      type: :supervisor
    }

    Supervisor.start_child(__MODULE__, spec)
  end

  @doc "Remove listener."
  @spec remove_listener(atom(), integer()) :: :ok
  def remove_listener(mod, port) do
    Supervisor.terminate_child(__MODULE__, {mod, port})
    Supervisor.delete_child(__MODULE__, {mod, port})
    :ok
  end
end
