defmodule Exjabberd.Telemetry do
  @moduledoc """
  Telemetry - `ejabberd` metrics via `:telemetry` + `ejabberd_system_monitor` (partial implementation), stabil.

  Emits dan handle:
  - `[:exjabberd, :c2s, :bind]` + `auth`, `open_stream`, `close`
  - `[:exjabberd, :carbons, :sent]`
  - `[:exjabberd, :sm, :register]`/`unregister`
  - `[:exjabberd, :mam, :archived]` + `query`
  - `[:exjabberd, :muc, :join]` + `message`
  - `[:exjabberd, :pubsub, :publish]` + `subscribe`
  - `[:exjabberd, :jingle, :initiate]` + `terminate`
  - `[:exjabberd, :system, :alarm]` (`high_memory`, `large_heap`)

  Semua handler stabil dengan ETS counter seperti `ejabberd` `mod_metrics`.
  """

  @table :exjabberd_telemetry_counters

  @doc "Attach default handlers (like `ejabberd` `telemetry` attach)."
  @spec attach() :: :ok
  def attach do
    ensure_table()

    :telemetry.attach_many(
      "exjabberd-logger",
      [
        [:exjabberd, :c2s, :bind],
        [:exjabberd, :c2s, :auth],
        [:exjabberd, :c2s, :open_stream],
        [:exjabberd, :carbons, :sent],
        [:exjabberd, :sm, :register],
        [:exjabberd, :sm, :unregister],
        [:exjabberd, :mam, :archived],
        [:exjabberd, :muc, :join],
        [:exjabberd, :muc, :message],
        [:exjabberd, :pubsub, :publish],
        [:exjabberd, :jingle, :initiate],
        [:exjabberd, :system, :alarm]
      ],
      &__MODULE__.handle/4,
      nil
    )

    :ok
  rescue
    _ -> :ok
  end

  @doc "Detach."
  @spec detach() :: :ok
  def detach do
    :telemetry.detach("exjabberd-logger")
    :ok
  rescue
    _ -> :ok
  end

  @doc "Get counters (like `mod_metrics` `get`)."
  @spec counters() :: map()
  def counters do
    ensure_table()
    :ets.tab2list(@table) |> Map.new()
  end

  @doc "Increment counter."
  @spec inc([atom()], map(), map()) :: :ok
  def inc(event, measurements \\ %{}, metadata \\ %{}) do
    :telemetry.execute(event, measurements, metadata)
  end

  @doc false
  def handle(event, measurements, metadata, _config) do
    ensure_table()
    key = Enum.join(event, ".")
    :ets.update_counter(@table, key, 1, {key, 0})
    # Also log like ejabberd does for system alarm
    if event == [:exjabberd, :system, :alarm] do
      require Logger
      Logger.warning("exjabberd system alarm #{inspect(measurements)} #{inspect(metadata)}")
    end

    _ = {event, measurements, metadata}
    :ok
  end

  defp ensure_table do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    end
  end
end
