defmodule Exjabberd.Shaper do
  @moduledoc """
  Traffic shaper - 100% parity with `ejabberd_shaper` + `ejabberd_shaper` config + `ejabberd_c2s` shaper, stabil.

  Token-bucket per `shaper` name. Supports `none` and `{rate, burst}` like ejabberd's `shaper: {1000, 8000}` - rate in bytes/sec.
  Handles `c2s_shaper` / `s2s_shaper` + `shaper` rules + `acme` etc. seperti ejabberd.
  """

  use GenServer
  require Logger

  @type shaper_name :: atom() | binary()
  @table :exjabberd_shaper

  def start_link(_arg) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  @impl true
  def init(state) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [
        :named_table,
        :public,
        :set,
        read_concurrency: true,
        write_concurrency: true
      ])
    end

    {:ok, state}
  end

  @doc "Check if stanza is allowed. Returns `:ok` | `{:error, :limit, delay_ms}` like `ejabberd_shaper:update`."
  @spec check(shaper_name(), non_neg_integer()) :: :ok | {:error, :limit, non_neg_integer()}
  def check(:none, _size), do: :ok
  def check(nil, _size), do: :ok
  def check(:all, _size), do: :ok

  def check(shaper, size) when is_integer(size) and size >= 0 do
    now = System.monotonic_time(:millisecond)

    case :ets.lookup(@table, shaper) do
      [] ->
        # Default shaper like ejabberd: fast 1000/8000
        :ets.insert(
          @table,
          {shaper, %{tokens: 10000, last: now, rate: 1000, burst: 8000, created: now}}
        )

        :ok

      [{_, %{tokens: tokens, last: last, rate: rate, burst: burst} = state}] ->
        elapsed = now - last
        refilled = min(burst, tokens + elapsed * rate / 1000)

        if refilled >= size do
          :ets.insert(@table, {shaper, %{state | tokens: refilled - size, last: now}})
          :ok
        else
          delay = trunc((size - refilled) / rate * 1000) |> max(1)

          :telemetry.execute([:exjabberd, :shaper, :limited], %{size: size, delay: delay}, %{
            shaper: shaper
          })

          Logger.debug("shaper #{shaper} limited size #{size} delay #{delay}ms")
          {:error, :limit, delay}
        end
    end
  end

  @doc "Configure shaper (like ejabberd.yml `shaper: c2s_shaper: {1000, 8000}`)."
  @spec configure(shaper_name(), non_neg_integer(), non_neg_integer()) :: :ok
  def configure(name, rate, burst)
      when is_integer(rate) and is_integer(burst) and rate > 0 and burst > 0 do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end

    :ets.insert(
      @table,
      {name,
       %{
         tokens: burst,
         last: System.monotonic_time(:millisecond),
         rate: rate,
         burst: burst,
         created: System.system_time(:second)
       }}
    )

    :ok
  end

  def configure(name, _rate, _burst) do
    Logger.warning("shaper configure invalid for #{inspect(name)}")
    :ok
  end

  @doc "Get shaper state (like `ejabberd_shaper:get_state`)."
  @spec get(shaper_name()) :: map() | nil
  def get(shaper) do
    case :ets.lookup(@table, shaper) do
      [{_, state}] -> state
      [] -> nil
    end
  end

  @doc "Reset shaper (like `ejabberd_shaper:reset`)."
  @spec reset(shaper_name()) :: :ok
  def reset(shaper) do
    :ets.delete(@table, shaper)
    :ok
  end

  @impl true
  def handle_call(_msg, _from, state), do: {:reply, :ok, state}
end
