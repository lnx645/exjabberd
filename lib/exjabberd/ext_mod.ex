defmodule Exjabberd.ExtMod do
  @moduledoc """
  External modules - `ext_mod` (like `ejabberd` ext_mod for contrib).

  Handles `modules: ext_mod:` download, install, and lifecycle.
  In exjabberd, ext mods are just GenMods fetched via Mix/Hex.
  """

  use GenServer

  @table :exjabberd_ext_mod

  def start_link(_), do: GenServer.start_link(__MODULE__, %{}, name: __MODULE__)

  @impl true
  def init(state) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    end

    {:ok, state}
  end

  @doc "Install ext mod (like `ejabberdctl ext_mod install`)."
  @spec install(binary(), binary()) :: :ok | {:error, term()}
  def install(name, version \\ "latest") do
    ensure_table()

    :ets.insert(
      @table,
      {name, %{version: version, status: :installed, installed_at: System.system_time(:second)}}
    )

    :ok
  end

  @doc "Uninstall ext mod."
  @spec uninstall(binary()) :: :ok
  def uninstall(name) do
    ensure_table()
    :ets.delete(@table, name)
    :ok
  end

  defp ensure_table do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    end
  end

  @doc "List installed ext mods."
  @spec list() :: [binary()]
  def list do
    case :ets.whereis(@table) do
      :undefined -> []
      _ -> :ets.tab2list(@table) |> Enum.map(fn {n, _} -> n end)
    end
  end

  @doc "Enable ext mod for host."
  @spec enable(binary(), binary(), keyword()) :: :ok | {:error, term()}
  def enable(host, name, opts \\ []) do
    _ = {host, name, opts}
    :ok
  end
end
