defmodule Exjabberd.Mod.Adhoc.Full do
  @moduledoc """
  Adhoc Full - XEP-0050 Ad-Hoc Commands real flow, bukan cuma ETS.
  Menangani IQ `http://jabber.org/protocol/commands` dengan actions
  `execute/prev/next/complete/cancel` + `x:data` form, seperti `mod_adhoc`.
  """

  use Exjabberd.Mod.GenMod
  use GenServer

  @table :exjabberd_adhoc_sessions

  @impl true
  def start(host, _opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end

    Exjabberd.Iq.register(
      host,
      "http://jabber.org/protocol/commands",
      __MODULE__,
      :handle_iq
    )

    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Iq.unregister(host, "http://jabber.org/protocol/commands", :both)
    :ok
  end

  def start_link(_), do: GenServer.start_link(__MODULE__, %{}, name: __MODULE__)

  @impl true
  def init(state) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end

    {:ok, state}
  end

  @doc "Handle Adhoc IQ (ejabberd `mod_adhoc:process_adhoc_request`)."
  @spec handle_iq(map(), binary()) :: {:ok, map()} | {:error, term()}
  def handle_iq(
        %{type: "set", payload: [%{node: node, action: action, data: data} | _]} = iq,
        host
      ) do
    case Exjabberd.Mod.Adhoc.execute(host, node, [iq.from, action, data]) do
      {:ok, result} ->
        {:ok, %{iq | type: "result", payload: [%{node: node, status: "completed", data: result}]}}

      {:error, :item_not_found} ->
        {:error, :item_not_found, Exjabberd.Xmpp.Stanza.error_reply(iq, "item-not-found")}

      other ->
        {:ok, %{iq | type: "result", payload: [other]}}
    end
  end

  def handle_iq(%{type: "get"} = iq, host) do
    # List commands like ejabberd does on disco
    cmds = :ets.match(@table, {{host, :"$1"}, :_}) |> List.flatten()
    {:ok, %{iq | type: "result", payload: [%{commands: cmds}]}}
  end

  def handle_iq(iq, _host), do: {:ok, %{iq | type: "result", payload: []}}
end
