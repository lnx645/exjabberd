defmodule Exjabberd.Application do
  @moduledoc """
  OTP Application for exjabberd.

  Supervision strategy mirrors ejabberd's fault-tolerant design but with
  Elixir idioms. Every core subsystem is isolated so a crash in one MUC
  room never brings down c2s connections.
  """
  use Application

  @impl true
  def start(_type, _args) do
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
      {Exjabberd.Listener.C2S, [port: 5222]}
    ]

    opts = [strategy: :one_for_one, name: Exjabberd.Supervisor]
    Supervisor.start_link(children, opts)
  end
end

defmodule Exjabberd.ListenerSupervisor do
  @moduledoc "Dynamic supervisor for c2s/s2s/http listeners."
  use DynamicSupervisor

  def start_link(_arg), do: DynamicSupervisor.start_link(__MODULE__, :ok, name: __MODULE__)

  @impl true
  def init(:ok), do: DynamicSupervisor.init(strategy: :one_for_one)
end
