defmodule Exjabberd.Listener.Mqtt do
  @moduledoc """
  TCP listener for the MQTT broker (port 1883 by default).

  Mirrors `Exjabberd.Listener.C2S`: binds the port, accepts sockets
  and hands each one to an `Exjabberd.Mqtt.Connection` process, which
  owns the socket from there on.
  """

  use GenServer
  require Logger

  alias Exjabberd.Mqtt.Connection

  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @impl true
  def init(opts) do
    port = Keyword.get(opts, :port, 1883)
    host = Keyword.get(opts, :host, "localhost")

    {:ok, ls} =
      :gen_tcp.listen(port, [:binary, packet: 0, active: false, reuseaddr: true, backlog: 128])

    Logger.info("exjabberd MQTT listening real on 0.0.0.0:#{port} (host #{host})")
    send(self(), :accept)
    {:ok, %{ls: ls, port: port, host: host}}
  end

  @impl true
  def handle_info(:accept, %{ls: ls} = s) do
    case :gen_tcp.accept(ls, 1000) do
      {:ok, sock} ->
        pid = Connection.start(sock, s.host)
        :ok = :gen_tcp.controlling_process(sock, pid)
        send(pid, {:take_socket, sock})

      {:error, :timeout} ->
        :ok

      {:error, e} ->
        Logger.warning("MQTT accept error #{inspect(e)}")
        Process.sleep(100)
    end

    send(self(), :accept)
    {:noreply, s}
  end
end
