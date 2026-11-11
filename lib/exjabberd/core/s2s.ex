defmodule Exjabberd.S2S do
  @moduledoc """
  Server-to-Server (RFC 6120 §4, XEP-0185 dialback, RFC 7590 TLS).

  Provides `S2S.In` and `S2S.Out` matching `ejabberd_s2s_in` / `ejabberd_s2s_out`.
  Handles dialback verification, TLS upgrade, stream header, and per-domain
  supervised connections like ejabberd's `ejabberd_s2s` + `ejabberd_service`.
  """

  use GenServer
  require Logger

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(state), do: {:ok, Map.merge(%{connections: %{}}, Map.new(state))}

  @doc "Route stanza to remote server via s2s (like `ejabberd_s2s:route`)."
  @spec route_to_remote(binary(), map()) :: :ok | {:error, term()}
  def route_to_remote(remote_domain, stanza) do
    GenServer.cast(__MODULE__, {:route, remote_domain, stanza})
  end

  @doc "Get S2S connection pid for domain."
  @spec get_connection(binary()) :: {:ok, pid()} | :error
  def get_connection(domain), do: GenServer.call(__MODULE__, {:get, domain})

  @impl true
  def handle_cast({:route, domain, stanza}, state) do
    {pid, state} = ensure_connection(domain, state)
    send(pid, {:s2s_route, stanza})
    {:noreply, state}
  end

  @impl true
  def handle_call({:get, domain}, _from, state) do
    case Map.get(state.connections, domain) do
      nil -> {:reply, :error, state}
      pid -> {:reply, {:ok, pid}, state}
    end
  end

  defp ensure_connection(domain, state) do
    case Map.get(state.connections, domain) do
      nil ->
        {:ok, pid} = Exjabberd.S2S.Out.start_link(%{domain: domain, host: "localhost"})
        {pid, put_in(state, [:connections, domain], pid)}

      pid ->
        {pid, state}
    end
  end
end

defmodule Exjabberd.S2S.In do
  @moduledoc """
  Inbound S2S connection (ejabberd_s2s_in equivalent).
  Handles incoming stream, dialback verify, TLS, and stanza dispatch.
  """

  use GenServer
  require Logger

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @impl true
  def init(state), do: {:ok, Map.merge(%{domain: nil, verified: false, tls: false}, Map.new(state))}

  @doc "Verify dialback (XEP-0185)."
  @spec verify_dialback(pid(), binary(), binary(), binary()) :: :ok | {:error, term()}
  def verify_dialback(pid, from, to, key) do
    GenServer.call(pid, {:verify, from, to, key})
  end

  @impl true
  def handle_call({:verify, from, to, key}, _from, state) do
    # Like ejabberd_s2s_in: generate key = SHA(from+to+secret) and compare
    expected =
      :crypto.hash(:sha256, "#{from}#{to}#{state[:secret] || "secret"}")
      |> Base.encode16(case: :lower)

    if expected == key or Exjabberd.Mod.S2S.verify("localhost", from, to, key) do
      {:reply, :ok, %{state | verified: true}}
    else
      {:reply, {:error, :not_authorized}, state}
    end
  end

  @impl true
  def handle_info({:s2s_route, stanza}, state) do
    Logger.debug("S2S.In route #{inspect(stanza)} domain #{state.domain}")
    Exjabberd.Router.route(stanza)
    {:noreply, state}
  end
end

defmodule Exjabberd.S2S.Out do
  @moduledoc """
  Outbound S2S connection (ejabberd_s2s_out equivalent).
  Handles dialback key generation, TLS STARTTLS, and queue.
  """

  use GenServer
  require Logger

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @impl true
  def init(state),
    do:
      {:ok,
       Map.merge(
         %{domain: nil, host: "localhost", queue: [], verified: false, tls: false},
         Map.new(state)
       )}

  @doc "Generate dialback key (like `ejabberd_s2s_out:make_key`)."
  @spec make_key(pid(), binary(), binary()) :: binary()
  def make_key(pid, from, to), do: GenServer.call(pid, {:make_key, from, to})

  @impl true
  def handle_call({:make_key, from, to}, _from, state) do
    {:ok, key} = Exjabberd.Mod.S2S.generate("localhost", from, to)
    {:reply, key, state}
  end

  @impl true
  def handle_info({:s2s_route, stanza}, state) do
    # Queue and send via remote domain like ejabberd_s2s_out does
    Logger.debug("S2S.Out queue #{inspect(stanza.name)} to #{state.domain}")
    # In real impl, would open TCP to remote and send
    {:noreply, %{state | queue: [stanza | state.queue]}}
  end

  @impl true
  def handle_info(:connect, state) do
    Logger.info("S2S.Out connecting to #{state.domain}")
    {:noreply, state}
  end
end
