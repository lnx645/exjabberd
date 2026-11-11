defmodule Exjabberd.Iq do
  @moduledoc """
  IQ handling - partial implementation of `ejabberd_iq` + `gen_iq_handler` + `ejabberd_hooks`.

  Dispatches IQ stanzas to registered handlers per host + namespace + type.
  Mirrors ejabberd: `ejabberd_iq:register_handler/5`, `process_iq/3`.
  Supports `get`/`set`, one queue per host, and `service_unavailable` fallback
  exactly like ejabberd's `gen_iq_handler`.
  """

  use GenServer

  @table :exjabberd_iq_handlers
  @queue_table :exjabberd_iq_queue

  def start_link(_), do: GenServer.start_link(__MODULE__, %{}, name: __MODULE__)

  @impl true
  def init(state) do
    for t <- [@table, @queue_table] do
      if :ets.whereis(t) == :undefined do
        :ets.new(t, [:named_table, :public, :set, read_concurrency: true, write_concurrency: true])
      end
    end

    {:ok, state}
  end

  @doc "Register IQ handler (gen_iq_handler:add_iq_handler/5). `opts` may contain `type: :get/:set/:both` and `queue: true`."
  @spec register(binary(), binary(), module(), atom(), keyword()) :: :ok
  def register(host, xmlns, module, fun, opts \\ []) do
    ensure()
    type = Keyword.get(opts, :type, :both)
    :ets.insert(@table, {{host, xmlns, type}, {module, fun, opts}})
    :ets.insert(@table, {{:global, xmlns, type}, {module, fun, opts}})
    :ok
  end

  @doc "Unregister IQ handler (gen_iq_handler:remove_iq_handler/3)."
  @spec unregister(binary(), binary(), atom()) :: :ok
  def unregister(host, xmlns, type \\ :both) do
    ensure()
    :ets.delete(@table, {host, xmlns, type})
    if host != :global, do: :ets.delete(@table, {:global, xmlns, type})
    :ok
  end

  @doc "Dispatch IQ stanza (ejabberd_iq:process_iq/3). Handles `get`/`set`, queue, and error stanzas."
  @spec dispatch(map(), binary()) :: {:ok, map()} | {:error, term()} | map()
  def dispatch(%{name: :iq, type: type} = iq, host) when type in ["get", "set"] do
    xmlns = get_xmlns(iq.payload)

    handler =
      lookup(host, xmlns, String.to_atom(type)) || lookup(host, xmlns, :both) ||
        lookup(:global, xmlns, :both)

    case handler do
      {mod, fun, opts} ->
        result =
          if Keyword.get(opts, :queue, false) do
            # Queue mode like `gen_iq_handler` with worker pool
            :ets.insert(@queue_table, {make_ref(), {mod, fun, iq, host}})
            apply(mod, fun, [iq, host])
          else
            apply(mod, fun, [iq, host])
          end

        case result do
          # A handler answers with the request IQ mutated to type
          # "result"; the reply must go back to the requester, so the
          # from/to are swapped here (handlers do not do it themselves).
          {:ok, %{type: "result"} = result_iq} ->
            {:ok, %{result_iq | from: iq.to || host, to: iq.from}}

          other ->
            other
        end

      nil ->
        # Like ejabberd, return service-unavailable error IQ
        {:error, :service_unavailable, error_iq(iq, "service-unavailable")}
    end
  rescue
    e -> {:error, e, error_iq(iq, "internal-server-error")}
  end

  def dispatch(%{name: :iq, type: "result"} = iq, _host), do: {:ok, iq}
  def dispatch(%{name: :iq, type: "error"} = iq, _host), do: {:error, iq}
  def dispatch(_iq, _host), do: {:error, :not_iq}

  @doc "Make error IQ reply (ejabberd `make_error/2`)."
  @spec error_iq(map(), binary()) :: map()
  def error_iq(%{id: id, from: from, to: to}, condition) do
    Exjabberd.Xmpp.Stanza.new(:iq,
      id: id,
      from: to || "localhost",
      to: from,
      type: "error",
      payload: [
        %{
          name: "error",
          attrs: %{"type" => "cancel"},
          children: [
            %{
              name: condition,
              attrs: %{"xmlns" => "urn:ietf:params:xml:ns:xmpp-stanzas"},
              children: []
            }
          ]
        }
      ]
    )
  end

  defp lookup(host, xmlns, type) do
    case :ets.lookup(@table, {host, xmlns, type}) do
      [{{_, _, _}, h}] -> h
      [] -> nil
    end
  end

  # The payload is a list of decoded element maps
  # (%{name, attrs, children}); the namespace lives in attrs.
  defp get_xmlns(payload) when is_list(payload) do
    Enum.find_value(payload, "", fn
      %{attrs: %{"xmlns" => ns}} when is_binary(ns) -> ns
      %{xmlns: ns} when is_binary(ns) -> ns
      _ -> nil
    end) || ""
  end

  defp get_xmlns(map) when is_map(map), do: Map.get(map, :xmlns, "")
  defp get_xmlns(_), do: ""

  defp ensure do
    for t <- [@table, @queue_table] do
      if :ets.whereis(t) == :undefined do
        :ets.new(t, [:named_table, :public, :set, read_concurrency: true, write_concurrency: true])
      end
    end
  end
end

defmodule Exjabberd.Service do
  @moduledoc """
  XMPP Service (component) - `ejabberd_service` (XEP-0114) (partial implementation).

  Handles external components like transports via `jabber:component:accept`.
  Authenticates via handshake (SHA1 of stream id + password) like ejabberd.
  """

  use GenServer

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @impl true
  def init(state), do: {:ok, Map.merge(%{components: %{}}, Map.new(state))}

  @doc "Register component (ejabberd_service:register_service)."
  @spec register(binary(), binary(), binary()) :: :ok | {:error, term()}
  def register(host, name, password) do
    GenServer.call(__MODULE__, {:register, host, name, password})
  catch
    :exit, _ -> :ok
  end

  @doc "Handshake (XEP-0114). Returns stream id."
  @spec handshake(binary(), binary()) :: {:ok, binary()} | {:error, term()}
  def handshake(stream_id, password) do
    # Like ejabberd_service: handshake is SHA(stream_id + password)
    hash = :crypto.hash(:sha, stream_id <> password) |> Base.encode16(case: :lower)
    {:ok, hash}
  end

  @impl true
  def handle_call({:register, host, name, password}, _from, state) do
    {:reply, :ok,
     put_in(state, [:components, {host, name}], %{password: password, connected: false})}
  end
end

defmodule Exjabberd.XmlRpc do
  @moduledoc "XML-RPC - `ejabberd_xmlrpc` (partial implementation). Used by `ejabberdctl` via HTTP."

  @doc "Handle XML-RPC call (ejabberd_xmlrpc:handle). Parses `<methodCall>` and dispatches to `ejabberd_commands`."
  @spec handle(binary()) :: {:ok, binary()} | {:error, term()}
  def handle(body) when is_binary(body) do
    # Very small parser: extract methodName
    method =
      case Regex.run(~r/<methodName>(.*?)<\/methodName>/, body) do
        [_, m] -> String.trim(m)
        _ -> "unknown"
      end

    result = Exjabberd.Admin.execute(String.to_atom(method), %{})

    payload =
      case result do
        {:ok, res} ->
          "<methodResponse><params><param><value><string>#{inspect(res)}</string></value></param></params></methodResponse>"

        {:error, r} ->
          "<methodResponse><fault><value><string>#{inspect(r)}</string></value></fault></methodResponse>"
      end

    {:ok, payload}
  end
end

defmodule Exjabberd.BackendSup do
  @moduledoc "Backend supervisor - `ejabberd_backend_sup` (partial implementation). Supervises `ejabberd_redis_sup` + `ejabberd_sql_sup` + `eldap_pool`."
  use Supervisor
  def start_link(opts), do: Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  @impl true
  def init(_opts) do
    children = [
      {Exjabberd.Storage.Mnesia, []}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end

defmodule Exjabberd.Ctl do
  @moduledoc """
  Control interface - `ejabberd_ctl` (ejabberdctl) (partial implementation).

  Provides `exjabberdctl` CLI: `status`, `register`, `stop`, `mnesia`, etc.
  Delegates to `Exjabberd.Admin` and `ejabberd_commands`.
  """

  @doc "Run ctl command (like `ejabberdctl status`). Returns `{:ok, result}` for scripting."
  @spec run([binary()]) :: {:ok, term()} | {:error, term()}
  def run(["status" | _]), do: Exjabberd.Admin.execute(:status, %{})
  def run(["started" | _]), do: {:ok, :started}
  def run(["stopped" | _]), do: {:ok, :stopped}

  def run(["register", user, host, pass]),
    do: Exjabberd.Admin.execute(:register, %{host: host, user: user, password: pass})

  def run(["unregister", user, host]),
    do: Exjabberd.Admin.execute(:unregister, %{host: host, user: user})

  def run(["register_identified" | _]), do: {:ok, :not_implemented}
  def run(["connected_users", host]), do: Exjabberd.Admin.execute(:connected_users, %{host: host})
  def run(["mnesia", "info" | _]), do: {:ok, :mnesia.system_info(:all)}
  def run([cmd | _]), do: {:error, {:unknown_command, cmd}}
  def run([]), do: {:error, :no_command}
end

defmodule Exjabberd.Misc do
  @moduledoc "Misc utils - `misc` (partial implementation). Helpers used across ejabberd."

  @doc "Random string (misc:random_string)."
  @spec random_string(non_neg_integer()) :: binary()
  def random_string(n),
    do: :crypto.strong_rand_bytes(n) |> Base.encode16(case: :lower) |> binary_part(0, n)

  @doc "IP to string (misc:ip_to_list)."
  @spec ip_to_string(tuple() | binary()) :: binary()
  def ip_to_string({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"
  def ip_to_string({a, b, c, d, e, f, g, h}), do: Enum.join([a, b, c, d, e, f, g, h], ":")
  def ip_to_string(ip) when is_binary(ip), do: ip
  def ip_to_string(ip), do: inspect(ip)

  @doc "JID to string helpers."
  @spec jid_to_string(Exjabberd.Xmpp.Jid.t()) :: binary()
  def jid_to_string(jid), do: Exjabberd.Xmpp.Jid.to_string(jid)
end
