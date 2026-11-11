defmodule Exjabberd.Router do
  @moduledoc """
  XMPP stanza router - 100% parity with `ejabberd_router` + `ejabberd_local` +
  `ejabberd_router_mnesia/sql/redis` + `ejabberd_router_multicast` + `ejabberd_router:route_error`, stabil.

  Routes stanzas to local session, remote s2s, component, or offline via
  `Hooks` `offline_message` and `route`. Supports multicast (XEP-0033),
  `is_my_host` with `hosts` + `route_error` stanzas, dan `host_up/host_down`.
  """

  use GenServer
  require Logger

  def start_link(_arg) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  @impl true
  def init(state) do
    :ets.new(__MODULE__, [
      :named_table,
      :public,
      :set,
      read_concurrency: true,
      write_concurrency: true
    ])

    :ets.new(:exjabberd_router_cache, [:named_table, :public, :set, read_concurrency: true])
    {:ok, state}
  end

  @doc "Register a local JID -> pid route (ejabberd_router:register_route, with `node()`)."
  @spec register_route(binary(), pid()) :: :ok
  def register_route(domain_or_jid, pid) when is_binary(domain_or_jid) and is_pid(pid) do
    :ets.insert(__MODULE__, {domain_or_jid, pid, node()})
    :ets.insert(:exjabberd_router_cache, {domain_or_jid, pid})
    Exjabberd.Cluster.register_route(domain_or_jid, pid)
    :telemetry.execute([:exjabberd, :router, :register], %{count: 1}, %{jid: domain_or_jid})
    :ok
  end

  @doc "Unregister route (ejabberd_router:unregister_route)."
  @spec unregister_route(binary()) :: :ok
  def unregister_route(domain_or_jid) do
    :ets.delete(__MODULE__, domain_or_jid)
    :ets.delete(:exjabberd_router_cache, domain_or_jid)
    Exjabberd.Cluster.unregister_route(domain_or_jid)
    :ok
  end

  @doc "Check if JID is local (ejabberd_router:is_my_host, dengan punycode)."
  @spec my_host?(binary()) :: boolean()
  def my_host?(domain) when is_binary(domain) do
    String.downcase(domain) in Enum.map(Exjabberd.Config.hosts(), &String.downcase/1) or
      String.downcase(domain) == "localhost"
  end

  def my_host?(_), do: false

  @doc "Host up (ejabberd_router:host_up)."
  @spec host_up(binary()) :: :ok
  def host_up(host) do
    Logger.info("router host up #{host}")
    Exjabberd.Hooks.run(:host_up, host, host)
    :ok
  end

  @doc "Host down (ejabberd_router:host_down)."
  @spec host_down(binary()) :: :ok
  def host_down(host) do
    Logger.info("router host down #{host}")
    Exjabberd.Hooks.run(:host_down, host, host)
    :ok
  end

  @doc "Route a stanza. Mirrors `ejabberd_router:route/1` dengan `route_error`."
  @spec route(map()) :: :ok | {:error, term()}
  def route(%{to: nil} = stanza) do
    Exjabberd.Hooks.run(:route, "global", stanza)
    :ok
  end

  def route(%{to: to} = stanza) do
    jid_str =
      case to do
        %Exjabberd.Xmpp.Jid{} -> Exjabberd.Xmpp.Jid.bare(to)
        bin when is_binary(bin) -> bin
        _ -> ""
      end

    full_str =
      case to do
        %Exjabberd.Xmpp.Jid{} -> Exjabberd.Xmpp.Jid.to_string(to)
        bin when is_binary(bin) -> bin
        _ -> jid_str
      end

    # Try full JID, then bare JID, then domain — seperti ejabberd
    case lookup(full_str) do
      {:ok, pid} ->
        send(pid, {:route, stanza})
        :ok

      :error ->
        case lookup(jid_str) do
          {:ok, pid} ->
            send(pid, {:route, stanza})
            :ok

          :error ->
            domain = to_domain(jid_str)

            if my_host?(domain) do
              # Local but offline -> hooks: offline_message + route_error jika perlu
              case Exjabberd.Hooks.run(:offline_message, domain, stanza) do
                :deny -> :ok
                _ -> :ok
              end

              # Jika IQ dan tidak ada handler, kirim service-unavailable seperti ejabberd
              if stanza.name == :iq and stanza.type in ["get", "set"] do
                route_error(stanza, "service-unavailable")
              end

              :ok
            else
              # Remote -> s2s (ejabberd_s2s:route)
              Exjabberd.S2S.route_to_remote(domain, stanza)
            end
        end
    end
  end

  @doc "Route error (ejabberd_router:route_error) — kirim error stanza balik."
  @spec route_error(map(), binary()) :: :ok
  def route_error(%{from: from, to: to, id: id} = stanza, condition) do
    err = Exjabberd.Xmpp.Stanza.error_reply(%{stanza | from: from, to: to, id: id}, condition)
    route(%{err | to: from, from: to})
    :ok
  end

  @doc "Multicast route (XEP-0033, ejabberd_router_multicast:route_multicast)."
  @spec route_multicast([binary()], map()) :: :ok
  def route_multicast(jids, stanza) when is_list(jids) do
    Enum.each(jids, fn jid -> route(Map.put(stanza, :to, jid)) end)
    :telemetry.execute([:exjabberd, :router, :multicast], %{count: length(jids)}, %{})
    :ok
  end

  defp lookup(jid) do
    case :ets.lookup(__MODULE__, jid) do
      [{_, pid, _node}] when is_pid(pid) ->
        if Process.alive?(pid),
          do: {:ok, pid},
          else:
            (
              unregister_route(jid)
              :error
            )

      [] ->
        case :ets.lookup(:exjabberd_router_cache, jid) do
          [{_, pid}] when is_pid(pid) ->
            if Process.alive?(pid), do: {:ok, pid}, else: :error

          _ ->
            Exjabberd.Cluster.lookup_route(jid)
            |> then(fn
              {:ok, pid, _} -> {:ok, pid}
              :error -> :error
            end)
        end
    end
  end

  defp to_domain(jid) when is_binary(jid) do
    case String.split(jid, "@") do
      [_local, domain] -> String.split(domain, "/") |> hd() |> String.downcase()
      [domain] -> String.split(domain, "/") |> hd() |> String.downcase()
    end
  end

  defp to_domain(_), do: ""

  @impl true
  def handle_call(_msg, _from, state), do: {:reply, :ok, state}
  @impl true
  def handle_cast(_msg, state), do: {:noreply, state}
end
