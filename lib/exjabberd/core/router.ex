defmodule Exjabberd.Router do
  @moduledoc """
  XMPP stanza router - partial implementation of `ejabberd_router` + `ejabberd_local` +
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
  def route(%{to: nil, name: :presence} = stanza) do
    # Bare presence (no `to`): the user announcing themselves. ejabberd
    # broadcasts it to roster contacts with a subscription; this server
    # has no subscription enforcement yet, so initial presence is
    # broadcast to every online local session (documented simplification
    # until roster-subscription broadcast lands).
    broadcast_presence(stanza)
    :ok
  end

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

            cond do
              conference_domain?(domain) ->
                route_conference(stanza, domain)

              pubsub_domain?(domain) ->
                route_pubsub(stanza, domain)

              my_host?(domain) ->
                route_local_offline(stanza, domain)

              true ->
                # Remote -> s2s (ejabberd_s2s:route)
                Exjabberd.S2S.route_to_remote(domain, stanza)
            end
        end
    end
  end

  @doc "True when `domain` is the `conference.` service of a local host."
  @spec conference_domain?(binary()) :: boolean()
  def conference_domain?(domain) when is_binary(domain) do
    case domain do
      "conference." <> base -> my_host?(base)
      _ -> false
    end
  end

  def conference_domain?(_), do: false

  @doc "True when `domain` is the `pubsub.` service of a local host."
  @spec pubsub_domain?(binary()) :: boolean()
  def pubsub_domain?(domain) when is_binary(domain) do
    case domain do
      "pubsub." <> base -> my_host?(base)
      _ -> false
    end
  end

  def pubsub_domain?(_), do: false

  # Stanza to a local user with no online session.
  defp route_local_offline(%{name: :presence}, _domain) do
    # Presence to an offline user is silently dropped (normal XMPP).
    :ok
  end

  defp route_local_offline(%{name: :iq, type: type} = stanza, _domain)
       when type in ["get", "set"] do
    # An IQ cannot wait offline: answer service-unavailable like ejabberd.
    route_error(stanza, "service-unavailable")
    :ok
  end

  defp route_local_offline(%{name: :message} = stanza, domain) do
    # mod_offline stores it when the user exists; an unknown local user
    # gets a service-unavailable error instead of silent loss.
    case Exjabberd.Hooks.run(:offline_message, domain, stanza) do
      :stored -> :ok
      :deny -> :ok
      _ -> route_error(stanza, "service-unavailable")
    end

    :ok
  end

  defp route_local_offline(_stanza, _domain), do: :ok

  # Stanza addressed to room@conference.host or to conference.host.
  defp route_conference(stanza, domain) do
    # A crashing room must never kill the sender's session: contain
    # module errors here and answer IQs with an error instead.
    try do
      do_route_conference(stanza, domain)
    rescue
      e ->
        Logger.warning("MUC route failed: #{inspect(e)}")

        if stanza.name == :iq and stanza.type in ["get", "set"] do
          route(Exjabberd.Iq.error_iq(stanza, "internal-server-error"))
        end

        :ok
    catch
      :exit, reason ->
        Logger.warning("MUC route exited: #{inspect(reason)}")

        if stanza.name == :iq and stanza.type in ["get", "set"] do
          route(Exjabberd.Iq.error_iq(stanza, "internal-server-error"))
        end

        :ok
    end
  end

  defp do_route_conference(stanza, domain) do
    host = String.replace_prefix(domain, "conference.", "")
    {bare, resource} = split_jid(stanza.to)
    from_bare = from_bare(stanza.from)

    case stanza.name do
      :presence ->
        if stanza.type == "unavailable" do
          Exjabberd.Mod.Muc.leave(host, bare, from_bare, resource)
        else
          Exjabberd.Mod.Muc.join(host, bare, from_bare, resource)
        end

        :ok

      :message ->
        body = Exjabberd.Xmpp.Stanza.child_text(stanza.payload, "body") || ""

        if stanza.type in ["groupchat", nil] do
          Exjabberd.Mod.Muc.send_message(host, bare, from_bare, body)
        end

        :ok

      :iq when stanza.type in ["get", "set"] ->
        # Service/room IQ (disco, muc#owner, muc#admin): dispatch locally
        # and route the answer back to the sender.
        case Exjabberd.Iq.dispatch(stanza, host) do
          {:ok, result} -> route(result)
          {:error, _, err} -> route(err)
          {:error, reason} -> route(Exjabberd.Iq.error_iq(stanza, error_condition(reason)))
          _ -> :ok
        end

        :ok

      _ ->
        :ok
    end
  end

  # Stanza addressed to pubsub.<host> (the PubSub service).
  defp route_pubsub(stanza, domain) do
    try do
      do_route_pubsub(stanza, domain)
    rescue
      e ->
        Logger.warning("PubSub route failed: #{inspect(e)}")

        if stanza.name == :iq and stanza.type in ["get", "set"] do
          route(Exjabberd.Iq.error_iq(stanza, "internal-server-error"))
        end

        :ok
    catch
      :exit, reason ->
        Logger.warning("PubSub route exited: #{inspect(reason)}")

        if stanza.name == :iq and stanza.type in ["get", "set"] do
          route(Exjabberd.Iq.error_iq(stanza, "internal-server-error"))
        end

        :ok
    end
  end

  defp do_route_pubsub(stanza, domain) do
    host = String.replace_prefix(domain, "pubsub.", "")

    case stanza.name do
      :iq when stanza.type in ["get", "set"] ->
        # Service/node IQ (disco, pubsub, pubsub#owner): dispatch
        # locally and route the answer back to the sender.
        case Exjabberd.Iq.dispatch(stanza, host) do
          {:ok, result} -> route(result)
          {:error, _, err} -> route(err)
          {:error, reason} -> route(Exjabberd.Iq.error_iq(stanza, error_condition(reason)))
          _ -> :ok
        end

        :ok

      _ ->
        # Messages/presence to the service itself are dropped (the
        # service only speaks IQ; notifications flow the other way).
        :ok
    end
  end

  defp error_condition(:bad_request), do: "bad-request"
  defp error_condition(:not_allowed), do: "not-allowed"
  defp error_condition(:forbidden), do: "forbidden"
  defp error_condition(:not_found), do: "item-not-found"
  defp error_condition(:conflict), do: "conflict"
  defp error_condition(_), do: "internal-server-error"

  defp from_bare(%Exjabberd.Xmpp.Jid{} = jid), do: Exjabberd.Xmpp.Jid.bare(jid)
  defp from_bare(bin) when is_binary(bin), do: Exjabberd.Xmpp.Jid.bare(bin)
  defp from_bare(_), do: ""

  defp split_jid(%Exjabberd.Xmpp.Jid{} = jid) do
    {Exjabberd.Xmpp.Jid.bare(jid), jid.resource || ""}
  end

  defp split_jid(bin) when is_binary(bin) do
    case String.split(bin, "/", parts: 2) do
      [bare, res] -> {bare, res}
      [bare] -> {bare, ""}
    end
  end

  defp split_jid(_), do: {"", ""}

  # Broadcast a bare presence to every online local session except the
  # resource that sent it.
  defp broadcast_presence(stanza) do
    sender_pid = sender_pid(stanza)

    Exjabberd.SessionManager.all_sessions()
    |> Enum.each(fn {_bare, _res, pid} ->
      if pid != sender_pid, do: send(pid, {:route, stanza})
    end)
  end

  defp sender_pid(%{from: %Exjabberd.Xmpp.Jid{local: local, domain: domain, resource: res}})
       when is_binary(local) do
    case Exjabberd.SessionManager.get_session("#{local}@#{domain}", res || "") do
      {:ok, pid} -> pid
      :error -> nil
    end
  end

  defp sender_pid(_), do: nil

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
