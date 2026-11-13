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

  @doc "Unregister route (ejabberd_router:unregister_route). The cluster mirror entry is only removed when it still points at the pid this node registered, so one node's teardown never removes another node's live route for the same JID."
  @spec unregister_route(binary()) :: :ok
  def unregister_route(domain_or_jid) do
    pid =
      case :ets.lookup(__MODULE__, domain_or_jid) do
        [{_, p, _}] -> p
        [] -> nil
      end

    :ets.delete(__MODULE__, domain_or_jid)
    :ets.delete(:exjabberd_router_cache, domain_or_jid)
    Exjabberd.Cluster.unregister_route(domain_or_jid, pid)
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
    # Bare presence (no `to`): the user announcing themselves. It is
    # fanned out to the sender's own sessions plus every contact
    # subscribed to the sender's presence (roster items `from` /
    # `both`) — RFC 6121 §4.2/§4.5, like ejabberd. It is never
    # broadcast to unrelated users.
    broadcast_presence(stanza)
    :ok
  end

  def route(%{to: nil} = stanza) do
    Exjabberd.Hooks.run(:route, "global", stanza)
    :ok
  end

  def route(%{to: to} = stanza) do
    # XEP-0016 / XEP-0191 enforcement point: every stanza addressed
    # to a local user passes the recipient's privacy/block lists in
    # the router, so online delivery, offline storage and inbound
    # S2S are all covered (ejabberd runs mod_privacy on the
    # filter_packet hook in its router).
    case privacy_verdict(stanza) do
      :deny -> deny_stanza(stanza)
      :allow -> route_checked(stanza, to)
    end
  end

  defp privacy_verdict(%{name: name} = stanza) when name in [:message, :presence, :iq] do
    case stanza.to do
      %Exjabberd.Xmpp.Jid{local: local, domain: domain}
      when is_binary(local) and local != "" ->
        if my_host?(domain) do
          case Exjabberd.Hooks.run(:privacy_check_packet, domain, stanza) do
            :deny -> :deny
            _ -> :allow
          end
        else
          :allow
        end

      _ ->
        :allow
    end
  end

  defp privacy_verdict(_stanza), do: :allow

  defp deny_stanza(%{name: :iq, type: type} = stanza) when type in ["get", "set"] do
    # XEP-0191: a blocked IQ is answered with service-unavailable.
    route_error(stanza, "service-unavailable")
    :ok
  end

  defp deny_stanza(_stanza), do: :ok

  defp route_checked(stanza, to) do
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

              mix_domain?(domain) ->
                route_mix(stanza, domain)

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

  @doc "True when `domain` is the `mix.` service of a local host."
  @spec mix_domain?(binary()) :: boolean()
  def mix_domain?(domain) when is_binary(domain) do
    case domain do
      "mix." <> base -> my_host?(base)
      _ -> false
    end
  end

  def mix_domain?(_), do: false

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
        cond do
          stanza.type == "unavailable" ->
            Exjabberd.Mod.Muc.leave(host, bare, from_bare, resource)
            :ok

          stanza.type in [nil, "available"] ->
            # XEP-0045 join: the room password travels in
            # <x xmlns='http://jabber.org/protocol/muc'><password/>.
            password =
              case Exjabberd.Xmpp.Stanza.child(stanza.payload, "x") do
                nil -> nil
                x -> Exjabberd.Xmpp.Stanza.child_text(x.children, "password")
              end

            case Exjabberd.Mod.Muc.join(host, bare, from_bare, resource, password: password) do
              :ok -> :ok
              {:error, condition} -> route_presence_error(stanza, condition)
              _ -> :ok
            end

          true ->
            :ok
        end

      :message ->
        subject_el = Exjabberd.Xmpp.Stanza.child(stanza.payload, "subject")

        cond do
          stanza.type in ["groupchat", nil] and subject_el != nil ->
            Exjabberd.Mod.Muc.set_subject(
              host,
              bare,
              from_bare,
              Exjabberd.Xmpp.Stanza.text_of(subject_el)
            )

            :ok

          stanza.type in ["groupchat", nil] ->
            body = Exjabberd.Xmpp.Stanza.child_text(stanza.payload, "body") || ""
            Exjabberd.Mod.Muc.send_message(host, bare, from_bare, body)
            :ok

          true ->
            :ok
        end

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

  # Answer a failed MUC join with a presence error (XEP-0045 §7.2):
  # from the room/nick the user tried to join, with the XMPP error
  # condition for the refusal reason.
  defp route_presence_error(stanza, condition) do
    {name, etype} =
      case condition do
        :forbidden -> {"forbidden", "auth"}
        :registration_required -> {"registration-required", "auth"}
        :not_authorized -> {"not-authorized", "auth"}
        :conflict -> {"conflict", "cancel"}
        :resource_constraint -> {"resource-constraint", "wait"}
        _ -> {"service-unavailable", "cancel"}
      end

    err = %{
      stanza
      | type: "error",
        from: stanza.to,
        to: stanza.from,
        payload: [
          %{
            name: "error",
            attrs: %{"type" => etype},
            children: [
              %{
                name: name,
                attrs: %{"xmlns" => "urn:ietf:params:xml:ns:xmpp-stanzas"},
                children: []
              }
            ]
          }
        ]
    }

    route(err)
    :ok
  end

  # Stanza addressed to mix.<host> or to a MIX channel
  # (channel@mix.<host>) — XEP-0369.
  defp route_mix(stanza, domain) do
    host = String.replace_prefix(domain, "mix.", "")
    bare = from_bare(stanza.to)
    from_bare_jid = from_bare(stanza.from)

    case stanza.name do
      :iq when stanza.type in ["get", "set"] ->
        # Participants retrieval is a PubSub-shaped IQ the generic
        # PubSub handler cannot resolve for channels.
        result =
          if bare != domain and Exjabberd.Mod.Mix.participants_query?(stanza) do
            # Iq.dispatch normally swaps from/to on results; this
            # direct call must do it itself.
            case Exjabberd.Mod.Mix.participants_iq(stanza, host) do
              {:ok, %{type: "result"} = res} ->
                {:ok, %{res | from: stanza.to || host, to: stanza.from}}

              other ->
                other
            end
          else
            Exjabberd.Iq.dispatch(stanza, host)
          end

        case result do
          {:ok, res} -> route(res)
          {:error, _, err} -> route(err)
          {:error, reason} -> route(Exjabberd.Iq.error_iq(stanza, error_condition(reason)))
          _ -> :ok
        end

        :ok

      :message ->
        if stanza.type in ["groupchat", nil] do
          body = Exjabberd.Xmpp.Stanza.child_text(stanza.payload, "body") || ""
          Exjabberd.Mod.Mix.send_message(host, bare, from_bare_jid, body)
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

      :message ->
        # The one message the service consumes: a subscription
        # authorization reply (XEP-0060 §6.5). Anything else
        # addressed to the service is dropped.
        if Exjabberd.Mod.PubSub.authorization_reply?(stanza) do
          Exjabberd.Mod.PubSub.handle_authorization_reply(stanza, host, nil)
        end

        :ok

      _ ->
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

  # --- presence state + fanout (RFC 6121) ---

  @presence_table :exjabberd_presence_state

  defp ensure_presence_table do
    if :ets.whereis(@presence_table) == :undefined do
      # Race-safe lazy creation: the fanout runs inside many C2S
      # processes at once, so two of them can both see :undefined.
      try do
        :ets.new(@presence_table, [
          :named_table,
          :public,
          :set,
          read_concurrency: true,
          write_concurrency: true
        ])
      rescue
        ArgumentError -> @presence_table
      end
    end

    @presence_table
  end

  @doc "Last recorded available-presence stanzas of a user's sessions (keyed by full JID)."
  @spec recorded_presences(binary()) :: [map()]
  def recorded_presences(bare) do
    ensure_presence_table()
    prefix = String.downcase(bare) <> "/"

    :ets.tab2list(@presence_table)
    |> Enum.filter(fn {full, _stanza} -> String.starts_with?(full, prefix) end)
    |> Enum.map(fn {_full, stanza} -> stanza end)
  end

  @doc "Whether this full JID has an available presence on record."
  @spec presence_recorded?(term()) :: boolean()
  def presence_recorded?(%Exjabberd.Xmpp.Jid{} = jid) do
    ensure_presence_table()
    :ets.member(@presence_table, Exjabberd.Xmpp.Jid.to_string(jid))
  end

  def presence_recorded?(_), do: false

  # Fan a bare presence out: the sender's own sessions + the
  # sessions of every contact subscribed to the sender's presence.
  # The last available presence per full JID is recorded so that
  # initial presence (and subscription approvals) can replay the
  # current presence of subscribed contacts without probes.
  defp broadcast_presence(%{from: %Exjabberd.Xmpp.Jid{} = from} = stanza) do
    ensure_presence_table()
    sender_bare = Exjabberd.Xmpp.Jid.bare(from)
    host = from.domain
    user = from.local
    full = Exjabberd.Xmpp.Jid.to_string(from)
    sender_pid = sender_pid(stanza)

    initial? =
      case stanza.type do
        "unavailable" ->
          :ets.delete(@presence_table, full)
          false

        nil ->
          first = not :ets.member(@presence_table, full)
          :ets.insert(@presence_table, {full, stanza})
          first

        _ ->
          false
      end

    if stanza.type in [nil, "unavailable"] do
      roster = Exjabberd.Mod.Roster.get_roster(host, user)
      bare_to = %Exjabberd.Xmpp.Jid{local: user, domain: host}

      # Recipients as {pid, recipient_bare} — each delivered copy is
      # addressed to its own recipient, like ejabberd does.
      own =
        Exjabberd.SessionManager.get_sessions(sender_bare, host)
        |> Enum.map(fn {_res, pid, _prio} -> {pid, sender_bare} end)

      subscribed_contacts =
        roster
        |> Enum.filter(fn item -> Map.get(item, :subscription) in [:from, :both] end)
        |> Enum.flat_map(fn item ->
          Exjabberd.SessionManager.get_sessions(item.jid, host)
          |> Enum.map(fn {_res, pid, _prio} -> {pid, item.jid} end)
        end)

      (own ++ subscribed_contacts)
      |> Enum.uniq_by(fn {pid, _bare} -> pid end)
      |> Enum.each(fn {pid, bare} ->
        if pid != sender_pid do
          [u, h] = String.split(bare, "@", parts: 2)
          send(pid, {:route, %{stanza | to: %Exjabberd.Xmpp.Jid{local: u, domain: h}}})
        end
      end)

      # Initial presence: replay the recorded presence of every
      # contact the sender subscribes to (`to`/`both` items).
      if initial? and not is_nil(sender_pid) do
        roster
        |> Enum.filter(fn item -> Map.get(item, :subscription) in [:to, :both] end)
        |> Enum.flat_map(fn item -> recorded_presences(item.jid) end)
        |> Enum.each(fn pres -> send(sender_pid, {:route, %{pres | to: bare_to}}) end)
      end
    end

    :ok
  end

  # Non-JID senders (should not occur for client presence): keep the
  # legacy behaviour of reaching the sender's own sessions only.
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
            lookup_mirror(jid)
        end
    end
  end

  # Cluster mirror — may point at a session on another node.
  # Remote pids need the :rpc liveness probe: Process.alive?
  # raises ArgumentError on them.
  defp lookup_mirror(jid) do
    case Exjabberd.Cluster.lookup_route(jid) do
      {:ok, pid, _} ->
        if Exjabberd.Cluster.alive?(pid) do
          {:ok, pid}
        else
          Exjabberd.Cluster.unregister_route(jid, pid)
          :error
        end

      :error ->
        :error
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
