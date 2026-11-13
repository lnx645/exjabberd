defmodule Exjabberd.Mqtt.Broker do
  @moduledoc """
  MQTT broker core for v3.1.1 and v5.0: subscriptions (plain and
  shared), retained messages, sessions, QoS 1/2 flows and delivery.

  One GenServer holds all broker state (single node — clustering is
  not implemented anywhere in this server yet). Connection processes
  talk to it via the calls below and receive deliveries as
  `{:mqtt_publish, packet}` messages; the connection owns the socket
  and the wire encoding.

  QoS 2 (exactly once) state:
  * inbound (publisher → broker): a PUBLISH is stored on first sight
    and answered with PUBREC; the matching PUBREL releases it — the
    message is published exactly once, and a duplicate PUBLISH with
    the same packet id is answered with PUBREC again without
    re-publishing (§4.3.3);
  * outbound (broker → subscriber): the PUBLISH is stored until the
    subscriber's PUBREC, answered with PUBREL, and cleared on PUBCOMP.

  Sessions:
  * v3.1.1: `clean_session: false` sessions keep subscriptions and
    undelivered QoS 1/2 messages across disconnects (queued, capped
    by `mqtt.max_queued`, oldest dropped first) and replay them on
    reconnect (§3.1.2.4); `clean_session: true` wipes on both ends.
  * v5.0: survival is governed by the Session Expiry Interval
    (CONNECT property, changeable at DISCONNECT): 0 ends the session
    at disconnect, a finite value schedules its deletion, and the
    Clean Start flag only decides whether a previous session is
    discarded at CONNECT time.
  * A second connection with the same client id takes over the
    session; `client_gone` calls carry the caller's pid and are
    ignored when the session has already been taken over, so a dying
    connection can never tear down its replacement's session.

  v5.0 extras: Will Delay (a Will is parked when the connection drops
  ungracefully and published when the delay elapses, when the session
  ends first, or never if the session is continued by a reconnect),
  Message Expiry (retained and queued messages die at their expiry;
  deliveries carry the remaining interval in their packet's
  `:expires_at`, which the connection turns into the wire property),
  subscription options (No Local, Retain As Published, Retain
  Handling), Subscription Identifiers (attached to deliveries as
  `:subscription_identifiers` properties) and Shared Subscriptions
  (`$share/<group>/<filter>` — one group member per publish,
  round-robin).

  Internal publish packets may carry `:properties` (v5 pass-through:
  payload format, content type, response topic, correlation data,
  user properties, subscription identifiers) and `:expires_at`
  (unix seconds); the v3.1.1 codec path ignores both.
  """

  use GenServer
  require Logger

  alias Exjabberd.Mqtt.{Bridge, Codec}

  @type client_id :: binary()

  defstruct subs: [],
            # client_id => %{pid, monitor, clean_session, session_expiry,
            #                session_token, username, will, next_packet_id, queued: []}
            clients: %{},
            # topic => {payload, qos, properties, expires_at | nil}
            retained: %{},
            # {client_id, packet_id} => publish packet (inbound QoS 2, stored)
            in_qos2: %{},
            # {client_id, packet_id} => :waiting_pubrec | :waiting_pubcomp (outbound QoS 2)
            out_qos2: %{},
            # client_id => %{will: will, gen: integer} (v5 delayed Will)
            pending_wills: %{},
            # {share_group, inner_filter} => round-robin counter
            share_rr: %{}

  def start_link(_opts), do: GenServer.start_link(__MODULE__, %__MODULE__{}, name: __MODULE__)

  @default_sub_opts %{no_local: false, retain_as_published: false, retain_handling: 0}

  # --- client API -----------------------------------------------------

  @doc """
  Register a connected client. Returns `{:ok, session_present}` or
  `{:error, :max_clients}`. `clean_session` is the wipe flag (v3
  Clean Session / v5 Clean Start); `opts` accepts `:username`,
  `:will` and `:session_expiry` (seconds, or `:infinity`; default
  derives from `clean_session`: 0 when clean, `:infinity` otherwise).
  """
  @spec register(client_id(), pid(), boolean(), keyword()) ::
          {:ok, boolean()} | {:error, :max_clients}
  def register(client_id, pid, clean_session, opts \\ []) do
    GenServer.call(__MODULE__, {:register, client_id, pid, clean_session, opts})
  end

  @doc """
  Subscribe `pid` (client `client_id`) to filters; returns the granted
  QoS per filter (0x80 = failure). Topics are `{filter, qos}` (v3) or
  `{filter, qos, sub_opts}` (v5); `opts` accepts
  `:subscription_identifier` (v5, applies to the whole packet).
  """
  @spec subscribe(client_id(), pid(), [tuple()], keyword()) :: [0..2 | 0x80]
  def subscribe(client_id, pid, topics, opts \\ []) do
    GenServer.call(__MODULE__, {:subscribe, client_id, pid, topics, opts})
  end

  @doc "Subscribe a bare pid with no client id (internal `mod_mqtt` use)."
  @spec subscribe_pid(pid(), binary(), 0..2) :: :ok
  def subscribe_pid(pid, filter, qos \\ 0) do
    GenServer.call(__MODULE__, {:subscribe_pid, pid, filter, qos})
  end

  @doc "Unsubscribe `client_id` from filters."
  @spec unsubscribe(client_id(), [binary()]) :: :ok
  def unsubscribe(client_id, topics) do
    GenServer.call(__MODULE__, {:unsubscribe, client_id, topics})
  end

  @doc """
  Unsubscribe and report a v5 reason code per filter
  (0x00 = success, 0x11 = no subscription existed).
  """
  @spec unsubscribe_codes(client_id(), [binary()]) :: [non_neg_integer()]
  def unsubscribe_codes(client_id, topics) do
    GenServer.call(__MODULE__, {:unsubscribe_codes, client_id, topics})
  end

  @doc """
  Publish a message. Delivers to matching subscribers, stores it when
  retained, queues it for offline persistent sessions, and (unless
  `from_bridge: true`) forwards it to the XMPP PubSub bridge.

  Extra `opts` (v5): `:from_client` (publisher client id, for
  No Local), `:properties` (pass-through property map),
  `:message_expiry` (seconds from now).
  """
  @spec publish(binary(), binary(), 0..2, boolean(), keyword()) ::
          :ok | {:error, :invalid_topic | :too_large}
  def publish(topic, payload, qos \\ 0, retain \\ false, opts \\ []) do
    GenServer.call(__MODULE__, {:publish, topic, payload, qos, retain, opts})
  end

  @doc "Publish this client's Will message immediately, if one was set."
  @spec publish_will(client_id()) :: :ok
  def publish_will(client_id), do: GenServer.call(__MODULE__, {:publish_will, client_id})

  @doc """
  The client is gone. `:clean` = it sent DISCONNECT (no Will);
  `:abnormal` = socket died (Will handling applies); `:disconnect_will`
  = v5 DISCONNECT with reason 0x04 (publish the Will now).

  `opts`: `:from_pid` — the calling connection's pid; the call is
  ignored when the session now belongs to a different pid (takeover).
  `:session_expiry` — v5 DISCONNECT property override (seconds or
  `:infinity`).
  """
  @spec client_gone(client_id(), :clean | :abnormal | :disconnect_will, keyword()) :: :ok
  def client_gone(client_id, reason, opts \\ []),
    do: GenServer.call(__MODULE__, {:client_gone, client_id, reason, opts})

  @doc "Inbound QoS 2: store a PUBLISH; `:duplicate` when this packet id was already stored."
  @spec store_in_qos2(client_id(), non_neg_integer(), map()) :: :ok | :duplicate
  def store_in_qos2(client_id, packet_id, packet) do
    GenServer.call(__MODULE__, {:store_in_qos2, client_id, packet_id, packet})
  end

  @doc "Inbound QoS 2: release a stored PUBLISH on PUBREL; returns the packet or `:error`."
  @spec release_in_qos2(client_id(), non_neg_integer()) :: {:ok, map()} | :error
  def release_in_qos2(client_id, packet_id) do
    GenServer.call(__MODULE__, {:release_in_qos2, client_id, packet_id})
  end

  @doc "Outbound QoS 2: the subscriber answered our PUBLISH with PUBREC."
  @spec out_qos2_pubrec(client_id(), non_neg_integer()) :: :ok | :error
  def out_qos2_pubrec(client_id, packet_id) do
    GenServer.call(__MODULE__, {:out_qos2_pubrec, client_id, packet_id})
  end

  @doc "Outbound QoS 2: the subscriber answered our PUBREL with PUBCOMP."
  @spec out_qos2_pubcomp(client_id(), non_neg_integer()) :: :ok | :error
  def out_qos2_pubcomp(client_id, packet_id) do
    GenServer.call(__MODULE__, {:out_qos2_pubcomp, client_id, packet_id})
  end

  @doc "Number of connected clients."
  @spec client_count() :: non_neg_integer()
  def client_count, do: GenServer.call(__MODULE__, :client_count)

  @doc "Connected client ids (debug/admin)."
  @spec list_clients() :: [client_id()]
  def list_clients, do: GenServer.call(__MODULE__, :list_clients)

  @doc "Retained message for a topic, or `nil`."
  @spec retained(binary()) :: {binary(), 0..2} | nil
  def retained(topic), do: GenServer.call(__MODULE__, {:retained, topic})

  # --- server ---------------------------------------------------------

  @impl true
  def init(state), do: {:ok, state}

  @impl true
  def handle_call({:register, client_id, pid, clean_session, opts}, _from, state) do
    max_clients = Exjabberd.Mqtt.config(:max_clients, 1000)
    existing = Map.get(state.clients, client_id)

    if existing == nil and map_size(state.clients) >= max_clients do
      {:reply, {:error, :max_clients}, state}
    else
      {state, session_present} = take_over(state, client_id, existing, clean_session)
      old_queued = if session_present, do: Map.get(existing, :queued, []), else: []

      # A parked delayed Will dies when its session is continued by
      # this reconnect; when the session is NOT continued (wiped or
      # brand new), the old session is over and the Will goes out.
      state = settle_pending_will_on_register(state, client_id, session_present)

      monitor = Process.monitor(pid)

      session_expiry =
        Keyword.get(opts, :session_expiry, if(clean_session, do: 0, else: :infinity))

      client = %{
        pid: pid,
        monitor: monitor,
        clean_session: clean_session,
        session_expiry: session_expiry,
        session_token: nil,
        username: Keyword.get(opts, :username),
        will: Keyword.get(opts, :will),
        next_packet_id: 1,
        queued: []
      }

      state = %{state | clients: Map.put(state.clients, client_id, client)}

      state =
        if session_present do
          # Reconnect to a persistent session: subscriptions now
          # point at the new connection pid, and the queued offline
          # messages are replayed with fresh packet ids (§3.1.2.4).
          subs =
            Enum.map(state.subs, fn sub ->
              if sub.client_id == client_id, do: %{sub | pid: pid}, else: sub
            end)

          state = %{state | subs: subs}
          now = now_s()

          Enum.reduce(old_queued, state, fn packet, acc ->
            if expired?(packet, now) do
              acc
            else
              {packet, acc} = assign_packet_id(acc, client_id, packet)
              send(pid, {:mqtt_publish, packet})
              acc
            end
          end)
        else
          state
        end

      {:reply, {:ok, session_present}, state}
    end
  end

  def handle_call({:subscribe, client_id, pid, topics, opts}, _from, state) do
    state = purge_expired_retained(state)
    sub_id = Keyword.get(opts, :subscription_identifier)

    {granted, state} =
      Enum.map_reduce(topics, state, fn topic_tuple, acc ->
        {raw_filter, requested_qos, sub_opts} = normalize_topic(topic_tuple)

        {shared, inner} =
          case Codec.shared_parts(raw_filter) do
            {:ok, group, inner_filter} -> {group, inner_filter}
            _ -> {nil, raw_filter}
          end

        cond do
          not Codec.valid_filter?(raw_filter) ->
            {0x80, acc}

          requested_qos > 2 ->
            {0x80, acc}

          true ->
            existed =
              Enum.any?(acc.subs, &(&1.pid == pid and &1.raw_filter == raw_filter))

            sub = %{
              filter: inner,
              raw_filter: raw_filter,
              pid: pid,
              qos: requested_qos,
              client_id: client_id,
              opts: sub_opts,
              sub_id: sub_id,
              shared: shared
            }

            acc = %{acc | subs: [sub | Enum.reject(acc.subs, &same_sub?(&1, sub))]}

            # Retained messages matching a new subscription are
            # delivered immediately (§3.3.1.2), subject to the v5
            # Retain Handling option (0 = always, 1 = only when the
            # subscription is new, 2 = never at subscribe time).
            acc =
              if sub_opts.retain_handling == 2 or
                   (sub_opts.retain_handling == 1 and existed) do
                acc
              else
                Enum.reduce(acc.retained, acc, fn {rtopic, retained_entry}, acc2 ->
                  {payload, retained_qos, props, expires_at} = retained_entry

                  if Codec.matches?(inner, rtopic) do
                    {packet, acc3} =
                      retained_packet(acc2, client_id, rtopic, payload, retained_qos,
                        requested_qos, props, expires_at)

                    send(pid, {:mqtt_publish, packet})
                    acc3
                  else
                    acc2
                  end
                end)
              end

            {requested_qos, acc}
        end
      end)

    {:reply, granted, state}
  end

  def handle_call({:subscribe_pid, pid, filter, qos}, _from, state) do
    sub = %{
      filter: filter,
      raw_filter: filter,
      pid: pid,
      qos: qos,
      client_id: nil,
      opts: @default_sub_opts,
      sub_id: nil,
      shared: nil
    }

    state = %{state | subs: [sub | Enum.reject(state.subs, &same_sub?(&1, sub))]}
    {:reply, :ok, state}
  end

  def handle_call({:unsubscribe, client_id, topics}, _from, state) do
    {:reply, :ok, do_unsubscribe(state, client_id, topics)}
  end

  def handle_call({:unsubscribe_codes, client_id, topics}, _from, state) do
    codes =
      Enum.map(topics, fn topic ->
        if Enum.any?(state.subs, &(&1.client_id == client_id and &1.raw_filter == topic)) do
          0x00
        else
          0x11
        end
      end)

    {:reply, codes, do_unsubscribe(state, client_id, topics)}
  end

  def handle_call({:publish, topic, payload, qos, retain, opts}, _from, state) do
    case do_publish(state, topic, payload, qos, retain, opts) do
      {:ok, state} -> {:reply, :ok, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:publish_will, client_id}, _from, state) do
    case get_in(state.clients, [client_id, :will]) do
      %{topic: _} = will -> {:reply, :ok, publish_will_now(state, will)}
      _ -> {:reply, :ok, state}
    end
  end

  def handle_call({:client_gone, client_id, reason, opts}, _from, state) do
    {:reply, :ok, process_gone(state, client_id, reason, opts)}
  end

  def handle_call({:store_in_qos2, client_id, packet_id, packet}, _from, state) do
    key = {client_id, packet_id}

    if Map.has_key?(state.in_qos2, key) do
      {:reply, :duplicate, state}
    else
      {:reply, :ok, %{state | in_qos2: Map.put(state.in_qos2, key, packet)}}
    end
  end

  def handle_call({:release_in_qos2, client_id, packet_id}, _from, state) do
    key = {client_id, packet_id}

    case Map.pop(state.in_qos2, key) do
      {nil, _} -> {:reply, :error, state}
      {packet, rest} -> {:reply, {:ok, packet}, %{state | in_qos2: rest}}
    end
  end

  def handle_call({:out_qos2_pubrec, client_id, packet_id}, _from, state) do
    key = {client_id, packet_id}

    case Map.get(state.out_qos2, key) do
      :waiting_pubrec ->
        state = %{state | out_qos2: Map.put(state.out_qos2, key, :waiting_pubcomp)}
        {:reply, :ok, state}

      _ ->
        {:reply, :error, state}
    end
  end

  def handle_call({:out_qos2_pubcomp, client_id, packet_id}, _from, state) do
    key = {client_id, packet_id}

    case Map.get(state.out_qos2, key) do
      :waiting_pubcomp ->
        {:reply, :ok, %{state | out_qos2: Map.delete(state.out_qos2, key)}}

      _ ->
        {:reply, :error, state}
    end
  end

  def handle_call(:client_count, _from, state), do: {:reply, map_size(state.clients), state}

  def handle_call(:list_clients, _from, state),
    do: {:reply, state.clients |> Map.keys() |> Enum.sort(), state}

  def handle_call({:retained, topic}, _from, state) do
    case Map.get(state.retained, topic) do
      {payload, qos, _props, expires_at} ->
        if expires_at != nil and expires_at <= now_s() do
          {:reply, nil, state}
        else
          {:reply, {payload, qos}, state}
        end

      nil ->
        {:reply, nil, state}
    end
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, _reason}, state) do
    # A connection process died without unregistering (crash): treat
    # it as an abnormal disconnect — Will first, then drop/keep the
    # session exactly like a socket failure.
    client_id =
      Enum.find_value(state.clients, fn {cid, client} ->
        if client.pid == pid, do: cid
      end)

    state =
      if client_id do
        process_gone(state, client_id, :abnormal, from_pid: pid)
      else
        # A bare-pid subscriber (mod_mqtt API, client_id nil) died:
        # drop its subs. Subscriptions owned by a session (client_id
        # set) are never dropped here — a persistent session keeps
        # them even after its connection process is gone.
        %{state | subs: Enum.reject(state.subs, &(&1.pid == pid and &1.client_id == nil))}
      end

    {:noreply, state}
  end

  def handle_info({:delayed_will, client_id, gen}, state) do
    state =
      case Map.get(state.pending_wills, client_id) do
        %{gen: ^gen, will: will} ->
          state = %{state | pending_wills: Map.delete(state.pending_wills, client_id)}
          publish_will_now(state, will)

        _ ->
          state
      end

    {:noreply, state}
  end

  def handle_info({:expire_session, client_id, token}, state) do
    state =
      case Map.get(state.clients, client_id) do
        %{pid: nil, session_token: ^token} ->
          # The session ends now: a still-parked Will goes out first
          # (its delay yields to the session end, §3.1.2.5).
          state =
            case Map.pop(state.pending_wills, client_id) do
              {nil, _} -> state
              {%{will: will}, pending} -> publish_will_now(%{state | pending_wills: pending}, will)
            end

          full_drop(state, client_id)

        _ ->
          state
      end

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # --- session lifecycle ------------------------------------------------

  defp take_over(state, _client_id, nil, _clean_session), do: {state, false}

  defp take_over(state, client_id, existing, clean_session) do
    # Tell the old connection to close (no Will — this is a session
    # takeover, not a failure) and drop its monitor. An offline
    # persistent session has no live pid to tell.
    if is_pid(existing.pid) do
      send(existing.pid, :mqtt_takeover)
    end

    Process.demonitor(existing.monitor, [:flush])

    if clean_session do
      {full_drop(state, client_id), false}
    else
      # Persistent session survives: keep subscriptions, queued
      # messages and QoS 2 state; the new connection resumes it.
      {state, true}
    end
  end

  defp full_drop(state, client_id) do
    %{
      state
      | subs: Enum.reject(state.subs, &(&1.client_id == client_id)),
        in_qos2: Map.reject(state.in_qos2, fn {{cid, _}, _} -> cid == client_id end),
        out_qos2: Map.reject(state.out_qos2, fn {{cid, _}, _} -> cid == client_id end),
        clients: Map.delete(state.clients, client_id)
    }
  end

  defp process_gone(state, client_id, reason, opts) do
    case Map.get(state.clients, client_id) do
      nil ->
        state

      client ->
        from_pid = Keyword.get(opts, :from_pid)

        if from_pid != nil and client.pid != from_pid do
          # Stale connection: the session was taken over (or already
          # processed); the replacement connection owns it now.
          state
        else
          client =
            case Keyword.get(opts, :session_expiry) do
              nil -> client
              expiry -> %{client | session_expiry: expiry}
            end

          state = %{state | clients: Map.put(state.clients, client_id, client)}
          state = settle_will(state, client_id, client, reason)
          drop_client(state, client_id)
        end
    end
  end

  # Will handling at disconnect time. `:clean` (a DISCONNECT packet)
  # discards the Will in both protocol versions; v5 DISCONNECT with
  # reason 0x04 publishes it at once; an ungraceful loss publishes it
  # immediately unless a Will Delay applies *and* the session outlives
  # the connection — when the session ends with the disconnect, the
  # Will goes out with it (§3.1.2.5).
  defp settle_will(state, _client_id, %{will: nil}, _reason), do: state

  defp settle_will(state, _client_id, _client, :clean), do: state

  defp settle_will(state, _client_id, %{will: will}, :disconnect_will) do
    publish_will_now(state, will)
  end

  defp settle_will(state, client_id, %{will: will} = client, :abnormal) do
    delay = Map.get(will, :delay, 0)

    cond do
      client.session_expiry == 0 -> publish_will_now(state, will)
      delay > 0 -> park_will(state, client_id, will, delay)
      true -> publish_will_now(state, will)
    end
  end

  defp settle_will(state, _client_id, _client, _reason), do: state

  defp park_will(state, client_id, will, delay) do
    gen = System.unique_integer([:positive])
    Process.send_after(self(), {:delayed_will, client_id, gen}, delay * 1000)
    %{state | pending_wills: Map.put(state.pending_wills, client_id, %{will: will, gen: gen})}
  end

  defp settle_pending_will_on_register(state, client_id, session_present) do
    case Map.pop(state.pending_wills, client_id) do
      {nil, _} ->
        state

      {_pending, _} when session_present ->
        %{state | pending_wills: Map.delete(state.pending_wills, client_id)}

      {%{will: will}, _} ->
        state = %{state | pending_wills: Map.delete(state.pending_wills, client_id)}
        publish_will_now(state, will)
    end
  end

  defp publish_will_now(state, will) do
    case do_publish(state, will.topic, will.payload, will.qos, will.retain,
           from_bridge: false,
           properties: Map.get(will, :properties, %{}),
           message_expiry: Map.get(will, :message_expiry)
         ) do
      {:ok, state} -> state
      {:error, _} -> state
    end
  end

  defp drop_client(state, client_id) do
    case Map.get(state.clients, client_id) do
      nil ->
        state

      client ->
        Process.demonitor(client.monitor, [:flush])

        if client.session_expiry == 0 do
          full_drop(state, client_id)
        else
          # Session survives the connection: subscriptions stay, the
          # pid is gone, and a finite expiry schedules the session's
          # deletion.
          token = make_ref()

          if is_integer(client.session_expiry) do
            Process.send_after(
              self(),
              {:expire_session, client_id, token},
              client.session_expiry * 1000
            )
          end

          %{state | clients: Map.put(state.clients, client_id, %{client | pid: nil, session_token: token})}
        end
    end
  end

  # --- publish / delivery -------------------------------------------------

  defp do_publish(state, topic, payload, qos, retain, opts) do
    expires_at =
      case Keyword.get(opts, :message_expiry) do
        nil -> nil
        seconds -> now_s() + seconds
      end

    cond do
      not Codec.valid_topic?(topic) ->
        {:error, :invalid_topic}

      byte_size(payload) > Exjabberd.Mqtt.config(:max_payload, 262_144) ->
        {:error, :too_large}

      expires_at != nil and expires_at <= now_s() ->
        # Already expired (Message Expiry Interval 0): drop silently.
        {:ok, state}

      true ->
        props = Keyword.get(opts, :properties, %{})

        state =
          if retain do
            retained =
              if payload == "" do
                Map.delete(state.retained, topic)
              else
                Map.put(state.retained, topic, {payload, qos, props, expires_at})
              end

            %{state | retained: retained}
          else
            state
          end

        meta = %{
          from_client: Keyword.get(opts, :from_client),
          properties: props,
          expires_at: expires_at
        }

        state = deliver(state, topic, payload, qos, retain, meta)

        unless Keyword.get(opts, :from_bridge, false) do
          Bridge.mqtt_to_pubsub(topic, payload)
        end

        {:ok, state}
    end
  end

  defp deliver(state, topic, payload, qos, retain, meta) do
    matching =
      Enum.filter(state.subs, fn sub ->
        Codec.matches?(sub.filter, topic) and
          not (meta.from_client != nil and sub.client_id == meta.from_client and
                 sub.opts.no_local)
      end)

    {shared_subs, plain_subs} = Enum.split_with(matching, &(&1.shared != nil))

    # One contribution per pid: highest QoS across its matching
    # filters, Retain As Published if any contributing subscription
    # asks for it, and the union of subscription identifiers.
    contributions =
      Enum.reduce(plain_subs, %{}, fn sub, acc -> add_contribution(acc, sub) end)

    {contributions, state} =
      shared_subs
      |> Enum.group_by(fn sub -> {sub.shared, sub.filter} end)
      |> Enum.reduce({contributions, state}, fn {key, group_subs}, {cacc, sacc} ->
        pids = group_subs |> Enum.map(& &1.pid) |> Enum.uniq() |> Enum.sort()
        idx = Map.get(sacc.share_rr, key, 0)
        chosen = Enum.at(pids, rem(idx, length(pids)))
        sacc = %{sacc | share_rr: Map.put(sacc.share_rr, key, idx + 1)}

        cacc =
          group_subs
          |> Enum.filter(&(&1.pid == chosen))
          |> Enum.reduce(cacc, fn sub, a -> add_contribution(a, sub) end)

        {cacc, sacc}
      end)

    state =
      Enum.reduce(contributions, state, fn {pid, contrib}, acc ->
        {packet, acc} =
          deliver_to(acc, contrib, topic, payload, qos, retain, meta)

        if packet, do: send(pid, {:mqtt_publish, packet})
        acc
      end)

    # Offline persistent sessions with a matching plain subscription
    # get QoS 1/2 messages queued (§3.1.2.4). Shared subscriptions are
    # excluded: the group's copy belongs to a connected member.
    state =
      Enum.reduce(state.clients, state, fn {cid, client}, acc ->
        offline_subs =
          Enum.filter(acc.subs, fn sub ->
            sub.client_id == cid and sub.shared == nil and
              Codec.matches?(sub.filter, topic) and
              not (meta.from_client == cid and sub.opts.no_local)
          end)

        if client.pid == nil and client.session_expiry != 0 and qos >= 1 and
             offline_subs != [] do
          max_queued = Exjabberd.Mqtt.config(:max_queued, 100)
          sub_qos = offline_subs |> Enum.map(& &1.qos) |> Enum.max()

          sub_ids =
            offline_subs |> Enum.map(& &1.sub_id) |> Enum.reject(&is_nil/1) |> Enum.uniq()

          packet =
            publish_packet(
              min(qos, sub_qos),
              topic,
              nil,
              payload,
              false,
              delivery_props(meta, sub_ids),
              meta.expires_at
            )

          queued = Enum.take(client.queued ++ [packet], -max_queued)
          %{acc | clients: Map.put(acc.clients, cid, %{client | queued: queued})}
        else
          acc
        end
      end)

    state
  end

  defp add_contribution(acc, sub) do
    entry = %{
      pid: sub.pid,
      client_id: sub.client_id,
      qos: sub.qos,
      rap: sub.opts.retain_as_published,
      sub_ids: List.wrap(sub.sub_id)
    }

    Map.update(acc, sub.pid, entry, fn existing ->
      %{
        existing
        | qos: max(existing.qos, sub.qos),
          rap: existing.rap or sub.opts.retain_as_published,
          sub_ids: Enum.uniq(existing.sub_ids ++ List.wrap(sub.sub_id))
      }
    end)
  end

  defp delivery_props(meta, sub_ids) do
    if sub_ids == [] do
      meta.properties
    else
      Map.put(meta.properties, :subscription_identifiers, sub_ids)
    end
  end

  # Build the packet for one subscriber; returns `{packet_or_nil, state}`.
  # QoS 2 delivery needs a packet id + outbound tracking; QoS 0/1 need
  # an id only for QoS 1.
  defp deliver_to(state, contrib, topic, payload, pub_qos, retain, meta) do
    effective_qos = min(pub_qos, contrib.qos)
    retain_flag = contrib.rap and retain
    props = delivery_props(meta, contrib.sub_ids)
    cid = contrib.client_id

    case effective_qos do
      0 ->
        {publish_packet(0, topic, nil, payload, retain_flag, props, meta.expires_at), state}

      1 ->
        {state, packet_id} = next_packet_id(state, cid || pid_key(contrib.pid))

        {publish_packet(1, topic, packet_id, payload, retain_flag, props, meta.expires_at),
         state}

      2 ->
        {state, packet_id} = next_packet_id(state, cid || pid_key(contrib.pid))
        state = %{state | out_qos2: Map.put(state.out_qos2, {cid || pid_key(contrib.pid), packet_id}, :waiting_pubrec)}

        {publish_packet(2, topic, packet_id, payload, retain_flag, props, meta.expires_at),
         state}
    end
  end

  defp publish_packet(qos, topic, packet_id, payload, retain, props, expires_at) do
    packet = %{
      type: :publish,
      dup: false,
      qos: qos,
      retain: retain,
      topic: topic,
      packet_id: packet_id,
      payload: payload
    }

    packet = if props == %{}, do: packet, else: Map.put(packet, :properties, props)
    if expires_at == nil, do: packet, else: Map.put(packet, :expires_at, expires_at)
  end

  # Retained delivery on SUBSCRIBE: same shape as a live delivery,
  # with the retain flag set; QoS 1/2 needs a real packet id.
  defp retained_packet(state, client_id, topic, payload, retained_qos, requested_qos, props, expires_at) do
    qos = min(retained_qos, requested_qos)

    if qos == 0 do
      {publish_packet(0, topic, nil, payload, true, props, expires_at), state}
    else
      {state, packet_id} = next_packet_id(state, client_id)

      state =
        if qos == 2 do
          %{state | out_qos2: Map.put(state.out_qos2, {client_id, packet_id}, :waiting_pubrec)}
        else
          state
        end

      {publish_packet(qos, topic, packet_id, payload, true, props, expires_at), state}
    end
  end

  defp next_packet_id(state, key) do
    case Map.get(state.clients, key) do
      nil ->
        {state, 1}

      client ->
        id = client.next_packet_id
        next = if id >= 65_535, do: 1, else: id + 1
        {%{state | clients: Map.put(state.clients, key, %{client | next_packet_id: next})}, id}
    end
  end

  # Give a queued (offline) packet a fresh packet id on replay; QoS 2
  # replays are tracked like any other outbound QoS 2 delivery.
  defp assign_packet_id(state, _client_id, %{qos: 0} = packet), do: {packet, state}

  defp assign_packet_id(state, client_id, packet) do
    {state, packet_id} = next_packet_id(state, client_id)

    state =
      if packet.qos == 2 do
        %{state | out_qos2: Map.put(state.out_qos2, {client_id, packet_id}, :waiting_pubrec)}
      else
        state
      end

    {%{packet | packet_id: packet_id}, state}
  end

  # --- helpers ------------------------------------------------------------

  defp normalize_topic({filter, qos}), do: {filter, qos, @default_sub_opts}
  defp normalize_topic({filter, qos, opts}), do: {filter, qos, Map.merge(@default_sub_opts, opts)}

  defp do_unsubscribe(state, client_id, topics) do
    subs =
      Enum.reject(state.subs, fn sub ->
        sub.client_id == client_id and sub.raw_filter in topics
      end)

    %{state | subs: subs}
  end

  defp purge_expired_retained(state) do
    now = now_s()

    retained =
      Map.filter(state.retained, fn {_topic, {_p, _q, _props, expires_at}} ->
        expires_at == nil or expires_at > now
      end)

    %{state | retained: retained}
  end

  defp expired?(packet, now), do: Map.get(packet, :expires_at) != nil and packet.expires_at <= now

  defp now_s, do: System.os_time(:second)

  defp pid_key(pid), do: inspect(pid)

  defp same_sub?(a, b), do: a.raw_filter == b.raw_filter and a.pid == b.pid
end
