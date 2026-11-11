defmodule Exjabberd.Mqtt.Broker do
  @moduledoc """
  MQTT v3.1.1 broker core: subscriptions, retained messages, sessions
  (clean / persistent), QoS 1/2 flows and delivery.

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

  Persistent sessions (`clean_session: false`): subscriptions and
  undelivered QoS 1/2 messages survive a disconnect (queued, capped
  by `mqtt.max_queued`, oldest dropped first) and are replayed on
  reconnect with the same client id (§3.1.2.4). A reconnect with
  `clean_session: true` wipes the old session. A second connection
  with the same client id takes over the session: the old connection
  is told to close (`:mqtt_takeover`).
  """

  use GenServer
  require Logger

  alias Exjabberd.Mqtt.{Bridge, Codec}

  @type client_id :: binary()

  defstruct subs: [],
            # client_id => %{pid, monitor, clean_session, username, next_packet_id, queued: []}
            clients: %{},
            retained: %{},
            # {client_id, packet_id} => publish packet (inbound QoS 2, stored)
            in_qos2: %{},
            # {client_id, packet_id} => :waiting_pubrec | :waiting_pubcomp (outbound QoS 2)
            out_qos2: %{}

  def start_link(_opts), do: GenServer.start_link(__MODULE__, %__MODULE__{}, name: __MODULE__)

  # --- client API -----------------------------------------------------

  @doc "Register a connected client. Returns `{:ok, session_present}` or `{:error, :max_clients}`."
  @spec register(client_id(), pid(), boolean(), keyword()) ::
          {:ok, boolean()} | {:error, :max_clients}
  def register(client_id, pid, clean_session, opts \\ []) do
    GenServer.call(__MODULE__, {:register, client_id, pid, clean_session, opts})
  end

  @doc "Subscribe `pid` (client `client_id`) to filters; returns granted QoS per filter (0x80 = failure)."
  @spec subscribe(client_id(), pid(), [{binary(), 0..2}]) :: [0..2 | 0x80]
  def subscribe(client_id, pid, topics) do
    GenServer.call(__MODULE__, {:subscribe, client_id, pid, topics})
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
  Publish a message. Delivers to matching subscribers, stores it when
  retained, queues it for offline persistent sessions, and (unless
  `from_bridge: true`) forwards it to the XMPP PubSub bridge.
  """
  @spec publish(binary(), binary(), 0..2, boolean(), keyword()) ::
          :ok | {:error, :invalid_topic | :too_large}
  def publish(topic, payload, qos \\ 0, retain \\ false, opts \\ []) do
    GenServer.call(__MODULE__, {:publish, topic, payload, qos, retain, opts})
  end

  @doc "Publish this client's Will message (on abnormal disconnect), if one was set."
  @spec publish_will(client_id()) :: :ok
  def publish_will(client_id), do: GenServer.call(__MODULE__, {:publish_will, client_id})

  @doc """
  The client is gone. `:clean` = it sent DISCONNECT (no Will);
  `:abnormal` = socket died (Will is published first).
  """
  @spec client_gone(client_id(), :clean | :abnormal) :: :ok
  def client_gone(client_id, reason), do: GenServer.call(__MODULE__, {:client_gone, client_id, reason})

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

      monitor = Process.monitor(pid)

      client = %{
        pid: pid,
        monitor: monitor,
        clean_session: clean_session,
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

          Enum.reduce(old_queued, state, fn packet, acc ->
            {packet, acc} = assign_packet_id(acc, client_id, packet)
            send(pid, {:mqtt_publish, packet})
            acc
          end)
        else
          state
        end

      {:reply, {:ok, session_present}, state}
    end
  end

  def handle_call({:subscribe, client_id, pid, topics}, _from, state) do
    {granted, state} =
      Enum.map_reduce(topics, state, fn {filter, requested_qos}, acc ->
        cond do
          not Codec.valid_filter?(filter) ->
            {0x80, acc}

          requested_qos > 2 ->
            {0x80, acc}

          true ->
            sub = %{filter: filter, pid: pid, qos: requested_qos, client_id: client_id}
            acc = %{acc | subs: [sub | Enum.reject(acc.subs, &same_sub?(&1, sub))]}

            # Retained messages matching a new subscription are
            # delivered immediately (§3.3.1.2).
            acc =
              Enum.reduce(acc.retained, acc, fn {rtopic, {payload, retained_qos}}, acc2 ->
                if Codec.matches?(filter, rtopic) do
                  {packet, acc3} =
                    retained_packet(acc2, client_id, rtopic, payload, retained_qos, requested_qos)

                  send(pid, {:mqtt_publish, packet})
                  acc3
                else
                  acc2
                end
              end)

            {requested_qos, acc}
        end
      end)

    {:reply, granted, state}
  end

  def handle_call({:subscribe_pid, pid, filter, qos}, _from, state) do
    sub = %{filter: filter, pid: pid, qos: qos, client_id: nil}
    state = %{state | subs: [sub | Enum.reject(state.subs, &same_sub?(&1, sub))]}
    {:reply, :ok, state}
  end

  def handle_call({:unsubscribe, client_id, topics}, _from, state) do
    subs =
      Enum.reject(state.subs, fn sub ->
        sub.client_id == client_id and sub.filter in topics
      end)

    {:reply, :ok, %{state | subs: subs}}
  end

  def handle_call({:publish, topic, payload, qos, retain, opts}, _from, state) do
    case do_publish(state, topic, payload, qos, retain, opts) do
      {:ok, state} -> {:reply, :ok, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:publish_will, client_id}, _from, state) do
    case get_in(state.clients, [client_id, :will]) do
      %{topic: topic, payload: payload, qos: qos, retain: retain}
      when is_binary(topic) ->
        {:ok, state} =
          do_publish(state, topic, payload, qos, retain, from_bridge: false)

        {:reply, :ok, state}

      _ ->
        {:reply, :ok, state}
    end
  end

  def handle_call({:client_gone, client_id, reason}, _from, state) do
    state =
      case reason do
        :abnormal ->
          case get_in(state.clients, [client_id, :will]) do
            %{topic: topic} = _will when is_binary(topic) ->
              {:ok, next} = do_publish_will(state, client_id)
              next

            _ ->
              state
          end

        :clean ->
          state
      end

    {:reply, :ok, drop_client(state, client_id)}
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
    {:reply, Map.get(state.retained, topic), state}
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
        case get_in(state.clients, [client_id, :will]) do
          %{topic: topic} when is_binary(topic) ->
            {:ok, next} = do_publish_will(state, client_id)
            next

          _ ->
            state
        end
      else
        state
      end

    state =
      if client_id do
        drop_client(state, client_id)
      else
        # A bare-pid subscriber (mod_mqtt API, client_id nil) died:
        # drop its subs. Subscriptions owned by a session (client_id
        # set) are never dropped here — a persistent session keeps
        # them even after its connection process is gone.
        %{state | subs: Enum.reject(state.subs, &(&1.pid == pid and &1.client_id == nil))}
      end

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # --- internals ------------------------------------------------------

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
      state = %{
        state
        | subs: Enum.reject(state.subs, &(&1.client_id == client_id)),
          in_qos2: Map.reject(state.in_qos2, fn {{cid, _}, _} -> cid == client_id end),
          out_qos2: Map.reject(state.out_qos2, fn {{cid, _}, _} -> cid == client_id end),
          clients: Map.delete(state.clients, client_id)
      }

      {state, false}
    else
      # Persistent session survives: keep subscriptions, queued
      # messages and QoS 2 state; the new connection resumes it.
      {state, true}
    end
  end

  defp drop_client(state, client_id) do
    case Map.get(state.clients, client_id) do
      nil ->
        state

      %{clean_session: true} = client ->
        Process.demonitor(client.monitor, [:flush])

        %{
          state
          | subs: Enum.reject(state.subs, &(&1.client_id == client_id)),
            in_qos2: Map.reject(state.in_qos2, fn {{cid, _}, _} -> cid == client_id end),
            out_qos2: Map.reject(state.out_qos2, fn {{cid, _}, _} -> cid == client_id end),
            clients: Map.delete(state.clients, client_id)
        }

      %{clean_session: false} = client ->
        # Persistent session: subscriptions stay, the pid is gone.
        Process.demonitor(client.monitor, [:flush])
        %{state | clients: Map.put(state.clients, client_id, %{client | pid: nil})}
    end
  end

  defp do_publish_will(state, client_id) do
    case get_in(state.clients, [client_id, :will]) do
      %{topic: topic, payload: payload, qos: qos, retain: retain}
      when is_binary(topic) ->
        do_publish(state, topic, payload, qos, retain, from_bridge: false)

      _ ->
        {:ok, state}
    end
  end

  defp do_publish(state, topic, payload, qos, retain, opts) do
    cond do
      not Codec.valid_topic?(topic) ->
        {:error, :invalid_topic}

      byte_size(payload) > Exjabberd.Mqtt.config(:max_payload, 262_144) ->
        {:error, :too_large}

      true ->
        state =
          if retain do
            retained =
              if payload == "" do
                Map.delete(state.retained, topic)
              else
                Map.put(state.retained, topic, {payload, qos})
              end

            %{state | retained: retained}
          else
            state
          end

        state = deliver(state, topic, payload, qos, retain)

        unless Keyword.get(opts, :from_bridge, false) do
          Bridge.mqtt_to_pubsub(topic, payload)
        end

        {:ok, state}
    end
  end

  defp deliver(state, topic, payload, qos, _retain) do
    # One delivery per subscriber pid, at the highest QoS of its
    # matching filters (§3.8.4 / §3.3.1).
    by_pid =
      state.subs
      |> Enum.filter(&Codec.matches?(&1.filter, topic))
      |> Enum.group_by(& &1.pid)

    state =
      Enum.reduce(by_pid, state, fn {pid, subs}, acc ->
        sub_qos = subs |> Enum.map(& &1.qos) |> Enum.max()
        cid = Enum.find_value(subs, & &1.client_id)
        {packet, acc} = deliver_to(acc, %{pid: pid, qos: sub_qos, client_id: cid}, topic, payload, qos)
        if packet, do: send(pid, {:mqtt_publish, packet})
        acc
      end)

    # Offline persistent sessions with a matching subscription get
    # QoS 1/2 messages queued (§3.1.2.4).
    state =
      Enum.reduce(state.clients, state, fn {cid, client}, acc ->
        if client.pid == nil and client.clean_session == false and qos >= 1 and
             Enum.any?(acc.subs, &(&1.client_id == cid and Codec.matches?(&1.filter, topic))) do
          max_queued = Exjabberd.Mqtt.config(:max_queued, 100)
          sub_qos = max_sub_qos(acc, cid, topic)

          packet = %{
            type: :publish,
            dup: false,
            qos: min(qos, sub_qos),
            retain: false,
            topic: topic,
            packet_id: nil,
            payload: payload
          }

          queued = Enum.take(client.queued ++ [packet], -max_queued)
          %{acc | clients: Map.put(acc.clients, cid, %{client | queued: queued})}
        else
          acc
        end
      end)

    state
  end

  # Build the packet for one subscriber; returns `{packet_or_nil, state}`.
  # QoS 2 delivery needs a packet id + outbound tracking; QoS 0/1 need
  # an id only for QoS 1.
  defp deliver_to(state, %{pid: pid, qos: sub_qos, client_id: cid}, topic, payload, qos) do
    effective_qos = min(qos, sub_qos)

    case effective_qos do
      0 ->
        {publish_packet(0, topic, nil, payload, false), state}

      1 ->
        {state, packet_id} = next_packet_id(state, cid || pid_key(pid))
        {publish_packet(1, topic, packet_id, payload, false), state}

      2 ->
        {state, packet_id} = next_packet_id(state, cid || pid_key(pid))
        state = %{state | out_qos2: Map.put(state.out_qos2, {cid || pid_key(pid), packet_id}, :waiting_pubrec)}
        {publish_packet(2, topic, packet_id, payload, false), state}
    end
  end

  defp publish_packet(qos, topic, packet_id, payload, retain) do
    %{type: :publish, dup: false, qos: qos, retain: retain, topic: topic, packet_id: packet_id, payload: payload}
  end

  # Retained delivery on SUBSCRIBE: same shape as a live delivery,
  # with the retain flag set; QoS 1/2 needs a real packet id.
  defp retained_packet(state, client_id, topic, payload, retained_qos, requested_qos) do
    qos = min(retained_qos, requested_qos)

    if qos == 0 do
      {publish_packet(0, topic, nil, payload, true), state}
    else
      {state, packet_id} = next_packet_id(state, client_id)

      state =
        if qos == 2 do
          %{state | out_qos2: Map.put(state.out_qos2, {client_id, packet_id}, :waiting_pubrec)}
        else
          state
        end

      {publish_packet(qos, topic, packet_id, payload, true), state}
    end
  end

  defp max_sub_qos(state, client_id, topic) do
    state.subs
    |> Enum.filter(&(&1.client_id == client_id and Codec.matches?(&1.filter, topic)))
    |> Enum.map(& &1.qos)
    |> Enum.max(fn -> 0 end)
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

  defp pid_key(pid), do: inspect(pid)

  defp same_sub?(a, b), do: a.filter == b.filter and a.pid == b.pid
end
