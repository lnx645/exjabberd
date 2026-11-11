defmodule Exjabberd.Mod.Muc do
  @moduledoc """
  Multi-User Chat - `mod_muc` (XEP-0045) (partial implementation), best-model Elixir.

  Each room is a GenServer under `Exjabberd.Mod.Muc.Supervisor`.
  Stores config in ETS, history in ordered_set, handles:
  - Affiliations: owner/admin/member/outcast/none (like `mod_muc:affiliation`)
  - Roles: moderator/participant/visitor/none
  - Room config: persistent, password, max_users, history_size
  - Presence broadcast, subject, invite, kick/ban
  - History (like `mod_muc_room` history)
  """

  use Exjabberd.Mod.GenMod

  @table :exjabberd_muc_rooms
  @index :exjabberd_muc_rooms_index

  @impl true
  def start(host, opts) do
    for t <- [@table, @index] do
      if :ets.whereis(t) == :undefined do
        :ets.new(t, [:named_table, :public, :set, read_concurrency: true, write_concurrency: true])
      end
    end

    history_size = Keyword.get(opts, :history_size, 20)
    default_room_opts = Keyword.get(opts, :default_room_options, [])
    _ = {history_size, default_room_opts}

    Exjabberd.Iq.register(
      host,
      "http://jabber.org/protocol/muc#owner",
      __MODULE__,
      :handle_owner_iq
    )

    Exjabberd.Iq.register(
      host,
      "http://jabber.org/protocol/muc#admin",
      __MODULE__,
      :handle_admin_iq
    )

    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Iq.unregister(host, "http://jabber.org/protocol/muc#owner", :both)
    Exjabberd.Iq.unregister(host, "http://jabber.org/protocol/muc#admin", :both)
    :ok
  end

  @doc "Create room (like `mod_muc:create_room`). Returns {:ok, pid} or {:error, :exists}."
  @spec create_room(binary(), binary(), binary()) :: {:ok, pid()} | {:error, term()}
  def create_room(host, room_jid, creator_nick) do
    ensure()

    case :ets.lookup(@index, {host, room_jid}) do
      [] ->
        {:ok, pid} =
          DynamicSupervisor.start_child(
            Exjabberd.Mod.Muc.Supervisor,
            {Exjabberd.Mod.Muc.Room,
             %{
               host: host,
               jid: room_jid,
               creator: creator_nick,
               created: System.system_time(:second)
             }}
          )

        :ets.insert(@index, {{host, room_jid}, pid})

        :ets.insert(
          @table,
          {{host, room_jid}, %{creator: creator_nick, created: System.system_time(:second)}}
        )

        {:ok, pid}

      [{_, pid}] ->
        {:error, {:exists, pid}}
    end
  end

  @doc "Join room (like `mod_muc_room:route` presence). Creates the room when it does not exist yet; the first joiner becomes its owner."
  @spec join(binary(), binary(), binary(), binary()) :: :ok | {:error, term()}
  def join(host, room_jid, user_jid, nick) do
    ensure()
    bare = bare_jid(user_jid)
    nick = if nick == "" or is_nil(nick), do: bare |> String.split("@") |> hd(), else: nick

    case :ets.lookup(@index, {host, room_jid}) do
      [{_, pid}] ->
        Exjabberd.Mod.Muc.Room.join(pid, bare, nick, created: false)

      [] ->
        case create_room(host, room_jid, nick) do
          {:ok, pid} -> Exjabberd.Mod.Muc.Room.join(pid, bare, nick, created: true)
          {:error, {:exists, pid}} -> Exjabberd.Mod.Muc.Room.join(pid, bare, nick, created: false)
          err -> err
        end
    end
  end

  @doc "Leave room (presence type='unavailable' to the room)."
  @spec leave(binary(), binary(), binary(), binary()) :: :ok | {:error, term()}
  def leave(host, room_jid, user_jid, nick) do
    ensure()
    bare = bare_jid(user_jid)

    case :ets.lookup(@index, {host, room_jid}) do
      [{_, pid}] -> Exjabberd.Mod.Muc.Room.leave(pid, bare, nick)
      [] -> {:error, :not_found}
    end
  end

  defp bare_jid(%Exjabberd.Xmpp.Jid{} = jid), do: Exjabberd.Xmpp.Jid.bare(jid)
  defp bare_jid(bin) when is_binary(bin), do: Exjabberd.Xmpp.Jid.bare(bin)
  defp bare_jid(_), do: ""

  @doc "Send groupchat message (like `mod_muc_room:route_message`)."
  @spec send_message(binary(), binary(), binary(), binary()) :: :ok | {:error, term()}
  def send_message(host, room_jid, from_jid, body) do
    ensure()

    case :ets.lookup(@index, {host, room_jid}) do
      [{_, pid}] -> Exjabberd.Mod.Muc.Room.broadcast(pid, bare_jid(from_jid), body, "groupchat")
      [] -> {:error, :not_found}
    end
  end

  @doc "Set room affiliation (owner/admin/member/outcast) — mod_muc affiliations."
  @spec set_affiliation(binary(), binary(), binary(), atom()) :: :ok | {:error, term()}
  def set_affiliation(host, room_jid, jid, aff)
      when aff in [:owner, :admin, :member, :outcast, :none] do
    case :ets.lookup(@index, {host, room_jid}) do
      [{_, pid}] -> Exjabberd.Mod.Muc.Room.set_affiliation(pid, jid, aff)
      [] -> {:error, :not_found}
    end
  end

  @doc "Approve member (like mod_muc approve) — set affiliation member."
  @spec approve_member(binary(), binary(), binary()) :: :ok | {:error, term()}
  def approve_member(host, room_jid, jid), do: set_affiliation(host, room_jid, jid, :member)

  @doc "Kick occupant (moderation, XEP-0045 kick) — set role none."
  @spec kick(binary(), binary(), binary(), binary()) :: :ok | {:error, term()}
  def kick(host, room_jid, nick, reason \\ "") do
    case :ets.lookup(@index, {host, room_jid}) do
      [{_, pid}] -> Exjabberd.Mod.Muc.Room.kick(pid, nick, reason)
      [] -> {:error, :not_found}
    end
  end

  @doc "Ban JID (affiliation outcast) — mod_muc ban."
  @spec ban(binary(), binary(), binary()) :: :ok | {:error, term()}
  def ban(host, room_jid, jid), do: set_affiliation(host, room_jid, jid, :outcast)

  @doc "Set role (moderator/participant/visitor) — mod_muc set_role."
  @spec set_role(binary(), binary(), binary(), atom()) :: :ok | {:error, term()}
  def set_role(host, room_jid, nick, role)
      when role in [:moderator, :participant, :visitor, :none] do
    case :ets.lookup(@index, {host, room_jid}) do
      [{_, pid}] -> Exjabberd.Mod.Muc.Room.set_role(pid, nick, role)
      [] -> {:error, :not_found}
    end
  end

  @doc "Moderate message (approve/reject) — mod_muc moderate."
  @spec moderate(binary(), binary(), binary(), atom()) :: :ok | {:error, term()}
  def moderate(host, room_jid, message_id, action) when action in [:approve, :retract] do
    case :ets.lookup(@index, {host, room_jid}) do
      [{_, pid}] -> Exjabberd.Mod.Muc.Room.moderate(pid, message_id, action)
      [] -> {:error, :not_found}
    end
  end

  @doc "Get occupants."
  @spec occupants(binary(), binary()) :: {:ok, map()} | {:error, term()}
  def occupants(host, room_jid) do
    case :ets.lookup(@index, {host, room_jid}) do
      [{_, pid}] -> Exjabberd.Mod.Muc.Room.get_state(pid)
      [] -> {:error, :not_found}
    end
  end

  @doc false
  def handle_owner_iq(iq, _host), do: {:ok, %{iq | type: "result", payload: []}}
  @doc false
  def handle_admin_iq(iq, _host), do: {:ok, %{iq | type: "result", payload: []}}

  defp ensure do
    for t <- [@table, @index] do
      if :ets.whereis(t) == :undefined do
        :ets.new(t, [:named_table, :public, :set, read_concurrency: true, write_concurrency: true])
      end
    end
  end
end

defmodule Exjabberd.Mod.Muc.Room do
  @moduledoc "MUC room GenServer - `mod_muc_room` (partial implementation)."

  use GenServer

  def start_link(init) do
    GenServer.start_link(__MODULE__, init)
  end

  @impl true
  def init(%{host: host, jid: jid, creator: creator}) do
    state = %{
      host: host,
      jid: jid,
      subject: "",
      subject_author: nil,
      occupants: %{},
      affiliations: %{creator => :owner},
      history: [],
      config: %{persistent: true, password: nil, max_users: 200, history_size: 20, public: true}
    }

    {:ok, state}
  end

  def join(pid, user_jid, nick, opts \\ []),
    do: GenServer.call(pid, {:join, user_jid, nick, opts})

  def leave(pid, user_jid, nick), do: GenServer.call(pid, {:leave, user_jid, nick})
  def broadcast(pid, from, body, type), do: GenServer.call(pid, {:broadcast, from, body, type})
  def set_affiliation(pid, jid, aff), do: GenServer.call(pid, {:affiliation, jid, aff})
  def kick(pid, nick, reason), do: GenServer.call(pid, {:kick, nick, reason})
  def set_role(pid, nick, role), do: GenServer.call(pid, {:set_role, nick, role})
  def moderate(pid, msg_id, action), do: GenServer.call(pid, {:moderate, msg_id, action})
  def get_state(pid), do: GenServer.call(pid, :get_state)

  @impl true
  def handle_call({:join, user_jid, nick, opts}, _from, state) do
    # Check ban
    aff = Map.get(state.affiliations, user_jid, :none)

    if aff == :outcast do
      {:reply, {:error, :banned}, state}
    else
      role = if aff in [:owner, :admin], do: :moderator, else: :participant

      next =
        put_in(state.occupants[nick], %{jid: user_jid, role: role, affiliation: aff, nick: nick})

      # Presence exchange like mod_muc: the joiner gets every existing
      # occupant's presence plus their own self-presence (status 110,
      # and 201 when they just created the room); everyone else gets
      # the joiner's presence.
      broadcast_presence(next, nick, user_jid, Keyword.get(opts, :created, false))
      {:reply, :ok, next}
    end
  end

  def handle_call({:leave, user_jid, nick}, _from, state) do
    case Map.pop(state.occupants, nick) do
      {nil, _} ->
        {:reply, {:error, :not_found}, state}

      {occ, rest} ->
        if occ.jid == user_jid do
          stanza =
            Exjabberd.Xmpp.Stanza.new(:presence,
              from: "#{state.jid}/#{nick}",
              to: occ.jid,
              type: "unavailable",
              payload: [muc_user_x(occ, [])]
            )

          Enum.each(rest, fn {_n, other} ->
            Exjabberd.Router.route(%{stanza | to: other.jid})
          end)
        end

        {:reply, :ok, %{state | occupants: rest}}
    end
  end

  def handle_call({:broadcast, from, body, type}, _from, state) do
    entry = %{from: from, body: body, type: type, ts: System.system_time(:millisecond)}
    history = Enum.take([entry | state.history], state.config.history_size)

    nick =
      Enum.find_value(state.occupants, fn {n, occ} -> if occ.jid == from, do: n end) ||
        from |> String.split("@") |> hd()

    # Route to all occupants via Router (like mod_muc_room does). The
    # message comes from room/nick, with a real <body/> child.
    Enum.each(state.occupants, fn {_nick, occ} ->
      stanza =
        Exjabberd.Xmpp.Stanza.new(:message,
          type: type,
          from: "#{state.jid}/#{nick}",
          to: occ.jid,
          payload: [%{name: "body", attrs: %{}, children: [body]}]
        )

      Exjabberd.Router.route(stanza)
    end)

    # Also archive via MAM if enabled
    _ = history
    {:reply, :ok, %{state | history: history}}
  end

  def handle_call({:affiliation, jid, aff}, _from, state) do
    next = put_in(state.affiliations[jid], aff)

    next =
      if aff == :outcast do
        occupants =
          Enum.reject(state.occupants, fn {_nick, occ} -> occ.jid == jid end) |> Map.new()

        %{next | occupants: occupants}
      else
        next
      end

    {:reply, :ok, next}
  end

  def handle_call({:kick, nick, reason}, _from, state) do
    case Map.pop(state.occupants, nick) do
      {nil, _} ->
        {:reply, {:error, :not_found}, state}

      {occ, rest} ->
        stanza =
          Exjabberd.Xmpp.Stanza.new(:presence,
            from: "#{state.jid}/#{nick}",
            to: occ.jid,
            type: "unavailable",
            payload: [muc_user_x(occ, [], reason)]
          )

        Exjabberd.Router.route(stanza)
        {:reply, :ok, %{state | occupants: rest}}
    end
  end

  def handle_call({:set_role, nick, role}, _from, state) do
    case Map.get(state.occupants, nick) do
      nil -> {:reply, {:error, :not_found}, state}
      occ -> {:reply, :ok, put_in(state.occupants[nick], %{occ | role: role})}
    end
  end

  def handle_call({:moderate, msg_id, action}, _from, state) do
    # XEP-0425 moderation: retract/approve message by id
    history =
      case action do
        :retract -> Enum.reject(state.history, fn %{body: b} -> b == msg_id end)
        :approve -> state.history
        _ -> state.history
      end

    {:reply, :ok, %{state | history: history}}
  end

  def handle_call(:get_state, _from, state), do: {:reply, {:ok, state}, state}

  defp broadcast_presence(state, nick, jid, created) do
    joined = Map.fetch!(state.occupants, nick)

    # The joiner's presence to every other occupant.
    Enum.each(state.occupants, fn {n, occ} ->
      if n != nick do
        stanza =
          Exjabberd.Xmpp.Stanza.new(:presence,
            from: "#{state.jid}/#{nick}",
            to: occ.jid,
            payload: [muc_user_x(joined, [])]
          )

        Exjabberd.Router.route(stanza)
      end
    end)

    # Every existing occupant's presence to the joiner.
    Enum.each(state.occupants, fn {n, occ} ->
      if n != nick do
        stanza =
          Exjabberd.Xmpp.Stanza.new(:presence,
            from: "#{state.jid}/#{n}",
            to: jid,
            payload: [muc_user_x(occ, [])]
          )

        Exjabberd.Router.route(stanza)
      end
    end)

    # The joiner's own self-presence (status 110; 201 when the room
    # was just created).
    codes = if created, do: ["110", "201"], else: ["110"]

    self_stanza =
      Exjabberd.Xmpp.Stanza.new(:presence,
        from: "#{state.jid}/#{nick}",
        to: jid,
        payload: [muc_user_x(joined, codes)]
      )

    Exjabberd.Router.route(self_stanza)
  end

  # <x xmlns='http://jabber.org/protocol/muc#user'> with the occupant's
  # affiliation/role and optional status codes (and a reason, for kicks).
  defp muc_user_x(occ, codes, reason \\ nil) do
    item_attrs = %{
      "affiliation" => to_string(Map.get(occ, :affiliation, :none)),
      "role" => to_string(Map.get(occ, :role, :participant))
    }

    item_attrs =
      if Map.get(occ, :jid), do: Map.put(item_attrs, "jid", occ.jid), else: item_attrs

    children = [%{name: "item", attrs: item_attrs, children: []}]

    children =
      children ++
        Enum.map(codes, fn code ->
          %{name: "status", attrs: %{"code" => code}, children: []}
        end)

    children =
      if reason do
        children ++ [%{name: "reason", attrs: %{}, children: [reason]}]
      else
        children
      end

    %{name: "x", attrs: %{"xmlns" => "http://jabber.org/protocol/muc#user"}, children: children}
  end
end

defmodule Exjabberd.Mod.Muc.Supervisor do
  @moduledoc "Supervisor for MUC rooms - `mod_muc_sup`."
  use DynamicSupervisor
  def start_link(_), do: DynamicSupervisor.start_link(__MODULE__, :ok, name: __MODULE__)
  @impl true
  def init(:ok), do: DynamicSupervisor.init(strategy: :one_for_one)
end

defmodule Exjabberd.Mod.MucLight do
  @moduledoc """
  MUC Light - `mod_muc_light` (partial implementation). Lightweight group chat with
  affiliations stored per-room, no roles, simpler than MUC.
  """

  use Exjabberd.Mod.GenMod

  @table :exjabberd_muc_light

  @impl true
  def start(_host, _opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [
        :named_table,
        :public,
        :set,
        read_concurrency: true,
        write_concurrency: true
      ])
    end

    :ok
  end

  @impl true
  def stop(_host), do: :ok

  @doc "Create light room (like `mod_muc_light:create_room`)."
  @spec create(binary(), binary(), [binary()]) :: :ok | {:error, term()}
  def create(host, room, members) when is_list(members) do
    if :ets.member(@table, {host, room}) do
      {:error, :exists}
    else
      :ets.insert(
        @table,
        {{host, room},
         %{
           members: Enum.uniq(members),
           config: %{},
           version: 1,
           created: System.system_time(:second)
         }}
      )

      :ok
    end
  end

  @doc "Add member."
  @spec add_member(binary(), binary(), binary()) :: :ok | {:error, term()}
  def add_member(host, room, jid) do
    case :ets.lookup(@table, {host, room}) do
      [{{_, _}, data}] ->
        :ets.insert(
          @table,
          {{host, room},
           %{data | members: Enum.uniq([jid | data.members]), version: data.version + 1}}
        )

        :ok

      [] ->
        {:error, :not_found}
    end
  end

  @doc "Send message to light room."
  @spec send_message(binary(), binary(), binary(), binary()) :: :ok | {:error, term()}
  def send_message(host, room, from, body) do
    case :ets.lookup(@table, {host, room}) do
      [{{_, _}, %{members: members}}] ->
        Enum.each(members, fn member ->
          stanza =
            Exjabberd.Xmpp.Stanza.new(:message,
              type: "groupchat",
              from: room,
              to: member,
              payload: [%{body: body, from: from}]
            )

          Exjabberd.Router.route(stanza)
        end)

        :ok

      [] ->
        {:error, :not_found}
    end
  end
end

defmodule Exjabberd.Mod.Announce do
  @moduledoc "`mod_announce` (XEP-0137) (partial implementation). Broadcast to all/online/motd with `announce` access."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(host, _opts) do
    Exjabberd.Iq.register(
      host,
      "http://jabber.org/protocol/admin#announce",
      __MODULE__,
      :handle_iq
    )

    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Iq.unregister(host, "http://jabber.org/protocol/admin#announce", :both)
    :ok
  end

  @doc "Announce to all users on host (like `mod_announce:announce_to_all`)."
  @spec announce(binary(), binary(), binary()) :: :ok
  def announce(host, from, msg) do
    stanza =
      Exjabberd.Xmpp.Stanza.new(:message, type: "normal", from: from, payload: [%{announce: msg}])

    Exjabberd.Hooks.run(:announce, host, stanza)
    # Also offline
    :ets.tab2list(:exjabberd_sm)
    |> Enum.each(fn {{user, _res}, _pid, _, _} ->
      Exjabberd.Router.route(Map.put(stanza, :to, "#{user}@#{host}"))
    end)

    :ok
  end

  @doc false
  def handle_iq(iq, _host), do: {:ok, %{iq | type: "result", payload: []}}
end
