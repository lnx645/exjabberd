defmodule Exjabberd.Mod.Muc do
  @moduledoc """
  Multi-User Chat - `mod_muc` (XEP-0045).

  Each room is a GenServer under `Exjabberd.Mod.Muc.Supervisor`.
  Implements, over the wire:

  - Affiliations (owner/admin/member/outcast/none) keyed by bare
    JID, roles (moderator/participant/visitor/none), presence
    exchange with `muc#user` items and status codes (110/201/301/307)
  - Join gating: banned users (`forbidden`), members-only rooms
    (`registration-required`), password-protected rooms
    (`not-authorized`), nick conflicts (`conflict`) — all answered
    with presence errors like ejabberd
  - `muc#admin` IQ: affiliation list get/set, role changes and
    kicks/bans by item, with presence updates to the room
  - `muc#owner` IQ: room configuration via the XEP-0045 data form
    (title, persistent, public, members-only, password, max users)
    and room destruction; temporary rooms vanish when they empty
  - Subject changes, message history (in-memory) and MAM archiving

  Room state is in-memory (GenServer + ETS index): rooms do not
  survive a server restart.
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

  @doc "Create room (like `mod_muc:create_room`). The creator is a bare JID and becomes the room owner. Returns {:ok, pid} or {:error, :exists}."
  @spec create_room(binary(), binary(), binary()) :: {:ok, pid()} | {:error, term()}
  def create_room(host, room_jid, creator_bare) do
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
               creator: creator_bare,
               created: System.system_time(:second)
             }}
          )

        # Claim the room JID atomically. Two joins racing to create
        # the same room both start a process, but only the first
        # insert_new wins; the loser terminates its duplicate (nobody
        # has joined it yet — joins happen after create_room returns)
        # and reports the winner, so the caller joins the winning
        # room instead. A plain insert here let the second create
        # overwrite the index and orphan the first room with its
        # creator inside: that occupant then silently missed
        # reflections and room MAM answers.
        if :ets.insert_new(@index, {{host, room_jid}, pid}) do
          :ets.insert(
            @table,
            {{host, room_jid}, %{creator: creator_bare, created: System.system_time(:second)}}
          )

          {:ok, pid}
        else
          DynamicSupervisor.terminate_child(Exjabberd.Mod.Muc.Supervisor, pid)
          [{_, winner}] = :ets.lookup(@index, {host, room_jid})
          {:error, {:exists, winner}}
        end

      [{_, pid}] ->
        {:error, {:exists, pid}}
    end
  end

  @doc "The room GenServer pid for a room bare JID, if the room exists."
  @spec room_pid(binary(), binary()) :: {:ok, pid()} | :error
  def room_pid(host, room_jid) do
    ensure()

    case :ets.lookup(@index, {host, room_jid}) do
      [{_, pid}] -> {:ok, pid}
      [] -> :error
    end
  end

  @doc """
  Join room (like `mod_muc_room:route` presence). Creates the room
  when it does not exist yet; the creator becomes its owner.
  `opts[:password]` is the room password from the join presence.
  Returns `:ok` or `{:error, condition}` with an XMPP error
  condition atom (`:forbidden`, `:registration_required`,
  `:not_authorized`, `:conflict`).
  """
  @spec join(binary(), binary(), binary(), binary(), keyword()) :: :ok | {:error, atom()}
  def join(host, room_jid, user_jid, nick, opts \\ []) do
    ensure()
    bare = bare_jid(user_jid)
    nick = if nick == "" or is_nil(nick), do: bare |> String.split("@") |> hd(), else: nick

    case :ets.lookup(@index, {host, room_jid}) do
      [{_, pid}] ->
        Exjabberd.Mod.Muc.Room.join(pid, bare, nick, created: false, password: opts[:password])

      [] ->
        case create_room(host, room_jid, bare) do
          {:ok, pid} ->
            Exjabberd.Mod.Muc.Room.join(pid, bare, nick, created: true, password: opts[:password])

          {:error, {:exists, pid}} ->
            Exjabberd.Mod.Muc.Room.join(pid, bare, nick, created: false, password: opts[:password])

          err ->
            err
        end
    end
  end

  @doc """
  Destroy a room (XEP-0045 §10.9): every occupant gets an
  unavailable presence carrying the `<destroy/>` element, the room
  process stops and the room leaves the service's room list.
  """
  @spec destroy_room(binary(), binary(), binary() | nil) :: :ok | {:error, :not_found}
  def destroy_room(host, room_jid, alternate_jid \\ nil) do
    ensure()

    case :ets.lookup(@index, {host, room_jid}) do
      [{_, pid}] ->
        Exjabberd.Mod.Muc.Room.destroy(pid, alternate_jid)
        DynamicSupervisor.terminate_child(Exjabberd.Mod.Muc.Supervisor, pid)
        :ets.delete(@index, {host, room_jid})
        :ets.delete(@table, {host, room_jid})
        :ok

      [] ->
        {:error, :not_found}
    end
  end

  @doc "Change the room subject (message with <subject/>, XEP-0045 §7.2)."
  @spec set_subject(binary(), binary(), binary(), binary()) :: :ok | {:error, term()}
  def set_subject(host, room_jid, from_jid, subject) do
    case :ets.lookup(@index, {host, room_jid}) do
      [{_, pid}] -> Exjabberd.Mod.Muc.Room.set_subject(pid, bare_jid(from_jid), subject)
      [] -> {:error, :not_found}
    end
  end

  @doc "Apply room configuration values (from the muc#owner form)."
  @spec set_config(binary(), binary(), map()) :: :ok | {:error, term()}
  def set_config(host, room_jid, config) do
    case :ets.lookup(@index, {host, room_jid}) do
      [{_, pid}] -> Exjabberd.Mod.Muc.Room.set_config(pid, config)
      [] -> {:error, :not_found}
    end
  end

  @doc "Leave room (presence type='unavailable' to the room)."
  @spec leave(binary(), binary(), binary(), binary()) :: :ok | {:error, term()}
  def leave(host, room_jid, user_jid, nick) do
    ensure()
    bare = bare_jid(user_jid)

    case :ets.lookup(@index, {host, room_jid}) do
      [{_, pid}] ->
        result = Exjabberd.Mod.Muc.Room.leave(pid, bare, nick)

        # Temporary rooms are destroyed when the last occupant
        # leaves (XEP-0045: non-persistent rooms are temporary).
        case Exjabberd.Mod.Muc.Room.get_state(pid) do
          {:ok, %{occupants: occ, config: %{persistent: false}}} when map_size(occ) == 0 ->
            destroy_room(host, room_jid)

          _ ->
            :ok
        end

        result

      [] ->
        {:error, :not_found}
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

  @doc "List room bare JIDs for a host (for disco#items on the MUC service)."
  @spec list_rooms(binary()) :: [binary()]
  def list_rooms(host) do
    ensure()

    :ets.match(@table, {{host, :"$1"}, :_})
    |> Enum.map(fn [room] -> room end)
    |> Enum.sort()
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

  alias Exjabberd.Xmpp.Stanza

  @doc "IQ handler for `muc#owner` (XEP-0045 §10): config form get, config submit, destroy."
  @spec handle_owner_iq(map(), binary()) :: {:ok, map()} | {:error, term()}
  def handle_owner_iq(%{type: "get"} = iq, host) do
    case owner_context(iq, host) do
      {:ok, _pid, state} ->
        {:ok, %{iq | type: "result", payload: [config_form_query(state)]}}

      {:error, _, _} = err ->
        err
    end
  end

  def handle_owner_iq(%{type: "set"} = iq, host) do
    case owner_context(iq, host) do
      {:ok, pid, _state} ->
        query = Stanza.child(iq.payload, "query")

        cond do
          query != nil and Stanza.child(query.children, "destroy") != nil ->
            destroy_el = Stanza.child(query.children, "destroy")
            destroy_room(host, bare_jid(iq.to), Stanza.child_attr(destroy_el, "jid"))
            {:ok, %{iq | type: "result", payload: []}}

          query != nil and Stanza.child(query.children, "x") != nil ->
            x = Stanza.child(query.children, "x")

            if Stanza.child_attr(x, "type") == "submit" do
              Exjabberd.Mod.Muc.Room.set_config(pid, config_from_form(form_fields(x)))
            end

            {:ok, %{iq | type: "result", payload: []}}

          true ->
            {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
        end

      {:error, _, _} = err ->
        err
    end
  end

  def handle_owner_iq(iq, _host),
    do: {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

  @doc "IQ handler for `muc#admin` (XEP-0045 §8–§9): affiliation lists, role changes, kicks and bans."
  @spec handle_admin_iq(map(), binary()) :: {:ok, map()} | {:error, term()}
  def handle_admin_iq(%{type: "get"} = iq, host) do
    case admin_context(iq, host) do
      {:ok, _pid, state} ->
        query = Stanza.child(iq.payload, "query")
        first_item = query && (Stanza.child(query.children, "item") || %{})

        items =
          cond do
            (aff = Stanza.child_attr(first_item, "affiliation")) != nil ->
              aff_atom = String.to_atom(aff)

              state.affiliations
              |> Enum.filter(fn {_jid, a} -> a == aff_atom end)
              |> Enum.sort()
              |> Enum.map(fn {jid, _} ->
                %{name: "item", attrs: %{"jid" => jid, "affiliation" => aff}, children: []}
              end)

            (role = Stanza.child_attr(first_item, "role")) != nil ->
              state.occupants
              |> Enum.filter(fn {_nick, occ} -> to_string(occ.role) == role end)
              |> Enum.map(fn {nick, occ} ->
                %{
                  name: "item",
                  attrs: %{"nick" => nick, "role" => role, "jid" => occ.jid},
                  children: []
                }
              end)

            true ->
              []
          end

        {:ok,
         %{
           iq
           | type: "result",
             payload: [
               %{
                 name: "query",
                 attrs: %{"xmlns" => "http://jabber.org/protocol/muc#admin"},
                 children: items
               }
             ]
         }}

      {:error, _, _} = err ->
        err
    end
  end

  def handle_admin_iq(%{type: "set"} = iq, host) do
    case admin_context(iq, host) do
      {:ok, pid, state} ->
        requester_aff = Map.get(state.affiliations, bare_jid(iq.from), :none)
        query = Stanza.child(iq.payload, "query")
        items = (query && Enum.filter(query.children, &match?(%{name: "item"}, &1))) || []

        result =
          Enum.reduce_while(items, :ok, fn item, :ok ->
            cond do
              (aff = Stanza.child_attr(item, "affiliation")) != nil and
                  Stanza.child_attr(item, "jid") != nil ->
                jid = Stanza.child_attr(item, "jid")
                aff_atom = String.to_atom(aff)

                if affiliation_change_allowed?(requester_aff, state, jid, aff_atom) do
                  Exjabberd.Mod.Muc.Room.set_affiliation(pid, jid, aff_atom)
                  {:cont, :ok}
                else
                  {:halt, {:error, :forbidden, Exjabberd.Iq.error_iq(iq, "forbidden")}}
                end

              (role = Stanza.child_attr(item, "role")) != nil and
                  Stanza.child_attr(item, "nick") != nil ->
                nick = Stanza.child_attr(item, "nick")
                reason = Stanza.child_text(item.children, "reason") || ""

                if role == "none" do
                  Exjabberd.Mod.Muc.Room.kick(pid, nick, reason)
                else
                  Exjabberd.Mod.Muc.Room.set_role(pid, nick, String.to_atom(role))
                end

                {:cont, :ok}

              true ->
                {:cont, :ok}
            end
          end)

        case result do
          :ok -> {:ok, %{iq | type: "result", payload: []}}
          err -> err
        end

      {:error, _, _} = err ->
        err
    end
  end

  def handle_admin_iq(iq, _host),
    do: {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

  # Owners can change any affiliation; admins only member-level
  # ones (grant/revoke member, ban/unban) — XEP-0045 §8.2/§9.2.
  defp affiliation_change_allowed?(:owner, _state, _jid, _new_aff), do: true

  defp affiliation_change_allowed?(:admin, state, jid, new_aff) do
    current = Map.get(state.affiliations, jid, :none)
    current in [:member, :outcast, :none] and new_aff in [:member, :outcast, :none]
  end

  defp affiliation_change_allowed?(_other, _state, _jid, _new_aff), do: false

  defp owner_context(iq, host) do
    case room_context(iq, host) do
      {:ok, pid, state} ->
        if Map.get(state.affiliations, bare_jid(iq.from)) == :owner do
          {:ok, pid, state}
        else
          {:error, :forbidden, Exjabberd.Iq.error_iq(iq, "forbidden")}
        end

      err ->
        err
    end
  end

  defp admin_context(iq, host) do
    case room_context(iq, host) do
      {:ok, pid, state} ->
        if Map.get(state.affiliations, bare_jid(iq.from)) in [:owner, :admin] do
          {:ok, pid, state}
        else
          {:error, :forbidden, Exjabberd.Iq.error_iq(iq, "forbidden")}
        end

      err ->
        err
    end
  end

  defp room_context(iq, host) do
    case room_pid(host, bare_jid(iq.to)) do
      {:ok, pid} ->
        {:ok, state} = Exjabberd.Mod.Muc.Room.get_state(pid)
        {:ok, pid, state}

      :error ->
        {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}
    end
  end

  # The XEP-0045 room configuration form (jabber:x:data), filled
  # with the room's current values.
  defp config_form_query(state) do
    c = state.config

    fields = [
      form_field("FORM_TYPE", "hidden", nil, "http://jabber.org/protocol/muc#roomconfig"),
      form_field("muc#roomconfig_roomname", "text-single", "Room name", c.title || ""),
      form_field("muc#roomconfig_persistentroom", "boolean", "Make room persistent", bool_str(c.persistent)),
      form_field("muc#roomconfig_publicroom", "boolean", "Make room public searchable", bool_str(c.public)),
      form_field("muc#roomconfig_passwordprotectedroom", "boolean", "Make room password protected", bool_str(c.password not in [nil, ""])),
      form_field("muc#roomconfig_roomsecret", "text-private", "Password", c.password || ""),
      form_field("muc#roomconfig_membersonly", "boolean", "Make room members-only", bool_str(c.members_only)),
      form_field("muc#roomconfig_maxusers", "text-single", "Maximum number of occupants", Integer.to_string(c.max_users || 200))
    ]

    %{
      name: "query",
      attrs: %{"xmlns" => "http://jabber.org/protocol/muc#owner"},
      children: [
        %{
          name: "x",
          attrs: %{"xmlns" => "jabber:x:data", "type" => "form"},
          children:
            [
              %{name: "title", attrs: %{}, children: ["Room configuration"]},
              %{
                name: "instructions",
                attrs: %{},
                children: ["Configure the room by completing this form."]
              }
            ] ++ fields
        }
      ]
    }
  end

  defp form_field(var, type, label, value) do
    attrs =
      %{"var" => var, "type" => type}
      |> then(fn a -> if label, do: Map.put(a, "label", label), else: a end)

    %{name: "field", attrs: attrs, children: [%{name: "value", attrs: %{}, children: [value]}]}
  end

  defp bool_str(true), do: "1"
  defp bool_str(_), do: "0"

  # Submitted form fields as %{var => value} (first value wins).
  defp form_fields(x_el) do
    x_el.children
    |> Enum.filter(&match?(%{name: "field"}, &1))
    |> Map.new(fn field ->
      {Stanza.child_attr(field, "var") || "",
       Stanza.child_text(field.children, "value") || ""}
    end)
  end

  # Map a submitted roomconfig form to Room config keys. Only keys
  # present in the form are returned (the room merges them).
  defp config_from_form(fields) do
    %{}
    |> put_form(fields, "muc#roomconfig_roomname", :title, & &1)
    |> put_form(fields, "muc#roomconfig_persistentroom", :persistent, &truthy?/1)
    |> put_form(fields, "muc#roomconfig_publicroom", :public, &truthy?/1)
    |> put_form(fields, "muc#roomconfig_membersonly", :members_only, &truthy?/1)
    |> put_form(fields, "muc#roomconfig_maxusers", :max_users, fn v ->
      case Integer.parse(v || "") do
        {n, _} when n > 0 -> n
        _ -> 200
      end
    end)
    |> put_password(fields)
  end

  defp put_form(acc, fields, var, key, fun) do
    case Map.fetch(fields, var) do
      {:ok, value} -> Map.put(acc, key, fun.(value))
      :error -> acc
    end
  end

  defp put_password(acc, fields) do
    cond do
      not Map.has_key?(fields, "muc#roomconfig_passwordprotectedroom") ->
        acc

      truthy?(fields["muc#roomconfig_passwordprotectedroom"]) ->
        case fields["muc#roomconfig_roomsecret"] do
          secret when is_binary(secret) and secret != "" -> Map.put(acc, :password, secret)
          _ -> acc
        end

      true ->
        Map.put(acc, :password, nil)
    end
  end

  defp truthy?(v), do: v in ["1", "true", true]

  defp ensure do
    for t <- [@table, @index] do
      if :ets.whereis(t) == :undefined do
        :ets.new(t, [:named_table, :public, :set, read_concurrency: true, write_concurrency: true])
      end
    end
  end
end

defmodule Exjabberd.Mod.Muc.Room do
  @moduledoc "MUC room GenServer - `mod_muc_room`. Holds occupants, affiliations, configuration, subject and history for one room."

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
      config: %{
        title: "",
        persistent: true,
        password: nil,
        members_only: false,
        max_users: 200,
        history_size: 20,
        public: true
      }
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
  def set_config(pid, config), do: GenServer.call(pid, {:set_config, config})
  def set_subject(pid, from_bare, subject), do: GenServer.call(pid, {:set_subject, from_bare, subject})
  def destroy(pid, alternate_jid), do: GenServer.call(pid, {:destroy, alternate_jid})
  def get_state(pid), do: GenServer.call(pid, :get_state)

  @impl true
  def handle_call({:join, user_jid, nick, opts}, _from, state) do
    aff = Map.get(state.affiliations, user_jid, :none)
    occupant = Map.get(state.occupants, nick)

    cond do
      # Banned users may not join (XEP-0045 §9.1).
      aff == :outcast ->
        {:reply, {:error, :forbidden}, state}

      # Members-only rooms admit only affiliated users (§7.2).
      state.config.members_only and aff == :none ->
        {:reply, {:error, :registration_required}, state}

      # Password-protected rooms check the join password (§7.2).
      state.config.password not in [nil, ""] and
          Keyword.get(opts, :password) != state.config.password ->
        {:reply, {:error, :not_authorized}, state}

      # The nick is taken by someone else (§7.2: conflict).
      occupant != nil and occupant.jid != user_jid ->
        {:reply, {:error, :conflict}, state}

      # The room is full.
      occupant == nil and map_size(state.occupants) >= (state.config.max_users || 200) ->
        {:reply, {:error, :resource_constraint}, state}

      true ->
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

    # Archive the groupchat message in the room's MAM archive
    # (XEP-0313, owner = room bare JID) so a MAM query addressed to
    # the room returns the room history.
    Exjabberd.Mod.Mam.archive_muc(state.host, state.jid, nick, from, body)

    # Also archive via MAM if enabled
    _ = history
    {:reply, :ok, %{state | history: history}}
  end

  def handle_call({:affiliation, jid, aff}, _from, state) do
    next = put_in(state.affiliations[jid], aff)

    # Keep current occupants in sync and tell the room, like
    # mod_muc_room does when an affiliation changes.
    {victims, occupants} =
      Enum.split_with(next.occupants, fn {_nick, occ} -> occ.jid == jid end)

    next =
      if aff == :outcast do
        # Banned: the victim leaves with status 301, everyone else
        # sees the unavailable presence too.
        Enum.each(victims, fn {nick, occ} ->
          stanza =
            Exjabberd.Xmpp.Stanza.new(:presence,
              from: "#{state.jid}/#{nick}",
              to: occ.jid,
              type: "unavailable",
              payload: [muc_user_x(%{occ | affiliation: :outcast, role: :none}, ["301"])]
            )

          Exjabberd.Router.route(stanza)
          Enum.each(occupants, fn {_n, other} -> Exjabberd.Router.route(%{stanza | to: other.jid}) end)
        end)

        %{next | occupants: Map.new(occupants)}
      else
        role = if aff in [:owner, :admin], do: :moderator, else: :participant

        updated_victims =
          Map.new(victims, fn {nick, occ} -> {nick, %{occ | affiliation: aff, role: role}} end)

        next = %{next | occupants: Map.merge(Map.new(occupants), updated_victims)}

        Enum.each(updated_victims, fn {nick, _occ} ->
          broadcast_occupant_presence(next, nick)
        end)

        next
      end

    {:reply, :ok, next}
  end

  def handle_call({:kick, nick, reason}, _from, state) do
    case Map.pop(state.occupants, nick) do
      {nil, _} ->
        {:reply, {:error, :not_found}, state}

      {occ, rest} ->
        # The kicked occupant and everyone else get the unavailable
        # presence with status 307 (XEP-0045 §8.5).
        stanza =
          Exjabberd.Xmpp.Stanza.new(:presence,
            from: "#{state.jid}/#{nick}",
            to: occ.jid,
            type: "unavailable",
            payload: [muc_user_x(%{occ | role: :none}, ["307"], reason)]
          )

        Exjabberd.Router.route(stanza)
        Enum.each(rest, fn {_n, other} -> Exjabberd.Router.route(%{stanza | to: other.jid}) end)
        {:reply, :ok, %{state | occupants: rest}}
    end
  end

  def handle_call({:set_role, nick, role}, _from, state) do
    case Map.get(state.occupants, nick) do
      nil ->
        {:reply, {:error, :not_found}, state}

      occ ->
        next = put_in(state.occupants[nick], %{occ | role: role})
        broadcast_occupant_presence(next, nick)
        {:reply, :ok, next}
    end
  end

  def handle_call({:set_config, config}, _from, state) do
    merged =
      Enum.reduce([:title, :persistent, :public, :members_only, :password, :max_users, :history_size], state.config, fn key, acc ->
        if Map.has_key?(config, key), do: Map.put(acc, key, Map.fetch!(config, key)), else: acc
      end)

    {:reply, :ok, %{state | config: merged}}
  end

  def handle_call({:set_subject, from_bare, subject}, _from, state) do
    case Enum.find(state.occupants, fn {_nick, occ} -> occ.jid == from_bare end) do
      nil ->
        {:reply, {:error, :not_occupant}, state}

      {nick, _occ} ->
        Enum.each(state.occupants, fn {_n, occ} ->
          stanza =
            Exjabberd.Xmpp.Stanza.new(:message,
              type: "groupchat",
              from: "#{state.jid}/#{nick}",
              to: occ.jid,
              payload: [%{name: "subject", attrs: %{}, children: [subject]}]
            )

          Exjabberd.Router.route(stanza)
        end)

        {:reply, :ok, %{state | subject: subject, subject_author: nick}}
    end
  end

  def handle_call({:destroy, alternate_jid}, _from, state) do
    Enum.each(state.occupants, fn {nick, occ} ->
      destroy_el = %{
        name: "destroy",
        attrs: if(alternate_jid, do: %{"jid" => alternate_jid}, else: %{}),
        children: []
      }

      stanza =
        Exjabberd.Xmpp.Stanza.new(:presence,
          from: "#{state.jid}/#{nick}",
          to: occ.jid,
          type: "unavailable",
          payload: [muc_user_x(occ, ["110"]), destroy_el]
        )

      Exjabberd.Router.route(stanza)
    end)

    {:reply, :ok, state}
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

  # Send one occupant's (updated) presence to every occupant —
  # used after role/affiliation changes (XEP-0045 §8.6/§9.7).
  defp broadcast_occupant_presence(state, nick) do
    occ = Map.fetch!(state.occupants, nick)

    Enum.each(state.occupants, fn {_n, target} ->
      stanza =
        Exjabberd.Xmpp.Stanza.new(:presence,
          from: "#{state.jid}/#{nick}",
          to: target.jid,
          payload: [muc_user_x(occ, [])]
        )

      Exjabberd.Router.route(stanza)
    end)
  end

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
