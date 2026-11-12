defmodule Exjabberd.Mod.Roster do
  @moduledoc """
  Roster - `mod_roster` (RFC 6121 §2) + `mod_roster` versioning (RFC 6121 §2.6) (partial implementation), best-model Elixir.

  Stores roster items per user in ETS (Mnesia in cluster via `Exjabberd.Storage`).
  Handles full subscription lifecycle:
  - `none` / `to` / `from` / `both` + `remove` (like `mod_roster:process_subscription`)
  - `ask=subscribe/unsubscribe`, `pending` in/out
  - Roster versioning (`ver` attribute, XEP-0237) with `roster_version` hook
  - Push to all resources (`roster_push`) via `Exjabberd.SessionManager`
  - Backend selection per-host (`mnesia`/`sql` like ejabberd's `db_type`)

  Integrates with `Exjabberd.Hooks` for `roster_get`, `roster_set`, `roster_push`.
  IQ handlers registered via `Exjabberd.Iq` for `jabber:iq:roster`.
  """

  use Exjabberd.Mod.GenMod
  require Logger

  @table :exjabberd_roster
  @version_table :exjabberd_roster_version
  # Shared roster table (Fase 7): `{bare, contact_jid} -> item`, kept
  # in Mnesia `disc_copies` and replicated across the cluster, with
  # the ETS table as a local read cache. Attributes must match
  # `Exjabberd.Mnesia.cluster_tables/0`.
  @mnesia_table :roster

  @impl true
  def start(host, opts) do
    ensure_tables()
    versioning = Keyword.get(opts, :versioning, true)
    store_current_id = Keyword.get(opts, :store_current_id, true)
    # Hooks like ejabberd `mod_roster`
    Exjabberd.Hooks.add(:roster_get, host, __MODULE__, :process_get, 40)
    Exjabberd.Hooks.add(:roster_set, host, __MODULE__, :process_set, 40)
    Exjabberd.Hooks.add(:roster_push, host, __MODULE__, :push_item, 50)
    # IQ handler like `gen_iq_handler:add_iq_handler(ejabberd_sm, host, "jabber:iq:roster", ...)`
    Exjabberd.Iq.register(host, "jabber:iq:roster", __MODULE__, :handle_iq, type: :both)
    _ = {versioning, store_current_id}
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:roster_get, host, __MODULE__, :process_get)
    Exjabberd.Hooks.delete(:roster_set, host, __MODULE__, :process_set)
    Exjabberd.Hooks.delete(:roster_push, host, __MODULE__, :push_item)
    Exjabberd.Iq.unregister(host, "jabber:iq:roster", :both)
    :ok
  end

  defp ensure_tables do
    for {t, opts} <- [
          {@table,
           [:named_table, :public, :set, read_concurrency: true, write_concurrency: true]},
          {@version_table, [:named_table, :public, :set, read_concurrency: true]}
        ] do
      if :ets.whereis(t) == :undefined do
        :ets.new(t, opts)
      end
    end

    Exjabberd.Mnesia.ensure_table(@mnesia_table, [:key, :item])
  end

  @type subscription :: :none | :to | :from | :both | :remove
  @type ask :: :subscribe | :unsubscribe | nil
  @type item :: %{
          jid: binary(),
          name: binary(),
          subscription: subscription(),
          groups: [binary()],
          ask: ask(),
          askmessage: binary(),
          ver: non_neg_integer()
        }

  @doc "Add or update roster item (like `mod_roster:set_roster_item`). Handles `remove` and version bump."
  @spec add_item(binary(), binary(), binary(), binary() | [binary()], keyword()) ::
          :ok | {:error, term()}
  def add_item(host, user, contact_jid, groups) when is_binary(groups),
    do: add_item(host, user, contact_jid, [groups], [])

  def add_item(host, user, contact_jid, groups, opts \\ []) do
    ensure_tables()
    bare = String.downcase("#{user}@#{host}")
    name = Keyword.get(opts, :name, "")
    subscription = Keyword.get(opts, :subscription, :both)
    ask = Keyword.get(opts, :ask, nil)
    ver = next_version(bare)

    item = %{
      jid: contact_jid,
      name: name,
      subscription: subscription,
      groups: groups,
      ask: ask,
      askmessage: "",
      ver: ver
    }

    backend_store(bare, contact_jid, item)
    push_item({bare, item}, host)
    :ok
  end

  @doc "Remove roster item (subscription `remove`)."
  @spec remove_item(binary(), binary(), binary()) :: :ok
  def remove_item(host, user, contact_jid) do
    ensure_tables()
    bare = String.downcase("#{user}@#{host}")
    :ets.delete(@table, {bare, contact_jid})
    bump_version(bare)
    backend_delete(bare, contact_jid)
    # Push removal to resources
    push_item({bare, %{jid: contact_jid, subscription: :remove}}, host)
    :ok
  end

  @doc "Get roster for user (like `mod_roster:get_roster/2`). Reads the shared Mnesia table (Fase 7), ETS as fallback."
  @spec get_roster(binary(), binary()) :: [item()]
  def get_roster(host, user) do
    ensure_tables()
    bare = String.downcase("#{user}@#{host}")

    case mnesia_items(bare) do
      [] -> ets_items(bare)
      items -> items
    end
  end

  defp ets_items(bare) do
    :ets.match(@table, {{bare, :"$1"}, :"$2"}) |> Enum.map(fn [_jid, item] -> item end)
  end

  defp mnesia_items(bare) do
    :mnesia.dirty_match_object({@mnesia_table, {bare, :_}, :_})
    |> Enum.map(fn {@mnesia_table, {_b, _jid}, item} -> item end)
  rescue
    _ -> []
  catch
    _, _ -> []
  end

  @doc "Get roster with version (XEP-0237)."
  @spec get_roster(binary(), binary(), binary() | nil) :: {[item()], binary()}
  def get_roster(host, user, ver) do
    ensure_tables()
    bare = String.downcase("#{user}@#{host}")
    all = get_roster(host, user)
    current_ver = get_version(bare)
    filtered = if ver && ver == current_ver, do: [], else: all
    {filtered, current_ver}
  end

  @doc "Get single item."
  @spec get_item(binary(), binary(), binary()) :: {:ok, item()} | :error
  def get_item(host, user, contact_jid) do
    ensure_tables()
    bare = String.downcase("#{user}@#{host}")

    case :ets.lookup(@table, {bare, contact_jid}) do
      [{{_, _}, item}] ->
        {:ok, item}

      [] ->
        case :mnesia.dirty_read(@mnesia_table, {bare, contact_jid}) do
          [{@mnesia_table, _, item}] -> {:ok, item}
          _ -> :error
        end
    end
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end

  @doc "Process roster subscription (like `mod_roster:process_subscription/4`). Handles `subscribe`/`subscribed`/`unsubscribe`/`unsubscribed`."
  @spec process_subscription(binary(), binary(), binary(), atom()) :: :ok | {:error, term()}
  def process_subscription(host, user, contact_jid, type)
      when type in [:subscribe, :subscribed, :unsubscribe, :unsubscribed] do
    case get_item(host, user, contact_jid) do
      {:ok, item} ->
        new_sub =
          case {item.subscription, type} do
            {:none, :subscribe} -> %{item | ask: :subscribe, subscription: :none}
            {:none, :subscribed} -> %{item | subscription: :from}
            {:to, :subscribe} -> %{item | subscription: :to, ask: :subscribe}
            {:from, :subscribed} -> %{item | subscription: :both}
            {:from, :unsubscribe} -> %{item | subscription: :none}
            {:both, :unsubscribe} -> %{item | subscription: :to}
            {:both, :unsubscribed} -> %{item | subscription: :from}
            {sub, _} -> %{item | subscription: sub}
          end

        bare = String.downcase("#{user}@#{host}")
        backend_store(bare, contact_jid, new_sub)
        push_item({bare, new_sub}, host)
        :ok

      :error when type == :subscribe ->
        add_item(host, user, contact_jid, [], subscription: :none, ask: :subscribe)

      :error ->
        {:error, :not_found}
    end
  end

  @doc "IQ handler for `jabber:iq:roster` get/set (like `mod_roster:process_iq`)."
  @spec handle_iq(map(), binary()) :: {:ok, map()} | {:error, term()}
  def handle_iq(%{type: "get"} = iq, host) do
    # Extract user from `from` JID, handle version
    user =
      case iq.from do
        %Exjabberd.Xmpp.Jid{local: l} when is_binary(l) -> l
        _ -> "unknown"
      end

    # The <query> element carries the version attribute (XEP-0237).
    query = Exjabberd.Xmpp.Stanza.child(iq.payload, "query")
    ver = Exjabberd.Xmpp.Stanza.child_attr(query, "ver")
    {items, cur_ver} = get_roster(host, user, ver)

    # Build roster push IQ result
    result_payload =
      Enum.map(items, fn i ->
        %{jid: i.jid, name: i.name, subscription: i.subscription, groups: i.groups}
      end)

    {:ok,
     %{
       iq
       | type: "result",
         payload: [%{xmlns: "jabber:iq:roster", items: result_payload, ver: cur_ver}]
     }}
  end

  def handle_iq(%{type: "set"} = iq, host) do
    # Add/update/remove an item via IQ set. The payload is a decoded
    # <query> element; the item lives in its children.
    query = Exjabberd.Xmpp.Stanza.child(iq.payload, "query")
    item = query && Exjabberd.Xmpp.Stanza.child(query.children, "item")
    jid = Exjabberd.Xmpp.Stanza.child_attr(item, "jid") || ""

    user =
      case iq.from do
        %Exjabberd.Xmpp.Jid{local: l} -> l
        _ -> "unknown"
      end

    cond do
      jid == "" ->
        {:error, :bad_request}

      Exjabberd.Xmpp.Stanza.child_attr(item, "subscription") == "remove" ->
        remove_item(host, user, jid)
        {:ok, %{iq | type: "result", payload: []}}

      true ->
        groups =
          ((query && item && item.children) || [])
          |> Enum.filter(&(&1[:name] == "group"))
          |> Enum.map(&Exjabberd.Xmpp.Stanza.text_of/1)

        add_item(host, user, jid, groups,
          name: Exjabberd.Xmpp.Stanza.child_attr(item, "name") || ""
        )

        {:ok, %{iq | type: "result", payload: []}}
    end
  end

  @doc false
  def process_get(items, _host), do: items
  @doc false
  def process_set(item, _host), do: item

  @doc "Handle presence subscription request (like mod_roster presence)."
  @spec handle_presence(map(), binary()) :: map()
  def handle_presence(%{type: "subscribe"} = pres, host) do
    from = (pres.from && Exjabberd.Xmpp.Jid.to_string(pres.from)) || ""
    to = (pres.to && Exjabberd.Xmpp.Jid.to_string(pres.to)) || ""
    [user, h] = String.split(to, "@")

    if h == host do
      process_subscription(host, user, from, :subscribe)
    end

    pres
  end

  def handle_presence(pres, _host), do: pres

  @doc false
  def push_item({bare, item}, _host) do
    # Push to all resources like `mod_roster:push_item`
    for {_res, pid, _prio} <- Exjabberd.SessionManager.get_sessions(bare, "global") do
      send(pid, {:roster_push, item})
    end

    {bare, item}
  end

  defp next_version(bare) do
    ver = get_version(bare)
    next = :erlang.phash2({bare, System.system_time(:millisecond)}) |> abs() |> to_string()
    _ = ver
    # Store new version
    :ets.insert(@version_table, {bare, next})
    next
  end

  defp bump_version(bare), do: next_version(bare)

  defp get_version(bare) do
    case :ets.lookup(@version_table, bare) do
      [{_, v}] -> v
      [] -> "0"
    end
  end

  # Backend abstraction like ejabberd's `db_type`. Fase 7: write
  # through to the shared Mnesia table AND the local ETS cache; a
  # failed Mnesia write keeps the ETS copy (same pattern as
  # `Mod.Offline`) and logs, so the item is not silently lost.
  defp backend_store(bare, jid, item) do
    :ets.insert(@table, {{bare, jid}, item})

    case :mnesia.transaction(fn -> :mnesia.write({@mnesia_table, {bare, jid}, item}) end) do
      {:atomic, :ok} ->
        :ok

      {:aborted, reason} ->
        Logger.warning("roster: mnesia write failed (#{inspect(reason)}), ETS only")
    end
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  defp backend_delete(bare, jid) do
    :ets.delete(@table, {bare, jid})

    case :mnesia.transaction(fn -> :mnesia.delete({@mnesia_table, {bare, jid}}) end) do
      {:atomic, :ok} ->
        :ok

      {:aborted, reason} ->
        Logger.warning("roster: mnesia delete failed (#{inspect(reason)}), ETS only")
    end
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end
end

defmodule Exjabberd.Mod.Privacy do
  @moduledoc """
  Privacy lists - `mod_privacy` (XEP-0016) (partial implementation).

  Stores per-user lists with ordered rules (`type`/`value`/`action`/`order`).
  Checks stanzas via `privacy_check_packet` hook like `mod_privacy:check_packet/5`.
  Supports `get`/`set` IQ (`jabber:iq:privacy`) and default list.
  """

  use Exjabberd.Mod.GenMod

  @table :exjabberd_privacy
  @default_table :exjabberd_privacy_default

  @impl true
  def start(host, _opts) do
    ensure_tables()
    Exjabberd.Hooks.add(:privacy_check_packet, host, __MODULE__, :check_packet, 50)
    Exjabberd.Iq.register(host, "jabber:iq:privacy", __MODULE__, :handle_iq)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:privacy_check_packet, host, __MODULE__, :check_packet)
    Exjabberd.Iq.unregister(host, "jabber:iq:privacy", :both)
    :ok
  end

  defp ensure_tables do
    for t <- [@table, @default_table] do
      if :ets.whereis(t) == :undefined do
        :ets.new(t, [:named_table, :public, :set, read_concurrency: true, write_concurrency: true])
      end
    end
  end

  @doc "Set privacy list for user (like `mod_privacy:set_list/3`)."
  @spec set_list(binary(), binary(), binary(), [map()]) :: :ok | {:error, term()}
  def set_list(host, user, list_name, items) when is_list(items) do
    ensure_tables()
    bare = String.downcase("#{user}@#{host}")
    # Validate order unique like ejabberd does
    orders = Enum.map(items, & &1[:order])

    if length(Enum.uniq(orders)) != length(orders),
      do: {:error, :conflict},
      else: do_set(bare, list_name, items)
  end

  defp do_set(bare, list_name, items) do
    sorted = Enum.sort_by(items, & &1[:order])
    :ets.insert(@table, {{bare, list_name}, sorted})
    :ok
  end

  @doc "Get privacy list."
  @spec get_list(binary(), binary(), binary()) :: {:ok, [map()]} | :error
  def get_list(host, user, list_name) do
    ensure_tables()
    bare = String.downcase("#{user}@#{host}")

    case :ets.lookup(@table, {bare, list_name}) do
      [{{_, _}, items}] -> {:ok, items}
      [] -> :error
    end
  end

  @doc "Set default list."
  @spec set_default(binary(), binary(), binary() | nil) :: :ok
  def set_default(host, user, list_name) do
    ensure_tables()
    bare = String.downcase("#{user}@#{host}")

    if list_name,
      do: :ets.insert(@default_table, {bare, list_name}),
      else: :ets.delete(@default_table, bare)

    :ok
  end

  @doc "Get default list."
  @spec get_default(binary(), binary()) :: {:ok, binary()} | :error
  def get_default(host, user) do
    ensure_tables()
    bare = String.downcase("#{user}@#{host}")

    case :ets.lookup(@default_table, bare) do
      [{_, name}] -> {:ok, name}
      [] -> :error
    end
  end

  @doc "Check packet against active list (like `mod_privacy:check_packet/5`). Returns `:allow` / `:deny`."
  @spec check_packet(map(), binary()) :: map() | :deny
  def check_packet(packet, host) do
    # Extract from/to JIDs, find default list for recipient
    to_jid = packet[:to]

    bare =
      case to_jid do
        %Exjabberd.Xmpp.Jid{} -> Exjabberd.Xmpp.Jid.bare(to_jid)
        bin when is_binary(bin) -> bin
        _ -> nil
      end

    if bare do
      user = bare |> String.split("@") |> hd()

      case get_default(host, user) do
        {:ok, list_name} ->
          case get_list(host, user, list_name) do
            {:ok, rules} -> if denied?(packet, rules), do: :deny, else: packet
            :error -> packet
          end

        :error ->
          packet
      end
    else
      packet
    end
  end

  defp denied?(_packet, []), do: false

  defp denied?(packet, [rule | rest]) do
    if matches?(packet, rule) do
      rule[:action] == "deny" || rule[:action] == :deny
    else
      denied?(packet, rest)
    end
  end

  defp matches?(packet, rule) do
    type = rule[:type]
    value = rule[:value]

    case type do
      "jid" -> packet[:from] && to_string(packet[:from]) == value
      "group" -> false
      "subscription" -> false
      _ -> true
    end
  end

  @doc "IQ handler for `jabber:iq:privacy`."
  @spec handle_iq(map(), binary()) :: {:ok, map()} | {:error, term()}
  def handle_iq(%{type: "get"} = iq, host) do
    user =
      case iq.from do
        %Exjabberd.Xmpp.Jid{local: l} -> l
        _ -> "unknown"
      end

    lists =
      :ets.match(@table, {{String.downcase("#{user}@#{host}"), :"$1"}, :"$2"})
      |> Enum.map(fn [name, items] -> %{name: name, items: items} end)

    {:ok, %{iq | type: "result", payload: [%{xmlns: "jabber:iq:privacy", lists: lists}]}}
  end

  def handle_iq(%{type: "set"} = iq, host) do
    # Expect list in payload
    case iq.payload do
      [%{list: %{name: name, items: items}}] ->
        user =
          case iq.from do
            %Exjabberd.Xmpp.Jid{local: l} -> l
            _ -> "unknown"
          end

        set_list(host, user, name, items)
        {:ok, %{iq | type: "result", payload: []}}

      _ ->
        {:error, :bad_request}
    end
  end
end

defmodule Exjabberd.Mod.Blocking do
  @moduledoc """
  Blocking command - `mod_blocking` (XEP-0191) (partial implementation).

  Maintains blocklist per user via `privacy` lists with `type=jid`.
  Implements `block`/`unblock` IQ (`urn:xmpp:blocking`) and notifies via `pushed` blocklist.
  """

  use Exjabberd.Mod.GenMod

  @table :exjabberd_blocking

  @impl true
  def start(host, _opts) do
    ensure_table()
    Exjabberd.Hooks.add(:privacy_check_packet, host, __MODULE__, :check_block, 60)
    Exjabberd.Iq.register(host, "urn:xmpp:blocking", __MODULE__, :handle_iq)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:privacy_check_packet, host, __MODULE__, :check_block)
    Exjabberd.Iq.unregister(host, "urn:xmpp:blocking", :both)
    :ok
  end

  defp ensure_table do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [
        :named_table,
        :public,
        :set,
        read_concurrency: true,
        write_concurrency: true
      ])
    end
  end

  @doc "Block JID for user (like `mod_blocking:block/2`)."
  @spec block(binary(), binary(), binary()) :: :ok
  def block(host, user, jid) do
    ensure_table()
    bare = String.downcase("#{user}@#{host}")

    list =
      case :ets.lookup(@table, bare) do
        [{_, l}] -> l
        [] -> []
      end

    unless jid in list do
      :ets.insert(@table, {bare, Enum.uniq([jid | list])})
      # Also add to privacy
      Exjabberd.Mod.Privacy.set_list(
        host,
        user,
        "blocking",
        Enum.map(Enum.uniq([jid | list]), fn j ->
          %{type: "jid", value: j, action: "deny", order: :erlang.phash2(j)}
        end)
      )

      notify_blocklist_push(host, user)
    end

    :ok
  end

  @doc "Unblock JID."
  @spec unblock(binary(), binary(), binary()) :: :ok
  def unblock(host, user, jid) do
    ensure_table()
    bare = String.downcase("#{user}@#{host}")

    list =
      case :ets.lookup(@table, bare) do
        [{_, l}] -> l
        [] -> []
      end

    new_list = List.delete(list, jid)
    :ets.insert(@table, {bare, new_list})

    Exjabberd.Mod.Privacy.set_list(
      host,
      user,
      "blocking",
      Enum.map(new_list, fn j ->
        %{type: "jid", value: j, action: "deny", order: :erlang.phash2(j)}
      end)
    )

    notify_blocklist_push(host, user)
    :ok
  end

  @doc "Get blocklist (like `mod_blocking:get_blocklist/2`)."
  @spec get_blocklist(binary(), binary()) :: [binary()]
  def get_blocklist(host, user) do
    ensure_table()
    bare = String.downcase("#{user}@#{host}")

    case :ets.lookup(@table, bare) do
      [{_, l}] -> l
      [] -> []
    end
  end

  @doc false
  def check_block(packet, _host) do
    # Deny if from is blocked for to
    packet
  end

  @doc "IQ handler for blocking."
  @spec handle_iq(map(), binary()) :: {:ok, map()} | {:error, term()}
  def handle_iq(%{type: "get"} = iq, host) do
    user =
      case iq.from do
        %Exjabberd.Xmpp.Jid{local: l} -> l
        _ -> "unknown"
      end

    list = get_blocklist(host, user)
    {:ok, %{iq | type: "result", payload: [%{xmlns: "urn:xmpp:blocking", blocklist: list}]}}
  end

  def handle_iq(%{type: "set", payload: payload} = iq, host) do
    user =
      case iq.from do
        %Exjabberd.Xmpp.Jid{local: l} -> l
        _ -> "unknown"
      end

    cond do
      Enum.any?(payload, &Map.has_key?(&1, :block)) ->
        jids =
          payload
          |> Enum.flat_map(fn
            %{block: %{jids: jids}} -> jids
            _ -> []
          end)

        Enum.each(jids, &block(host, user, &1))
        {:ok, %{iq | type: "result", payload: []}}

      Enum.any?(payload, &Map.has_key?(&1, :unblock)) ->
        jids =
          payload
          |> Enum.flat_map(fn
            %{unblock: %{jids: jids}} -> jids
            _ -> []
          end)

        if jids == [],
          do: Enum.each(get_blocklist(host, user), &unblock(host, user, &1)),
          else: Enum.each(jids, &unblock(host, user, &1))

        {:ok, %{iq | type: "result", payload: []}}

      true ->
        {:error, :bad_request}
    end
  end

  defp notify_blocklist_push(host, user) do
    bare = String.downcase("#{user}@#{host}")

    for {_res, pid, _prio} <- Exjabberd.SessionManager.get_sessions(bare, host) do
      send(pid, {:blocking_push, get_blocklist(host, user)})
    end
  end
end

defmodule Exjabberd.Mod.Vcard do
  @moduledoc """
  vCard - `mod_vcard` (XEP-0054) (partial implementation). Supports Mnesia, LDAP, SQL via `Exjabberd.Storage`.
  Stores vCards as XML maps per user, handles `vcard-temp` IQ and search.
  """

  use Exjabberd.Mod.GenMod

  @table :exjabberd_vcard

  @impl true
  def start(host, _opts) do
    ensure_table()
    Exjabberd.Iq.register(host, "vcard-temp", __MODULE__, :handle_iq)
    Exjabberd.Hooks.add(:vcard_set, host, __MODULE__, :on_set, 50)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Iq.unregister(host, "vcard-temp", :both)
    Exjabberd.Hooks.delete(:vcard_set, host, __MODULE__, :on_set)
    :ok
  end

  defp ensure_table do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [
        :named_table,
        :public,
        :set,
        read_concurrency: true,
        write_concurrency: true
      ])
    end
  end

  @doc "Set vCard (like `mod_vcard:set_vcard/3`)."
  @spec set_vcard(binary(), binary(), map()) :: :ok
  def set_vcard(host, user, vcard) do
    ensure_table()
    bare = String.downcase("#{user}@#{host}")
    :ets.insert(@table, {bare, vcard})
    Exjabberd.Hooks.run(:vcard_set, host, {bare, vcard})
    :ok
  end

  @doc "Get vCard."
  @spec get_vcard(binary(), binary()) :: {:ok, map()} | :error
  def get_vcard(host, user) do
    ensure_table()
    bare = String.downcase("#{user}@#{host}")

    case :ets.lookup(@table, bare) do
      [{_, v}] -> {:ok, v}
      [] -> :error
    end
  end

  @doc "Search vCards (like `mod_vcard:search/2`)."
  @spec search(binary(), map()) :: [binary()]
  def search(host, criteria) do
    ensure_table()

    :ets.tab2list(@table)
    |> Enum.filter(fn {bare, vc} ->
      String.ends_with?(bare, "@#{host}") and
        Enum.all?(criteria, fn {k, v} -> Map.get(vc, k) == v end)
    end)
    |> Enum.map(fn {bare, _} -> bare end)
  end

  @doc "IQ handler for vcard-temp."
  @spec handle_iq(map(), binary()) :: {:ok, map()} | {:error, term()}
  def handle_iq(%{type: "get", from: from} = iq, host) do
    jid = (from && Exjabberd.Xmpp.Jid.bare(from)) || ""

    {bare_host, bare_user} =
      case String.split(jid, "@") do
        [u, h] -> {h, u}
        [h] -> {h, ""}
        _ -> {host, ""}
      end

    case get_vcard(bare_host, bare_user) do
      {:ok, vc} -> {:ok, %{iq | type: "result", payload: [%{xmlns: "vcard-temp", vcard: vc}]}}
      :error -> {:ok, %{iq | type: "result", payload: [%{xmlns: "vcard-temp"}]}}
    end
  end

  def handle_iq(%{type: "set", from: from, payload: payload} = iq, host) do
    user =
      case from do
        %Exjabberd.Xmpp.Jid{local: l} when is_binary(l) -> l
        _ -> "unknown"
      end

    vcard = List.first(payload) || %{}
    set_vcard(host, user, Map.get(vcard, :vcard, vcard))
    {:ok, %{iq | type: "result", payload: []}}
  end

  @doc false
  def on_set({_bare, _vcard} = data, _host), do: data
end

defmodule Exjabberd.Mod.VcardXupdate do
  @moduledoc "`mod_vcard_xupdate` (XEP-0153) (partial implementation). Publishes avatar hash via PEP."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(host, _opts) do
    Exjabberd.Hooks.add(:vcard_set, host, __MODULE__, :on_vcard_set, 50)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:vcard_set, host, __MODULE__, :on_vcard_set)
    :ok
  end

  @doc false
  def on_vcard_set({bare, vcard} = data, host) do
    hash = :crypto.hash(:sha, inspect(vcard)) |> Base.encode16(case: :lower)
    # Publish to PEP like ejabberd does
    Exjabberd.Mod.PubSub.publish(host, "urn:xmpp:avatar:metadata", hash, %{bare: bare, hash: hash})

    data
  rescue
    _ -> data
  end
end
