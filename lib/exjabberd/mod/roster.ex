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

    # Like ejabberd's roster set: a plain roster update changes only
    # name/groups — the subscription state (subscription/ask and the
    # pending-in flag) belongs to the presence subscription flow and
    # is preserved. A brand-new item starts at `none`.
    existing =
      case get_item(host, user, contact_jid) do
        {:ok, item} -> item
        :error -> nil
      end

    subscription =
      cond do
        Keyword.has_key?(opts, :subscription) -> Keyword.get(opts, :subscription)
        existing -> Map.get(existing, :subscription, :none)
        true -> :none
      end

    ask =
      cond do
        Keyword.has_key?(opts, :ask) -> Keyword.get(opts, :ask)
        existing -> Map.get(existing, :ask)
        true -> nil
      end

    pending_in = if existing, do: Map.get(existing, :pending_in, false), else: false
    ver = next_version(bare)

    item = %{
      jid: contact_jid,
      name: name,
      subscription: subscription,
      groups: groups,
      ask: ask,
      pending_in: pending_in,
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

    # Mnesia first, like get_roster/2: in a cluster the local ETS
    # copy goes stale (subscription updates written by another node
    # land in the shared Mnesia table only), and a stale read here
    # corrupts the RFC 6121 state machine (Fase 11 fix). ETS remains
    # the fallback for rows whose Mnesia write failed.
    case mnesia_item(bare, contact_jid) do
      {:ok, item} ->
        {:ok, item}

      :error ->
        case :ets.lookup(@table, {bare, contact_jid}) do
          [{{_, _}, item}] -> {:ok, item}
          [] -> :error
        end
    end
  end

  defp mnesia_item(bare, contact_jid) do
    case :mnesia.dirty_read(@mnesia_table, {bare, contact_jid}) do
      [{@mnesia_table, _, item}] -> {:ok, item}
      _ -> :error
    end
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end

  @doc "Roster groups of `contact_jid` in `user`'s roster (for XEP-0016 `group` rules)."
  @spec groups_for(binary(), binary(), binary()) :: [binary()]
  def groups_for(host, user, contact_jid) do
    case get_item(host, user, contact_jid) do
      {:ok, item} -> Map.get(item, :groups, []) || []
      :error -> []
    end
  end

  @doc "Subscription state of `contact_jid` in `user`'s roster as a string (for XEP-0016 `subscription` rules)."
  @spec subscription_of(binary(), binary(), binary()) :: binary()
  def subscription_of(host, user, contact_jid) do
    case get_item(host, user, contact_jid) do
      {:ok, item} -> item |> Map.get(:subscription, :none) |> to_string()
      :error -> "none"
    end
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
        %{
          jid: i.jid,
          name: i.name,
          subscription: i.subscription,
          ask: Map.get(i, :ask),
          groups: i.groups
        }
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

  @doc """
  Process a subscription presence stanza between two local users
  (RFC 6121 §3–§4), like `mod_roster` does inside ejabberd's
  presence handling: updates BOTH users' roster items (state
  machine on `subscription` / `ask` / pending-in), pushes every
  changed item to that user's sessions, and — when a subscription
  is approved — exchanges the recorded current presence between
  the two users. Called by C2S before the stanza itself is routed
  to its addressee (who still receives it, so clients can react).
  """
  @spec process_subscription_stanza(binary(), map()) :: :ok
  def process_subscription_stanza(host, %{name: :presence, type: type} = stanza)
      when type in ["subscribe", "subscribed", "unsubscribe", "unsubscribed"] do
    from_bare = stanza.from && Exjabberd.Xmpp.Jid.bare(stanza.from)
    to_bare = stanza.to && Exjabberd.Xmpp.Jid.bare(stanza.to)

    with true <- is_binary(from_bare) and is_binary(to_bare),
         [s_user, s_host] <- String.split(from_bare, "@", parts: 2),
         [t_user, t_host] <- String.split(to_bare, "@", parts: 2),
         true <- s_host == host and t_host == host,
         true <- from_bare != to_bare do
      apply_subscription(host, s_user, from_bare, t_user, to_bare, type)
    else
      _ -> :ok
    end
  end

  def process_subscription_stanza(_host, _stanza), do: :ok

  defp apply_subscription(host, s_user, s_bare, t_user, t_bare, type) do
    s_item = fetch_or_new(host, s_user, t_bare)
    t_item = fetch_or_new(host, t_user, s_bare)

    {s_new, t_new} = subscription_transition(s_item, t_item, type)

    store_if_changed(host, s_bare, t_bare, s_item, s_new)
    store_if_changed(host, t_bare, s_bare, t_item, t_new)

    if type == "subscribed" do
      # Presence exchange on approval: the new subscriber receives
      # the approver's recorded presence, and the approver receives
      # the subscriber's when the approval made it mutual.
      if Map.get(t_new, :subscription) in [:to, :both],
        do: deliver_recorded(s_bare, t_bare)

      if Map.get(s_new, :subscription) in [:to, :both],
        do: deliver_recorded(t_bare, s_bare)
    end

    :ok
  end

  defp deliver_recorded(from_bare, to_bare) do
    [u, h] = String.split(to_bare, "@", parts: 2)
    to_jid = %Exjabberd.Xmpp.Jid{local: u, domain: h}

    Exjabberd.Router.recorded_presences(from_bare)
    |> Enum.each(fn pres -> Exjabberd.Router.route(%{pres | to: to_jid}) end)
  end

  defp fetch_or_new(host, user, contact_jid) do
    case get_item(host, user, contact_jid) do
      {:ok, item} ->
        item
        |> Map.put_new(:ask, nil)
        |> Map.put_new(:pending_in, false)
        |> Map.put_new(:name, "")
        |> Map.put_new(:groups, [])

      :error ->
        %{
          jid: contact_jid,
          name: "",
          groups: [],
          subscription: :none,
          ask: nil,
          pending_in: false
        }
    end
  end

  defp store_if_changed(host, owner_bare, contact_jid, old, new) do
    if old != new do
      backend_store(owner_bare, contact_jid, new)
      bump_version(owner_bare)
      push_item({owner_bare, new}, host)
    end

    :ok
  end

  # The RFC 6121 subscription state machine. `s` is the stanza
  # sender's item for the addressee, `t` the addressee's item for
  # the sender. `pending_in` on an item means "this contact has a
  # subscription request waiting for my approval" (ejabberd stores
  # the same state in its roster records).
  defp subscription_transition(s, t, "subscribe") do
    s = if s.subscription in [:none, :from], do: Map.put(s, :ask, :subscribe), else: s
    t = if t.subscription in [:none, :to], do: Map.put(t, :pending_in, true), else: t
    {s, t}
  end

  defp subscription_transition(s, t, "subscribed") do
    s =
      s
      |> Map.put(:subscription, upgrade_from(s.subscription))
      |> Map.put(:pending_in, false)

    t =
      t
      |> Map.put(:subscription, upgrade_to(t.subscription))
      |> Map.put(:ask, nil)

    {s, t}
  end

  defp subscription_transition(s, t, "unsubscribed") do
    s =
      cond do
        Map.get(s, :pending_in) -> Map.put(s, :pending_in, false)
        s.subscription == :from -> Map.put(s, :subscription, :none)
        s.subscription == :both -> Map.put(s, :subscription, :to)
        true -> s
      end

    t =
      cond do
        t.ask == :subscribe and t.subscription in [:none, :from] ->
          Map.put(t, :ask, nil)

        t.subscription == :to ->
          t |> Map.put(:subscription, :none) |> Map.put(:ask, nil)

        t.subscription == :both ->
          t |> Map.put(:subscription, :from) |> Map.put(:ask, nil)

        true ->
          t
      end

    {s, t}
  end

  defp subscription_transition(s, t, "unsubscribe") do
    s =
      case s.subscription do
        :to -> s |> Map.put(:subscription, :none) |> Map.put(:ask, nil)
        :both -> s |> Map.put(:subscription, :from) |> Map.put(:ask, nil)
        _ -> Map.put(s, :ask, nil)
      end

    t =
      case t.subscription do
        :from -> Map.put(t, :subscription, :none)
        :both -> Map.put(t, :subscription, :to)
        _ -> t
      end
      |> Map.put(:pending_in, false)

    {s, t}
  end

  defp upgrade_from(:none), do: :from
  defp upgrade_from(:to), do: :both
  defp upgrade_from(other), do: other

  defp upgrade_to(:none), do: :to
  defp upgrade_to(:from), do: :both
  defp upgrade_to(other), do: other

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
  Privacy lists - `mod_privacy` (XEP-0016).

  Stores per-user lists with ordered rules (`type`/`value`/`action`/`order`,
  optional stanza-type children). Enforcement runs on the
  `:privacy_check_packet` hook from the router: the recipient's
  active list wins, else the default list; the first matching rule
  decides. Supports the full `jabber:iq:privacy` protocol: list
  get/set/delete, `<active/>` and `<default/>` management.
  """

  use Exjabberd.Mod.GenMod

  alias Exjabberd.Xmpp.{Jid, Stanza}

  @table :exjabberd_privacy
  @default_table :exjabberd_privacy_default
  @active_table :exjabberd_privacy_active

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
    for t <- [@table, @default_table, @active_table] do
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

  @doc "Set the active list for a user (XEP-0016 `<active/>`; `nil` clears it)."
  @spec set_active(binary(), binary(), binary() | nil) :: :ok
  def set_active(host, user, list_name) do
    ensure_tables()
    bare = String.downcase("#{user}@#{host}")

    if list_name,
      do: :ets.insert(@active_table, {bare, list_name}),
      else: :ets.delete(@active_table, bare)

    :ok
  end

  @doc "Get the active list for a user."
  @spec get_active(binary(), binary()) :: {:ok, binary()} | :error
  def get_active(host, user) do
    ensure_tables()
    bare = String.downcase("#{user}@#{host}")

    case :ets.lookup(@active_table, bare) do
      [{_, name}] -> {:ok, name}
      [] -> :error
    end
  end

  @doc "All privacy list names a user has defined."
  @spec list_names(binary(), binary()) :: [binary()]
  def list_names(host, user) do
    ensure_tables()
    bare = String.downcase("#{user}@#{host}")

    :ets.match(@table, {{bare, :"$1"}, :_})
    |> Enum.map(fn [name] -> name end)
    |> Enum.sort()
  end

  @doc "Delete a privacy list (XEP-0016: setting an empty list removes it)."
  @spec delete_list(binary(), binary(), binary()) :: :ok
  def delete_list(host, user, list_name) do
    ensure_tables()
    bare = String.downcase("#{user}@#{host}")
    :ets.delete(@table, {bare, list_name})
    if get_default(host, user) == {:ok, list_name}, do: set_default(host, user, nil)
    if get_active(host, user) == {:ok, list_name}, do: set_active(host, user, nil)
    :ok
  end

  @doc "Check packet against active list (like `mod_privacy:check_packet/5`). Returns `:allow` / `:deny`."
  @spec check_packet(map(), binary()) :: map() | :deny
  def check_packet(packet, host) do
    # Extract from/to JIDs, find the effective list for the recipient:
    # the session's active list wins, else the default list (XEP-0016).
    to_jid = packet[:to]

    bare =
      case to_jid do
        %Exjabberd.Xmpp.Jid{} -> Exjabberd.Xmpp.Jid.bare(to_jid)
        bin when is_binary(bin) -> bin
        _ -> nil
      end

    if bare do
      user = bare |> String.split("@") |> hd()

      effective =
        case get_active(host, user) do
          {:ok, name} ->
            name

          :error ->
            case get_default(host, user) do
              {:ok, name} -> name
              :error -> nil
            end
        end

      case effective do
        nil ->
          packet

        list_name ->
          case get_list(host, user, list_name) do
            {:ok, rules} -> if denied?(packet, rules), do: :deny, else: packet
            :error -> packet
          end
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

  # XEP-0016 matching: a rule matches when its type test passes AND
  # either it has no stanza-type children or the packet's stanza kind
  # is one of them (`message`, `iq`, `presence-in`, `presence-out`).
  defp matches?(packet, rule) do
    stanza_ok? =
      case Map.get(rule, :only) do
        nil -> true
        [] -> true
        only -> stanza_kind(packet) in only
      end

    stanza_ok? and type_matches?(packet, rule)
  end

  defp stanza_kind(%{name: :message}), do: "message"
  defp stanza_kind(%{name: :iq}), do: "iq"
  defp stanza_kind(%{name: :presence}), do: "presence-in"
  defp stanza_kind(_), do: nil

  defp type_matches?(packet, rule) do
    from_bare = bare_of(packet[:from])
    from_full = full_of(packet[:from])

    case rule[:type] do
      "jid" ->
        value = rule[:value] || ""
        value == from_bare or value == from_full

      "group" ->
        # The sender's roster group for the recipient — checked via
        # the recipient's roster groups for the sender's bare JID.
        case packet[:to] do
          nil ->
            false

          to ->
            user = to |> bare_of() |> String.split("@") |> hd()
            host = to |> bare_of() |> String.split("@") |> List.last()
            groups = Exjabberd.Mod.Roster.groups_for(host, user, from_bare)
            (rule[:value] || "") in groups
        end

      "subscription" ->
        case packet[:to] do
          nil ->
            false

          to ->
            user = to |> bare_of() |> String.split("@") |> hd()
            host = to |> bare_of() |> String.split("@") |> List.last()
            sub = Exjabberd.Mod.Roster.subscription_of(host, user, from_bare)
            (rule[:value] || "none") == (sub || "none")
        end

      _ ->
        # `type` absent = fall-through rule: matches everything.
        true
    end
  end

  defp bare_of(%Jid{} = jid), do: Jid.bare(jid)
  defp bare_of(bin) when is_binary(bin), do: bin |> String.split("/") |> hd()
  defp bare_of(_), do: nil

  defp full_of(%Jid{} = jid), do: Jid.to_string(jid)
  defp full_of(bin) when is_binary(bin), do: bin
  defp full_of(_), do: nil

  @doc "IQ handler for `jabber:iq:privacy` (XEP-0016, generic wire elements)."
  @spec handle_iq(map(), binary()) :: {:ok, map()} | {:error, term()}
  def handle_iq(%{type: "get"} = iq, host) do
    user = iq_user(iq)
    query = Stanza.child(iq.payload, "query")

    case query && Stanza.child(query.children, "list") do
      %{attrs: %{"name" => name}} ->
        case get_list(host, user, name) do
          {:ok, items} ->
            {:ok, result(iq, [list_element(name, items)])}

          :error ->
            {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}
        end

      _ ->
        children =
          case get_active(host, user) do
            {:ok, name} -> [%{name: "active", attrs: %{"name" => name}, children: []}]
            :error -> []
          end ++
            case get_default(host, user) do
              {:ok, name} -> [%{name: "default", attrs: %{"name" => name}, children: []}]
              :error -> []
            end ++
            Enum.map(list_names(host, user), fn name ->
              %{name: "list", attrs: %{"name" => name}, children: []}
            end)

        {:ok, result(iq, children)}
    end
  end

  def handle_iq(%{type: "set"} = iq, host) do
    user = iq_user(iq)
    query = Stanza.child(iq.payload, "query")

    if query == nil do
      {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
    else
      Enum.each(query.children, fn
        %{name: "list", attrs: %{"name" => name}} = el ->
          items = parse_items(el)

          if items == [] do
            delete_list(host, user, name)
          else
            set_list(host, user, name, items)
          end

        %{name: "active"} = el ->
          set_active(host, user, Stanza.child_attr(el, "name"))

        %{name: "default"} = el ->
          set_default(host, user, Stanza.child_attr(el, "name"))

        _ ->
          :ok
      end)

      {:ok, %{iq | type: "result", payload: []}}
    end
  end

  def handle_iq(iq, _host),
    do: {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

  defp result(iq, query_children) do
    %{
      iq
      | type: "result",
        payload: [
          %{name: "query", attrs: %{"xmlns" => "jabber:iq:privacy"}, children: query_children}
        ]
    }
  end

  defp list_element(name, items) do
    %{
      name: "list",
      attrs: %{"name" => name},
      children:
        Enum.map(items, fn item ->
          attrs =
            %{
              "action" => to_string(item[:action] || "allow"),
              "order" => to_string(item[:order] || 0)
            }
            |> maybe_put("type", item[:type])
            |> maybe_put("value", item[:value])

          %{
            name: "item",
            attrs: attrs,
            children:
              Enum.map(Map.get(item, :only, []), fn kind ->
                %{name: kind, attrs: %{}, children: []}
              end)
          }
        end)
    }
  end

  defp parse_items(%{children: children}) do
    children
    |> Enum.filter(&match?(%{name: "item"}, &1))
    |> Enum.map(fn item ->
      {order, _} = Integer.parse(Stanza.child_attr(item, "order") || "0")

      %{
        type: Stanza.child_attr(item, "type"),
        value: Stanza.child_attr(item, "value"),
        action: Stanza.child_attr(item, "action") || "allow",
        order: order,
        only:
          item.children
          |> Enum.filter(&is_map/1)
          |> Enum.map(& &1.name)
          |> Enum.filter(&(&1 in ["message", "iq", "presence-in", "presence-out"]))
      }
    end)
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, to_string(value))

  defp iq_user(iq) do
    case iq.from do
      %Jid{local: l} when is_binary(l) -> l
      _ -> "unknown"
    end
  end
end

defmodule Exjabberd.Mod.Blocking do
  @moduledoc """
  Blocking command - `mod_blocking` (XEP-0191).

  Maintains a blocklist per user. Implements the `block` / `unblock` /
  blocklist-get IQs (`urn:xmpp:blocking`), pushes blocklist changes
  to the user's other resources, and enforces the list on the
  `:privacy_check_packet` router hook: stanzas from a blocked JID
  are not delivered (IQs are answered `service-unavailable`).
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
  def check_block(:deny, _host), do: :deny

  def check_block(packet, _host) when is_map(packet) do
    # Deny when the sender is on the recipient's blocklist (XEP-0191).
    # Runs on the :privacy_check_packet fold from the router, so it
    # covers online delivery and offline storage alike.
    to_bare = bare_of(packet[:to])
    from_bare = bare_of(packet[:from])

    cond do
      is_nil(to_bare) or is_nil(from_bare) ->
        packet

      to_bare == from_bare ->
        packet

      true ->
        [user, host] = String.split(to_bare, "@", parts: 2)
        list = get_blocklist(host, user)

        if from_bare in list or full_of(packet[:from]) in list,
          do: :deny,
          else: packet
    end
  end

  def check_block(packet, _host), do: packet

  defp bare_of(%Exjabberd.Xmpp.Jid{} = jid), do: Exjabberd.Xmpp.Jid.bare(jid)
  defp bare_of(bin) when is_binary(bin), do: bin |> String.split("/") |> hd()
  defp bare_of(_), do: nil

  defp full_of(%Exjabberd.Xmpp.Jid{} = jid), do: Exjabberd.Xmpp.Jid.to_string(jid)
  defp full_of(bin) when is_binary(bin), do: bin
  defp full_of(_), do: nil

  @doc "IQ handler for blocking (XEP-0191, generic wire elements)."
  @spec handle_iq(map(), binary()) :: {:ok, map()} | {:error, term()}
  def handle_iq(%{type: "get"} = iq, host) do
    user = iq_user(iq)
    list = get_blocklist(host, user)

    {:ok,
     %{
       iq
       | type: "result",
         payload: [
           %{
             name: "blocklist",
             attrs: %{"xmlns" => "urn:xmpp:blocking"},
             children:
               Enum.map(list, fn jid ->
                 %{name: "item", attrs: %{"jid" => jid}, children: []}
               end)
           }
         ]
     }}
  end

  def handle_iq(%{type: "set"} = iq, host) do
    user = iq_user(iq)
    alias Exjabberd.Xmpp.Stanza

    cond do
      (block_el = Stanza.child(iq.payload, "block")) != nil ->
        Enum.each(item_jids(block_el), &block(host, user, &1))
        {:ok, %{iq | type: "result", payload: []}}

      (unblock_el = Stanza.child(iq.payload, "unblock")) != nil ->
        case item_jids(unblock_el) do
          [] -> Enum.each(get_blocklist(host, user), &unblock(host, user, &1))
          jids -> Enum.each(jids, &unblock(host, user, &1))
        end

        {:ok, %{iq | type: "result", payload: []}}

      true ->
        {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
    end
  end

  def handle_iq(iq, _host),
    do: {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

  defp item_jids(el) do
    el.children
    |> Enum.filter(&match?(%{name: "item"}, &1))
    |> Enum.map(&Exjabberd.Xmpp.Stanza.child_attr(&1, "jid"))
    |> Enum.reject(&is_nil/1)
  end

  defp iq_user(iq) do
    case iq.from do
      %Exjabberd.Xmpp.Jid{local: l} when is_binary(l) -> l
      _ -> "unknown"
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
  vCard - `mod_vcard` (XEP-0054).

  Stores each user's vCard XML element verbatim in ETS and answers
  `vcard-temp` IQs: a `set` replaces the sender's own vCard, a `get`
  returns the *addressee's* vCard (any user may fetch any local
  user's vCard, as in ejabberd). Storage is in-memory (ETS), so
  vCards do not survive a server restart.
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

  @doc "IQ handler for vcard-temp (XEP-0054, generic wire elements)."
  @spec handle_iq(map(), binary()) :: {:ok, map()} | {:error, term()}
  def handle_iq(%{type: "get"} = iq, host) do
    # The vCard being fetched belongs to the IQ's *addressee* (XEP-0054
    # §3: a request is sent to the user's bare JID), not the requester.
    {bare_user, bare_host} = target_of(iq, host)

    case get_vcard(bare_host, bare_user) do
      {:ok, %{name: "vCard"} = el} ->
        {:ok, %{iq | type: "result", payload: [normalize_vcard(el)]}}

      {:ok, vc} when is_map(vc) ->
        # Legacy rows written by the old stub API: a flat field map.
        {:ok, %{iq | type: "result", payload: [%{xmlns: "vcard-temp", vcard: vc}]}}

      :error ->
        {:ok,
         %{
           iq
           | type: "result",
             payload: [%{name: "vCard", attrs: %{"xmlns" => "vcard-temp"}, children: []}]
         }}
    end
  end

  def handle_iq(%{type: "set", from: from} = iq, _host) do
    user =
      case from do
        %Exjabberd.Xmpp.Jid{local: l} when is_binary(l) -> l
        _ -> "unknown"
      end

    host =
      case from do
        %Exjabberd.Xmpp.Jid{domain: d} when is_binary(d) -> d
        _ -> "localhost"
      end

    # Store the vCard element verbatim (like ejabberd stores the XML):
    # nested fields (N, PHOTO, ADR, ...) survive a set/get round-trip.
    case Exjabberd.Xmpp.Stanza.child(iq.payload, "vCard") do
      nil ->
        {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

      el ->
        set_vcard(host, user, el)
        {:ok, %{iq | type: "result", payload: []}}
    end
  end

  def handle_iq(iq, _host),
    do: {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

  # Whose vCard an IQ asks for: the addressee when it is a user JID,
  # else the requester (a get with no `to` means "my own vCard").
  defp target_of(iq, host) do
    case iq.to do
      %Exjabberd.Xmpp.Jid{local: l, domain: d} when is_binary(l) and l != "" ->
        {l, d}

      _ ->
        case iq.from do
          %Exjabberd.Xmpp.Jid{local: l, domain: d} when is_binary(l) -> {l, d}
          _ -> {"", host}
        end
    end
  end

  defp normalize_vcard(%{name: "vCard"} = el) do
    %{el | attrs: Map.put(el.attrs || %{}, "xmlns", "vcard-temp")}
  end

  defp normalize_vcard(other), do: other

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
