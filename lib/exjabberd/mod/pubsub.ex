defmodule Exjabberd.Mod.PubSub do
  @moduledoc """
  Publish-Subscribe — `mod_pubsub` (XEP-0060, core) + PEP (XEP-0163).

  The service lives at `pubsub.<host>` (like `conference.<host>` for
  MUC): `Exjabberd.Router` routes stanzas addressed there to this
  module, and service discovery advertises it from the server.

  Nodes, items, subscriptions and affiliations persist in Mnesia
  (`disc_copies`, so they survive a restart) with an ETS fallback
  when Mnesia is not usable, mirroring `Exjabberd.Mod.Offline`.

  Implemented (XEP-0060 core):

  * Node lifecycle: create / delete (owner namespace) with node
    configuration (access model, publish model, max items,
    persist items, deliver payloads); get/set configuration via the
    owner namespace (`<configure/>`).
  * Subscriptions: subscribe / unsubscribe, with `subid`s; access
    models `open` (anyone), `whitelist` (affiliated JIDs only),
    `authorize` (subscription recorded as `pending` — approval by
    the owner is not implemented yet, see README),
    `presence` / `roster` (treated as `open` for local users —
    documented simplification).
  * Publishing: `publish` (item id or server-generated), `retract`,
    `purge` (owner); publish models `open`, `publishers`
    (owner/publisher affiliation), `subscribers`.
  * Retrieval: `items` (with `max_items` / RSM `<max/>`),
    `subscriptions`, `affiliations`; disco#info / disco#items for
    the service and for single nodes.
  * Notifications: every publish/retract/delete/purge sends a
    `<message type='headline'>` with a
    `<event xmlns='http://jabber.org/protocol/pubsub#event'>` to
    every subscriber (except the publisher when it is not
    subscribed — subscribers always get their own publishes when
    subscribed, as the XEP requires).

  Node configuration defaults (overridable per node at creation and
  via owner `<configure/>`, and globally via `modules:` options):

  * `access_model: "open"`, `publish_model: "publishers"`,
    `max_items: 10`, `persist_items: true`,
    `deliver_payloads: true`, node type `leaf`.

  Collections are not implemented: `create` with a collection type
  is rejected with `bad-request` (documented in the README).
  """

  use Exjabberd.Mod.GenMod
  require Logger

  alias Exjabberd.Xmpp.{Jid, Stanza}

  @pubsub_ns "http://jabber.org/protocol/pubsub"
  @owner_ns "http://jabber.org/protocol/pubsub#owner"
  @event_ns "http://jabber.org/protocol/pubsub#event"
  @disco_info_ns "http://jabber.org/protocol/disco#info"
  @disco_items_ns "http://jabber.org/protocol/disco#items"
  @data_ns "jabber:x:data"

  @nodes_table :pubsub_nodes
  @items_table :pubsub_items
  @subs_table :pubsub_subs
  @affs_table :pubsub_affs

  # Fallback ETS tables MUST use different names from the Mnesia
  # tables: Mnesia creates its own ETS table under the Mnesia table
  # name, so sharing the name makes `create_table` fail with
  # `{:system_limit, _, {"Failed to create ets table", :badarg}}`.
  @ets_nodes :exjabberd_pubsub_nodes
  @ets_items :exjabberd_pubsub_items
  @ets_subs :exjabberd_pubsub_subs
  @ets_affs :exjabberd_pubsub_affs

  @default_max_items 10

  @doc "PubSub service JID for a host (`pubsub.<host>`)."
  @spec service_jid(binary()) :: binary()
  def service_jid(host), do: "pubsub." <> host

  @impl true
  def start(host, opts) do
    ensure_tables()

    Logger.info(
      "mod_pubsub started for #{host} (service=#{service_jid(host)}, max_items=#{Keyword.get(opts, :max_items, @default_max_items)})"
    )

    Exjabberd.Iq.register(host, @pubsub_ns, __MODULE__, :handle_iq)
    Exjabberd.Iq.register(host, @owner_ns, __MODULE__, :handle_owner_iq)
    Exjabberd.Hooks.add(:disco_info, host, __MODULE__, :disco_info, 50)
    Exjabberd.Hooks.add(:pubsub_create_node, host, __MODULE__, :on_create_node, 50)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Iq.unregister(host, @pubsub_ns, :both)
    Exjabberd.Iq.unregister(host, @owner_ns, :both)
    Exjabberd.Hooks.delete(:disco_info, host, __MODULE__, :disco_info)
    Exjabberd.Hooks.delete(:pubsub_create_node, host, __MODULE__, :on_create_node)
    :ok
  end

  @impl true
  def mod_options(_host),
    do: [max_items: @default_max_items, access_model: "open", publish_model: "publishers"]

  @impl true
  def mod_doc,
    do: %{
      desc: "Publish-Subscribe (XEP-0060): pubsub.localhost service",
      doc: "https://xmpp.org/extensions/xep-0060.html"
    }

  # --- disco ---

  @doc false
  def disco_info(acc, _host),
    do:
      Map.update(
        acc,
        :features,
        [@pubsub_ns, @event_ns],
        &(&1 ++ [@pubsub_ns, @event_ns])
      )

  @doc "Disco#info answer for the service itself."
  @spec service_disco_info(binary()) :: {[binary()], [map()]}
  def service_disco_info(_host) do
    {[
       @disco_info_ns,
       @disco_items_ns,
       @pubsub_ns,
       @event_ns,
       "#{@pubsub_ns}#publish",
       "#{@pubsub_ns}#subscribe",
       "#{@pubsub_ns}#retrieve-items",
       "#{@pubsub_ns}#delete-items",
       "#{@pubsub_ns}#retract-items",
       "#{@pubsub_ns}#purge-nodes",
       "#{@pubsub_ns}#create-nodes",
       "#{@pubsub_ns}#delete-nodes",
       "#{@pubsub_ns}#manage-subscriptions",
       "#{@pubsub_ns}#retrieve-subscriptions",
       "#{@pubsub_ns}#retrieve-affiliations",
       "#{@pubsub_ns}#modify-affiliations"
     ], [%{category: "pubsub", type: "service", name: "exjabberd PubSub"}]}
  end

  @doc "Disco#info answer for one node, or `{:error, :not_found}`."
  @spec node_disco_info(binary(), binary()) ::
          {:ok, {[binary()], [map()]}} | {:error, :not_found}
  def node_disco_info(host, node) do
    case get_node(host, node) do
      nil ->
        {:error, :not_found}

      meta ->
        type = if meta.type == "collection", do: "collection", else: "leaf"

        {:ok,
         {[
            @disco_info_ns,
            @disco_items_ns,
            @pubsub_ns,
            "#{@pubsub_ns}#subscribe",
            "#{@pubsub_ns}#retrieve-items",
            "#{@pubsub_ns}#publish"
          ], [%{category: "pubsub", type: type, name: node}]}}
    end
  end

  @doc "All node names for a host, sorted."
  @spec list_nodes(binary()) :: [binary()]
  def list_nodes(host) do
    ensure_tables()

    all(@nodes_table)
    |> Enum.filter(fn {{h, _node}, _meta} -> h == host end)
    |> Enum.map(fn {{_h, node}, _meta} -> node end)
    |> Enum.sort()
  end

  # --- node lifecycle ---

  @type node_opts :: keyword()

  @doc "Create a pubsub node (like `mod_pubsub:create_node/5`)."
  @spec create_node(binary(), binary(), node_opts()) :: :ok | {:error, term()}
  def create_node(host, node, opts \\ []) do
    ensure_tables()

    cond do
      Keyword.get(opts, :type, "leaf") == "collection" ->
        {:error, :collection_not_supported}

      get_node(host, node) != nil ->
        {:error, :conflict}

      true ->
        meta = %{
          type: Keyword.get(opts, :type, "leaf"),
          access_model:
            to_string(Keyword.get(opts, :access_model, default_opt(host, :access_model, "open"))),
          publish_model:
            to_string(
              Keyword.get(opts, :publish_model, default_opt(host, :publish_model, "publishers"))
            ),
          max_items:
            Keyword.get(opts, :max_items, default_opt(host, :max_items, @default_max_items)),
          persist_items: Keyword.get(opts, :persist_items, true),
          deliver_payloads: Keyword.get(opts, :deliver_payloads, true),
          title: Keyword.get(opts, :title),
          description: Keyword.get(opts, :description),
          owner: Keyword.get(opts, :owner),
          created: System.system_time(:second)
        }

        put(@nodes_table, {host, node}, meta)
        if meta.owner, do: put(@affs_table, {host, node, meta.owner}, :owner)
        Exjabberd.Hooks.run(:pubsub_create_node, host, {node, meta})
        :ok
    end
  end

  @doc "Delete node (like `mod_pubsub:delete_node/2`). Notifies subscribers."
  @spec delete_node(binary(), binary()) :: :ok | {:error, term()}
  def delete_node(host, node) do
    ensure_tables()

    if get_node(host, node) == nil do
      {:error, :not_found}
    else
      subscribers = get_subscribers(host, node)
      delete(@nodes_table, {host, node})
      match_delete(@items_table, {host, node, :_})
      match_delete(@affs_table, {host, node, :_})
      match_delete(@subs_table, {host, node, :_})

      Enum.each(subscribers, fn sub_jid ->
        notify(sub_jid, host, %{
          name: "delete",
          attrs: %{"node" => node},
          children: []
        })
      end)

      :ok
    end
  end

  @doc "Get a node's configuration, or `nil` when it does not exist."
  @spec get_node(binary(), binary()) :: map() | nil
  def get_node(host, node) do
    ensure_tables()
    get(@nodes_table, {host, node})
  end

  @doc "Update a node's configuration (owner `<configure/>`)."
  @spec set_node_config(binary(), binary(), map()) :: :ok | {:error, term()}
  def set_node_config(host, node, config) do
    ensure_tables()

    case get_node(host, node) do
      nil -> {:error, :not_found}
      meta -> put(@nodes_table, {host, node}, Map.merge(meta, config))
    end
  end

  # --- affiliations ---

  @doc "Set affiliation (owner/publisher/member/outcast)."
  @spec set_affiliation(binary(), binary(), binary(), atom()) :: :ok | {:error, term()}
  def set_affiliation(host, node, jid, aff)
      when aff in [:owner, :publisher, :member, :outcast, :none] do
    ensure_tables()

    if get_node(host, node) == nil do
      {:error, :not_found}
    else
      if aff == :none do
        delete(@affs_table, {host, node, jid})
      else
        put(@affs_table, {host, node, jid}, aff)
      end

      :ok
    end
  end

  @doc "Get affiliation."
  @spec get_affiliation(binary(), binary(), binary()) :: atom()
  def get_affiliation(host, node, jid) do
    ensure_tables()
    get(@affs_table, {host, node, jid}) || :none
  end

  @doc "Affiliations of one JID across all nodes of a host."
  @spec affiliations_of(binary(), binary()) :: [{binary(), atom()}]
  def affiliations_of(host, jid) do
    ensure_tables()

    all(@affs_table)
    |> Enum.filter(fn {{h, _node, j}, _aff} -> h == host and j == jid end)
    |> Enum.map(fn {{_h, node, _j}, aff} -> {node, aff} end)
    |> Enum.sort()
  end

  # --- subscriptions ---

  @doc "Subscribe JID to node (like `mod_pubsub:subscribe_node`)."
  @spec subscribe(binary(), binary(), binary(), keyword()) ::
          {:ok, atom(), binary()} | {:error, term()}
  def subscribe(host, node, jid, opts \\ []) do
    ensure_tables()

    case get_node(host, node) do
      nil ->
        {:error, :not_found}

      meta ->
        cond do
          get_affiliation(host, node, jid) == :outcast ->
            {:error, :forbidden}

          meta.access_model == "whitelist" and get_affiliation(host, node, jid) == :none ->
            {:error, :forbidden}

          meta.access_model == "authorize" ->
            subid = Keyword.get(opts, :subid, random_id())
            put(@subs_table, {host, node, jid}, %{jid: jid, subid: subid, state: :pending})
            {:ok, :pending, subid}

          true ->
            subid = Keyword.get(opts, :subid, random_id())
            put(@subs_table, {host, node, jid}, %{jid: jid, subid: subid, state: :subscribed})
            {:ok, :subscribed, subid}
        end
    end
  end

  @doc "Unsubscribe."
  @spec unsubscribe(binary(), binary(), binary()) :: :ok
  def unsubscribe(host, node, jid) do
    ensure_tables()
    delete(@subs_table, {host, node, jid})
    :ok
  end

  @doc "Subscribed JIDs of a node (only `:subscribed` state)."
  @spec get_subscribers(binary(), binary()) :: [binary()]
  def get_subscribers(host, node) do
    ensure_tables()

    all(@subs_table)
    |> Enum.filter(fn
      {{h, n, _jid}, %{state: :subscribed}} -> h == host and n == node
      _ -> false
    end)
    |> Enum.map(fn {{_h, _n, jid}, _} -> jid end)
    |> Enum.sort()
  end

  @doc "Subscriptions of one JID across all nodes of a host."
  @spec subscriptions_of(binary(), binary()) :: [{binary(), map()}]
  def subscriptions_of(host, jid) do
    ensure_tables()

    all(@subs_table)
    |> Enum.filter(fn {{h, _node, j}, _} -> h == host and j == jid end)
    |> Enum.map(fn {{_h, node, _j}, sub} -> {node, sub} end)
    |> Enum.sort()
  end

  # --- items ---

  @doc "Publish to node and notify subscribers (like `mod_pubsub:publish_item`)."
  @spec publish(binary(), binary(), binary(), term(), keyword()) :: :ok | {:error, term()}
  def publish(host, node, item_id, payload, opts \\ []) do
    ensure_tables()
    publisher = Keyword.get(opts, :publisher)

    case get_node(host, node) do
      nil ->
        {:error, :not_found}

      meta ->
        if allowed_to_publish?(host, node, meta, publisher) do
          item_id = item_id || random_id()

          item = %{
            payload: payload,
            publisher: publisher,
            ts: System.system_time(:millisecond),
            id: item_id
          }

          if meta.persist_items do
            put(@items_table, {host, node, item_id}, item)
            enforce_max_items(host, node, meta)
          end

          if meta.deliver_payloads do
            Enum.each(get_subscribers(host, node), fn sub_jid ->
              notify_items(sub_jid, host, node, [item_element(item)])
            end)
          end

          :ok
        else
          {:error, :forbidden}
        end
    end
  end

  @doc "Retract an item and notify subscribers."
  @spec retract(binary(), binary(), binary(), keyword()) :: :ok | {:error, term()}
  def retract(host, node, item_id, opts \\ []) do
    ensure_tables()
    publisher = Keyword.get(opts, :publisher)

    case get_node(host, node) do
      nil ->
        {:error, :not_found}

      meta ->
        if allowed_to_publish?(host, node, meta, publisher) do
          delete(@items_table, {host, node, item_id})

          Enum.each(get_subscribers(host, node), fn sub_jid ->
            notify(sub_jid, host, %{
              name: "items",
              attrs: %{"node" => node},
              children: [%{name: "retract", attrs: %{"id" => item_id}, children: []}]
            })
          end)

          :ok
        else
          {:error, :forbidden}
        end
    end
  end

  @doc "Delete all items of a node and notify subscribers (owner `<purge/>`)."
  @spec purge(binary(), binary()) :: :ok | {:error, term()}
  def purge(host, node) do
    ensure_tables()

    if get_node(host, node) == nil do
      {:error, :not_found}
    else
      match_delete(@items_table, {host, node, :_})

      Enum.each(get_subscribers(host, node), fn sub_jid ->
        notify(sub_jid, host, %{name: "purge", attrs: %{"node" => node}, children: []})
      end)

      :ok
    end
  end

  @doc "Get items for node, oldest first."
  @spec get_items(binary(), binary(), keyword()) :: {:ok, [map()], map()} | {:error, term()}
  def get_items(host, node, opts \\ []) do
    ensure_tables()
    limit = Keyword.get(opts, :max_items, Keyword.get(opts, :limit, @default_max_items))

    if get_node(host, node) == nil do
      {:error, :not_found}
    else
      items =
        all(@items_table)
        |> Enum.filter(fn {{h, n, _id}, _item} -> h == host and n == node end)
        |> Enum.map(fn {{_h, _n, id}, item} -> Map.put(item, :id, id) end)
        |> Enum.sort_by(& &1.ts)
        |> Enum.take(limit)

      {:ok, items, %{count: length(items)}}
    end
  end

  @doc "Delete one item (no notification)."
  @spec delete_item(binary(), binary(), binary()) :: :ok
  def delete_item(host, node, item_id) do
    ensure_tables()
    delete(@items_table, {host, node, item_id})
    :ok
  end

  # --- IQ handlers ---

  @doc false
  def on_create_node({_node, _meta} = data, _host), do: data

  @doc "IQ handler for `http://jabber.org/protocol/pubsub`."
  @spec handle_iq(map(), binary()) :: {:ok, map()} | {:error, term()}
  def handle_iq(%{type: type} = iq, host) when type in ["get", "set"] do
    case Stanza.child(iq.payload, "pubsub") do
      nil -> {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
      pubsub_el -> dispatch_pubsub(iq, host, pubsub_el)
    end
  end

  def handle_iq(iq, _host),
    do: {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

  defp dispatch_pubsub(%{type: "set"} = iq, host, pubsub_el) do
    case first_action(pubsub_el) do
      {"create", el} -> handle_create(iq, host, el)
      {"subscribe", el} -> handle_subscribe(iq, host, el)
      {"unsubscribe", el} -> handle_unsubscribe(iq, host, el)
      {"publish", el} -> handle_publish(iq, host, el)
      {"retract", el} -> handle_retract(iq, host, el)
      _ -> {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
    end
  end

  defp dispatch_pubsub(%{type: "get"} = iq, host, pubsub_el) do
    case first_action(pubsub_el) do
      {"items", el} -> handle_get_items(iq, host, el, pubsub_el)
      {"subscriptions", _el} -> handle_get_subscriptions(iq, host)
      {"affiliations", _el} -> handle_get_affiliations(iq, host)
      _ -> {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
    end
  end

  defp first_action(pubsub_el) do
    case Enum.find(pubsub_el.children, &is_map/1) do
      %{name: name} = el -> {name, el}
      _ -> {nil, nil}
    end
  end

  # --- set actions ---

  defp handle_create(iq, host, el) do
    node = el.attrs["node"]
    owner = requester_bare(iq)

    cond do
      is_nil(node) or node == "" ->
        {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

      true ->
        opts = [owner: owner] ++ config_from_form(Stanza.child(el.children, "configure"))

        case create_node(host, node, opts) do
          :ok ->
            {:ok, %{iq | type: "result", payload: []}}

          {:error, :conflict} ->
            {:error, :conflict, Exjabberd.Iq.error_iq(iq, "conflict")}

          {:error, :collection_not_supported} ->
            {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
        end
    end
  end

  defp handle_subscribe(iq, host, el) do
    node = el.attrs["node"]
    jid = el.attrs["jid"] || requester_bare(iq)

    cond do
      is_nil(node) or node == "" ->
        {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

      true ->
        case subscribe(host, node, jid) do
          {:ok, state, subid} ->
            sub = %{
              name: "subscription",
              attrs: %{
                "node" => node,
                "jid" => jid,
                "subscription" => to_string(state),
                "subid" => subid
              },
              children: []
            }

            {:ok, %{iq | type: "result", payload: [wrap_pubsub([sub])]}}

          {:error, :not_found} ->
            {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}

          {:error, :forbidden} ->
            {:error, :forbidden, Exjabberd.Iq.error_iq(iq, "forbidden")}
        end
    end
  end

  defp handle_unsubscribe(iq, host, el) do
    node = el.attrs["node"]
    jid = el.attrs["jid"] || requester_bare(iq)

    if is_nil(node) or node == "" do
      {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
    else
      :ok = unsubscribe(host, node, jid)
      {:ok, %{iq | type: "result", payload: []}}
    end
  end

  defp handle_publish(iq, host, el) do
    node = el.attrs["node"]
    publisher = requester_bare(iq)

    case Stanza.child(el.children, "item") do
      nil ->
        {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

      item_el ->
        item_id = item_el.attrs["id"]

        case publish(host, node, item_id, item_el.children, publisher: publisher) do
          :ok ->
            {:ok, %{iq | type: "result", payload: []}}

          {:error, :not_found} ->
            {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}

          {:error, :forbidden} ->
            {:error, :forbidden, Exjabberd.Iq.error_iq(iq, "forbidden")}
        end
    end
  end

  defp handle_retract(iq, host, el) do
    node = el.attrs["node"]
    publisher = requester_bare(iq)

    case Stanza.child(el.children, "item") do
      %{attrs: %{"id" => item_id}} ->
        case retract(host, node, item_id, publisher: publisher) do
          :ok ->
            {:ok, %{iq | type: "result", payload: []}}

          {:error, :not_found} ->
            {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}

          {:error, :forbidden} ->
            {:error, :forbidden, Exjabberd.Iq.error_iq(iq, "forbidden")}
        end

      _ ->
        {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
    end
  end

  # --- get actions ---

  defp handle_get_items(iq, host, el, pubsub_el) do
    node = el.attrs["node"]
    # XEP-0060 puts the RSM <set/> next to <items/>, as a child of
    # <pubsub/> — not inside <items/>.
    max_items = parse_int(el.attrs["max_items"]) || parse_rsm_max(pubsub_el)

    case get_items(host, node, max_items: max_items || @default_max_items) do
      {:ok, items, _info} ->
        items_el = %{
          name: "items",
          attrs: %{"node" => node},
          children: Enum.map(items, &item_element/1)
        }

        {:ok, %{iq | type: "result", payload: [wrap_pubsub([items_el])]}}

      {:error, :not_found} ->
        {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}
    end
  end

  defp handle_get_subscriptions(iq, host) do
    jid = requester_bare(iq)

    subs =
      Enum.map(subscriptions_of(host, jid), fn {node, sub} ->
        %{
          name: "subscription",
          attrs: %{
            "node" => node,
            "jid" => jid,
            "subscription" => to_string(sub.state),
            "subid" => sub.subid
          },
          children: []
        }
      end)

    {:ok,
     %{
       iq
       | type: "result",
         payload: [wrap_pubsub([%{name: "subscriptions", attrs: %{}, children: subs}])]
     }}
  end

  defp handle_get_affiliations(iq, host) do
    jid = requester_bare(iq)

    affs =
      Enum.map(affiliations_of(host, jid), fn {node, aff} ->
        %{
          name: "affiliation",
          attrs: %{"node" => node, "jid" => jid, "affiliation" => to_string(aff)},
          children: []
        }
      end)

    {:ok,
     %{
       iq
       | type: "result",
         payload: [wrap_pubsub([%{name: "affiliations", attrs: %{}, children: affs}])]
     }}
  end

  # --- owner IQ handler ---

  @doc "IQ handler for `http://jabber.org/protocol/pubsub#owner`."
  @spec handle_owner_iq(map(), binary()) :: {:ok, map()} | {:error, term()}
  def handle_owner_iq(%{type: type} = iq, host) when type in ["get", "set"] do
    case Stanza.child(iq.payload, "pubsub") do
      nil -> {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
      pubsub_el -> dispatch_owner(iq, host, pubsub_el)
    end
  end

  def handle_owner_iq(iq, _host),
    do: {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

  defp dispatch_owner(%{type: "get"} = iq, host, pubsub_el) do
    case first_action(pubsub_el) do
      {"configure", el} -> handle_owner_get_configure(iq, host, el)
      {"subscriptions", el} -> handle_owner_get_subscriptions(iq, host, el)
      {"affiliations", el} -> handle_owner_get_affiliations(iq, host, el)
      _ -> {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
    end
  end

  defp dispatch_owner(%{type: "set"} = iq, host, pubsub_el) do
    case first_action(pubsub_el) do
      {"configure", el} -> handle_owner_set_configure(iq, host, el)
      {"delete", el} -> handle_owner_delete(iq, host, el)
      {"purge", el} -> handle_owner_purge(iq, host, el)
      {"subscriptions", el} -> handle_owner_set_subscriptions(iq, host, el)
      {"affiliations", el} -> handle_owner_set_affiliations(iq, host, el)
      _ -> {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
    end
  end

  defp handle_owner_get_configure(iq, host, el) do
    node = el.attrs["node"]

    case get_node(host, node) do
      nil ->
        {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}

      meta ->
        {:ok, %{iq | type: "result", payload: [wrap_owner([configure_element(node, meta)])]}}
    end
  end

  defp handle_owner_set_configure(iq, host, el) do
    node = el.attrs["node"]

    case get_node(host, node) do
      nil ->
        {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}

      _meta ->
        config = config_from_form(Stanza.child(el.children, "x"))

        case set_node_config(host, node, Map.new(config)) do
          :ok ->
            {:ok, %{iq | type: "result", payload: []}}

          {:error, :not_found} ->
            {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}
        end
    end
  end

  defp handle_owner_delete(iq, host, el) do
    node = el.attrs["node"]

    case delete_node(host, node) do
      :ok -> {:ok, %{iq | type: "result", payload: []}}
      {:error, :not_found} -> {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}
    end
  end

  defp handle_owner_purge(iq, host, el) do
    node = el.attrs["node"]

    case purge(host, node) do
      :ok -> {:ok, %{iq | type: "result", payload: []}}
      {:error, :not_found} -> {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}
    end
  end

  defp handle_owner_get_subscriptions(iq, host, el) do
    node = el.attrs["node"]

    if get_node(host, node) == nil do
      {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}
    else
      subs =
        all(@subs_table)
        |> Enum.filter(fn {{h, n, _j}, _} -> h == host and n == node end)
        |> Enum.map(fn {{_h, _n, jid}, sub} ->
          %{
            name: "subscription",
            attrs: %{
              "node" => node,
              "jid" => jid,
              "subscription" => to_string(sub.state),
              "subid" => sub.subid
            },
            children: []
          }
        end)

      {:ok,
       %{
         iq
         | type: "result",
           payload: [
             wrap_owner([%{name: "subscriptions", attrs: %{"node" => node}, children: subs}])
           ]
       }}
    end
  end

  defp handle_owner_get_affiliations(iq, host, el) do
    node = el.attrs["node"]

    if get_node(host, node) == nil do
      {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}
    else
      affs =
        all(@affs_table)
        |> Enum.filter(fn {{h, n, _j}, _} -> h == host and n == node end)
        |> Enum.map(fn {{_h, _n, jid}, aff} ->
          %{
            name: "affiliation",
            attrs: %{"node" => node, "jid" => jid, "affiliation" => to_string(aff)},
            children: []
          }
        end)

      {:ok,
       %{
         iq
         | type: "result",
           payload: [
             wrap_owner([%{name: "affiliations", attrs: %{"node" => node}, children: affs}])
           ]
       }}
    end
  end

  defp handle_owner_set_subscriptions(iq, host, el) do
    node = el.attrs["node"]

    if get_node(host, node) == nil do
      {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}
    else
      Enum.each(el.children, fn
        %{name: "subscription", attrs: %{"jid" => jid, "subscription" => state}} ->
          case state do
            "none" -> unsubscribe(host, node, jid)
            "subscribed" -> subscribe(host, node, jid)
            _ -> :ok
          end

        _ ->
          :ok
      end)

      {:ok, %{iq | type: "result", payload: []}}
    end
  end

  defp handle_owner_set_affiliations(iq, host, el) do
    node = el.attrs["node"]

    if get_node(host, node) == nil do
      {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}
    else
      Enum.each(el.children, fn
        %{name: "affiliation", attrs: %{"jid" => jid, "affiliation" => aff}} ->
          aff_atom = String.to_atom(aff)

          if aff_atom in [:owner, :publisher, :member, :outcast, :none] do
            set_affiliation(host, node, jid, aff_atom)
          end

        _ ->
          :ok
      end)

      {:ok, %{iq | type: "result", payload: []}}
    end
  end

  # --- node configuration form (XEP-0060 §9, jabber:x:data) ---

  # `<configure/>` inside create, or the `<x/>` form inside owner
  # configure: read the standard `pubsub#` fields into node opts.
  defp config_from_form(nil), do: []

  defp config_from_form(configure_el) do
    form =
      if configure_el.name == "x",
        do: configure_el,
        else: Stanza.child(configure_el.children, "x")

    if is_nil(form), do: [], else: form_fields(form)
  end

  defp form_fields(form) do
    Enum.flat_map(form.children, fn
      %{name: "field", attrs: %{"var" => var}, children: children} ->
        value = Stanza.child_text(children, "value")

        case {var, value} do
          {"pubsub#access_model", v} when is_binary(v) ->
            [access_model: v]

          {"pubsub#publish_model", v} when is_binary(v) ->
            [publish_model: v]

          {"pubsub#max_items", v} when is_binary(v) ->
            [max_items: parse_int(v) || @default_max_items]

          {"pubsub#persist_items", v} when is_binary(v) ->
            [persist_items: v in ["1", "true"]]

          {"pubsub#deliver_payloads", v} when is_binary(v) ->
            [deliver_payloads: v in ["1", "true"]]

          {"pubsub#title", v} when is_binary(v) ->
            [title: v]

          {"pubsub#description", v} when is_binary(v) ->
            [description: v]

          _ ->
            []
        end

      _ ->
        []
    end)
  end

  defp configure_element(node, meta) do
    fields = [
      {"FORM_TYPE", "hidden", @pubsub_ns <> "#node_config"},
      {"pubsub#access_model", "list-single", meta.access_model},
      {"pubsub#publish_model", "list-single", meta.publish_model},
      {"pubsub#max_items", "text-single", to_string(meta.max_items)},
      {"pubsub#persist_items", "boolean", if(meta.persist_items, do: "1", else: "0")},
      {"pubsub#deliver_payloads", "boolean", if(meta.deliver_payloads, do: "1", else: "0")},
      {"pubsub#title", "text-single", meta.title || ""},
      {"pubsub#description", "text-single", meta.description || ""}
    ]

    %{
      name: "configure",
      attrs: %{"node" => node},
      children: [
        %{
          name: "x",
          attrs: %{"xmlns" => @data_ns, "type" => "form"},
          children:
            Enum.map(fields, fn {var, type, value} ->
              %{
                name: "field",
                attrs: %{"var" => var, "type" => type},
                children: [%{name: "value", attrs: %{}, children: [value]}]
              }
            end)
        }
      ]
    }
  end

  # --- notifications ---

  defp notify_items(to_jid, host, node, item_elements) do
    notify(to_jid, host, %{
      name: "items",
      attrs: %{"node" => node},
      children: item_elements
    })
  end

  defp notify(to_jid, host, event_child) do
    stanza =
      Stanza.new(:message,
        type: "headline",
        from: service_jid(host),
        to: to_jid,
        payload: [
          %{
            name: "event",
            attrs: %{"xmlns" => @event_ns},
            children: [event_child]
          }
        ]
      )

    Exjabberd.Router.route(stanza)
  end

  defp item_element(%{id: id, payload: payload}) do
    children =
      cond do
        is_list(payload) -> payload
        is_binary(payload) -> [payload]
        is_nil(payload) -> []
        true -> [inspect(payload)]
      end

    %{name: "item", attrs: %{"id" => to_string(id)}, children: children}
  end

  # --- helpers ---

  defp wrap_pubsub(children),
    do: %{name: "pubsub", attrs: %{"xmlns" => @pubsub_ns}, children: children}

  defp wrap_owner(children),
    do: %{name: "pubsub", attrs: %{"xmlns" => @owner_ns}, children: children}

  defp requester_bare(iq) do
    case iq.from do
      %Jid{} = jid -> Jid.bare(jid)
      bin when is_binary(bin) -> Jid.bare(bin)
      _ -> ""
    end
  end

  defp allowed_to_publish?(host, node, meta, publisher) do
    case meta.publish_model do
      "open" ->
        true

      "publishers" ->
        is_nil(publisher) or get_affiliation(host, node, publisher) in [:owner, :publisher]

      "subscribers" ->
        publisher in get_subscribers(host, node)

      _ ->
        true
    end
  end

  defp enforce_max_items(host, node, meta) do
    max = meta.max_items || @default_max_items

    items =
      all(@items_table)
      |> Enum.filter(fn {{h, n, _id}, _item} -> h == host and n == node end)
      |> Enum.sort_by(fn {_key, item} -> item.ts end)

    if length(items) > max do
      items
      |> Enum.take(length(items) - max)
      |> Enum.each(fn {{h, n, id}, _item} -> delete(@items_table, {h, n, id}) end)
    end

    :ok
  end

  defp parse_rsm_max(el) do
    case Stanza.child(el.children, "set") do
      nil -> nil
      set -> set |> Stanza.child_text("max") |> parse_int()
    end
  end

  defp parse_int(nil), do: nil

  defp parse_int(str) when is_binary(str) do
    case Integer.parse(String.trim(str)) do
      {n, ""} when n > 0 -> n
      _ -> nil
    end
  end

  defp parse_int(n) when is_integer(n) and n > 0, do: n
  defp parse_int(_), do: nil

  defp default_opt(host, key, default) do
    host
    |> then(&Exjabberd.Mod.Supervisor.get_opts(&1, __MODULE__))
    |> Keyword.get(key, default)
  end

  defp random_id, do: :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)

  # --- storage (Mnesia disc_copies first, ETS fallback — same shape as mod_offline) ---

  defp ensure_tables do
    for {mnesia, ets} <- [
          {@nodes_table, @ets_nodes},
          {@items_table, @ets_items},
          {@subs_table, @ets_subs},
          {@affs_table, @ets_affs}
        ] do
      if :ets.whereis(ets) == :undefined do
        :ets.new(ets, [
          :named_table,
          :public,
          :set,
          read_concurrency: true,
          write_concurrency: true
        ])
      end

      Exjabberd.Mnesia.ensure_table(mnesia, [:key, :value])
    end
  end

  # The ETS fallback table for a Mnesia table.
  defp ets_table(@nodes_table), do: @ets_nodes
  defp ets_table(@items_table), do: @ets_items
  defp ets_table(@subs_table), do: @ets_subs
  defp ets_table(@affs_table), do: @ets_affs

  defp put(table, key, value) do
    case :mnesia.transaction(fn -> :mnesia.write({table, key, value}) end) do
      {:atomic, :ok} -> :ok
      {:aborted, _} -> :ets.insert(ets_table(table), {key, value})
    end
  rescue
    _ -> :ets.insert(ets_table(table), {key, value})
  catch
    _, _ -> :ets.insert(ets_table(table), {key, value})
  end

  defp get(table, key) do
    case :mnesia.dirty_read({table, key}) do
      [{^table, _, value}] ->
        value

      [] ->
        case :ets.lookup(ets_table(table), key) do
          [{_, value}] -> value
          [] -> nil
        end
    end
  rescue
    _ ->
      case :ets.lookup(ets_table(table), key) do
        [{_, value}] -> value
        [] -> nil
      end
  catch
    _, _ -> nil
  end

  defp delete(table, key) do
    case :mnesia.transaction(fn -> :mnesia.delete({table, key}) end) do
      {:atomic, :ok} -> :ok
      {:aborted, _} -> :ets.delete(ets_table(table), key)
    end

    :ets.delete(ets_table(table), key)
    :ok
  rescue
    _ -> :ets.delete(ets_table(table), key)
  catch
    _, _ -> :ets.delete(ets_table(table), key)
  end

  defp match_delete(table, pattern_key) do
    :mnesia.transaction(fn ->
      :mnesia.match_object({table, pattern_key, :_})
      |> Enum.each(&:mnesia.delete_object/1)
    end)

    :ets.match_delete(ets_table(table), {pattern_key, :_})
    :ok
  rescue
    _ -> :ets.match_delete(ets_table(table), {pattern_key, :_})
  catch
    _, _ -> :ok
  end

  defp all(table) do
    mnesia =
      :mnesia.dirty_match_object({table, :_, :_})
      |> Enum.map(fn {^table, key, value} -> {key, value} end)

    ets = :ets.tab2list(ets_table(table))
    (mnesia ++ ets) |> Enum.uniq_by(fn {key, _} -> key end)
  rescue
    _ -> :ets.tab2list(ets_table(table))
  catch
    _, _ -> []
  end
end

defmodule Exjabberd.Mod.Pep do
  @moduledoc "Personal Eventing Protocol - `mod_pubsub` PEP (XEP-0163) (partial implementation). Each user is a pubsub host with auto-create nodes."

  use Exjabberd.Mod.GenMod

  @impl true
  def start(host, _opts) do
    Exjabberd.Hooks.add(:pep_publish, host, __MODULE__, :on_publish, 50)
    Exjabberd.Hooks.add(:pep_delete, host, __MODULE__, :on_delete, 50)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:pep_publish, host, __MODULE__, :on_publish)
    Exjabberd.Hooks.delete(:pep_delete, host, __MODULE__, :on_delete)
    :ok
  end

  @doc false
  def on_publish({user, node, payload} = item, host) do
    # PEP auto-creates node per user like ejabberd
    _ = Exjabberd.Mod.PubSub.create_node(host, "#{user}/#{node}", owner: user)
    Exjabberd.Mod.PubSub.publish(host, "#{user}/#{node}", random_id(), payload, publisher: user)
    item
  rescue
    _ -> item
  end

  @doc false
  def on_delete(item, _host), do: item

  defp random_id, do: :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
end

defmodule Exjabberd.Mod.Caps do
  @moduledoc """
  Entity Capabilities - `mod_caps` (XEP-0115) (partial implementation).

  Caches caps hash -> features, handles `c` presence like ejabberd.
  """

  use Exjabberd.Mod.GenMod

  @table :exjabberd_caps

  @impl true
  def start(host, _opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [
        :named_table,
        :public,
        :set,
        read_concurrency: true,
        write_concurrency: true
      ])
    end

    Exjabberd.Hooks.add(:presence, host, __MODULE__, :on_presence, 50)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:presence, host, __MODULE__, :on_presence)
    :ok
  end

  @doc "Store caps (like `mod_caps:store_caps`)."
  @spec put(binary(), [binary()], binary()) :: :ok
  def put(hash, features, _node \\ "") do
    :ets.insert(@table, {hash, features})
    :ok
  end

  @doc "Get caps."
  @spec get(binary()) :: {:ok, [binary()]} | :error
  def get(hash) do
    case :ets.lookup(@table, hash) do
      [{_, f}] -> {:ok, f}
      [] -> :error
    end
  end

  @doc false
  def on_presence(presence, _host), do: presence
end

defmodule Exjabberd.Mod.Disco do
  @moduledoc """
  Service Discovery - `mod_disco` (XEP-0030) (partial implementation). Answers disco#info and disco#items,
  aggregates from all `disco_info` hooks like ejabberd.
  """

  use Exjabberd.Mod.GenMod

  @impl true
  def start(host, _opts) do
    Exjabberd.Hooks.add(:disco_info, host, __MODULE__, :info, 50)
    Exjabberd.Hooks.add(:disco_items, host, __MODULE__, :items, 50)

    Exjabberd.Iq.register(
      host,
      "http://jabber.org/protocol/disco#info",
      __MODULE__,
      :handle_info
    )

    Exjabberd.Iq.register(
      host,
      "http://jabber.org/protocol/disco#items",
      __MODULE__,
      :handle_items
    )

    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:disco_info, host, __MODULE__, :info)
    Exjabberd.Hooks.delete(:disco_items, host, __MODULE__, :items)
    Exjabberd.Iq.unregister(host, "http://jabber.org/protocol/disco#info", :both)
    Exjabberd.Iq.unregister(host, "http://jabber.org/protocol/disco#items", :both)
    :ok
  end

  @doc false
  def info(acc, _host),
    do:
      Map.update(
        acc,
        :features,
        ["http://jabber.org/protocol/disco#info"],
        &(&1 ++ ["http://jabber.org/protocol/disco#info"])
      )

  @doc false
  def items(acc, _host), do: acc

  @doc false
  def handle_info(iq, host) do
    # Aggregate features from hooks like ejabberd does
    acc = Exjabberd.Hooks.run_fold(:disco_info, host, %{features: [], identities: []}, [])
    node = query_node(iq)

    {features, identities} =
      case iq.to do
        %Exjabberd.Xmpp.Jid{domain: "conference." <> _} ->
          # The MUC service answers with its own identity + features.
          {["http://jabber.org/protocol/disco#info", "http://jabber.org/protocol/muc"],
           [%{category: "conference", type: "text", name: "exjabberd MUC"}]}

        %Exjabberd.Xmpp.Jid{domain: "pubsub." <> _} when not is_nil(node) ->
          # Disco#info on one node of the PubSub service.
          case Exjabberd.Mod.PubSub.node_disco_info(host, node) do
            {:ok, {f, i}} -> {f, i}
            {:error, :not_found} -> throw({:disco_error, iq})
          end

        %Exjabberd.Xmpp.Jid{domain: "pubsub." <> _} ->
          # The PubSub service answers with its own identity + features.
          Exjabberd.Mod.PubSub.service_disco_info(host)

        _ ->
          {acc.features, acc.identities}
      end

    {:ok,
     %{
       iq
       | type: "result",
         payload: [
           %{
             xmlns: "http://jabber.org/protocol/disco#info",
             features: features,
             identities: identities
           }
         ]
     }}
  catch
    {:disco_error, iq} ->
      {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}
  end

  @doc false
  def handle_items(iq, host) do
    acc = Exjabberd.Hooks.run_fold(:disco_items, host, %{items: []}, [])

    items =
      case iq.to do
        nil ->
          # The server lists its services.
          acc.items ++
            [
              %{jid: "conference.#{host}", name: "Multi-User Chat"},
              %{jid: "pubsub.#{host}", name: "Publish-Subscribe"}
            ]

        %Exjabberd.Xmpp.Jid{domain: "pubsub." <> _, local: nil} ->
          # The PubSub service lists its nodes.
          Enum.map(Exjabberd.Mod.PubSub.list_nodes(host), fn node ->
            %{jid: "pubsub.#{host}", node: node}
          end)

        %Exjabberd.Xmpp.Jid{domain: "conference." <> _, local: nil} ->
          # The MUC service lists its rooms.
          Enum.map(Exjabberd.Mod.Muc.list_rooms(host), fn room ->
            %{jid: room}
          end)

        %Exjabberd.Xmpp.Jid{local: nil, domain: domain} when domain == host ->
          # The server lists its services.
          acc.items ++
            [
              %{jid: "conference.#{host}", name: "Multi-User Chat"},
              %{jid: "pubsub.#{host}", name: "Publish-Subscribe"}
            ]

        _ ->
          acc.items
      end

    {:ok,
     %{
       iq
       | type: "result",
         payload: [%{xmlns: "http://jabber.org/protocol/disco#items", items: items}]
     }}
  end

  # The `node` attribute of the disco query element, if any.
  defp query_node(iq) do
    case Exjabberd.Xmpp.Stanza.child(iq.payload, "query") do
      %{attrs: %{"node" => node}} -> node
      _ -> nil
    end
  end
end

defmodule Exjabberd.Mod.Ping do
  @moduledoc "XMPP Ping - `mod_ping` (XEP-0199) (partial implementation). Answers c2s pings and pings clients with `ping_interval` like ejabberd."

  use Exjabberd.Mod.GenMod

  @impl true
  def start(host, opts) do
    interval = Keyword.get(opts, :ping_interval, 60)
    timeout = Keyword.get(opts, :ping_ack_timeout, 30)
    Exjabberd.Hooks.add(:c2s_ping, host, __MODULE__, :handle_ping, 50)
    # In real impl, start timer like `mod_ping` does with `erlang:send_after`
    _ = {interval, timeout}
    Exjabberd.Iq.register(host, "urn:xmpp:ping", __MODULE__, :handle_iq)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:c2s_ping, host, __MODULE__, :handle_ping)
    Exjabberd.Iq.unregister(host, "urn:xmpp:ping", :both)
    :ok
  end

  @doc false
  def handle_ping(iq, _host), do: iq

  @doc false
  def handle_iq(%{type: "get"} = iq, _host), do: {:ok, %{iq | type: "result", payload: []}}
  def handle_iq(iq, _host), do: {:ok, iq}
end
