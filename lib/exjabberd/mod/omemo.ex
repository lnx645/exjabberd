defmodule Exjabberd.Mod.Omemo do
  @moduledoc """
  OMEMO — XEP-0384, all three wire generations, over PEP
  (XEP-0163):

  * legacy `eu.siacs.conversations.axolotl` (advertised as
    `urn:xmpp:omemo:0`, XEP-0384 pre-0.4) — the generation
    Conversations / Gajim / slixmpp speak;
  * `urn:xmpp:omemo:1` (XEP-0384 0.4.0–0.7.0);
  * `urn:xmpp:omemo:2` (XEP-0384 0.8.0+, the current spec).

  The server does no cryptography: OMEMO key material is opaque
  payload in PEP nodes, the Signal sessions live entirely in the
  clients, and `<encrypted/>` message payloads are ordinary
  message routing. What the server owes XEP-0384 is the
  *plumbing*, here plus in `Exjabberd.Mod.PubSub` (PEP
  namespacing, auto-create, publish-options) and the bare-JID
  disco in `Exjabberd.Mod.Disco` / `PubSub`:

  * Device lists:
    - legacy node `eu.siacs.conversations.axolotl.devicelist`,
      one item, the current `<list/>` of `<device id/>` elements;
    - `urn:xmpp:omemo:1:devices` and `urn:xmpp:omemo:2:devices`,
      one item with id `current`, a `<devices/>` element
      (XEP-0384 §5.3.1 in both generations).
  * Bundles:
    - legacy: one node per device,
      `eu.siacs.conversations.axolotl.bundles:<deviceId>`, one
      item, the `<bundle/>` with identity key, signed pre-key and
      pre-keys;
    - :1/:2: ONE node per account, `urn:xmpp:omemo:1:bundles` /
      `urn:xmpp:omemo:2:bundles`, holding MANY items — one
      `<bundle/>` item per device, item id = device id
      (XEP-0384 §5.3.2). The node is therefore configured with
      `max_items` = "max" (encoded internally as 100_000, the
      same value publish-options `pubsub#max_items=max` maps to
      in `PubSub.config_from_form/1`), unlike every other OMEMO
      node which holds exactly one item.
  * Every OMEMO node is `access_model: open` (XEP-0384 REQUIRES
    it for the :1/:2 devices and bundles nodes, and §4.2 of the
    legacy text for its nodes: contacts without a presence
    subscription must still read them) and `publish_model: open`
    (the owner publishes; PEP additionally restricts publishing
    to the owner — see `PubSub.handle_publish/5`).

  A contact fetches bundles with an IQ-get for `<items/>`
  addressed to the owner's *bare* JID; the device list is
  discovered through disco#items on the bare JID, and the account
  advertises all three features — `urn:xmpp:omemo:0`,
  `urn:xmpp:omemo:1`, `urn:xmpp:omemo:2` — in disco#info, each
  backed by the real node layout above.
  """

  use Exjabberd.Mod.GenMod
  require Logger

  @devicelist_node "eu.siacs.conversations.axolotl.devicelist"
  @bundles_prefix "eu.siacs.conversations.axolotl.bundles:"
  @axolotl_ns "eu.siacs.conversations.axolotl"

  # XEP-0384 :1 (0.4.0) and :2 (0.8.0) node names.
  @modern_devices_nodes ["urn:xmpp:omemo:1:devices", "urn:xmpp:omemo:2:devices"]
  @modern_bundles_nodes ["urn:xmpp:omemo:1:bundles", "urn:xmpp:omemo:2:bundles"]

  # The internal encoding of XEP-0060 `pubsub#max_items` = "max"
  # (see PubSub.config_from_form/1): effectively unbounded.
  @max_items_unbounded 100_000

  @features ["urn:xmpp:omemo:0", "urn:xmpp:omemo:1", "urn:xmpp:omemo:2"]

  @doc "The OMEMO device list node name (legacy generation)."
  @spec devicelist_node() :: binary()
  def devicelist_node, do: @devicelist_node

  @doc "The legacy bundle node name for one device id."
  @spec bundle_node(binary() | non_neg_integer()) :: binary()
  def bundle_node(device_id), do: @bundles_prefix <> to_string(device_id)

  @doc "The OMEMO disco features advertised on accounts (all generations)."
  @spec disco_features() :: [binary()]
  def disco_features, do: @features

  @doc "The legacy OMEMO disco feature (`urn:xmpp:omemo:0`)."
  @spec disco_feature() :: binary()
  def disco_feature, do: "urn:xmpp:omemo:0"

  @doc "The legacy OMEMO payload namespace (`<list/>`, `<bundle/>`)."
  @spec axolotl_ns() :: binary()
  def axolotl_ns, do: @axolotl_ns

  @doc """
  True when `node` holds many bundle items — the single
  `urn:xmpp:omemo:1:bundles` / `urn:xmpp:omemo:2:bundles` node,
  as opposed to the one-item device-list and legacy bundle nodes.
  """
  @spec multi_bundle_node?(binary()) :: boolean()
  def multi_bundle_node?(node) when is_binary(node), do: node in @modern_bundles_nodes
  def multi_bundle_node?(_), do: false

  @doc "True when `node` is an OMEMO device list or bundle node of any generation."
  @spec omemo_node?(binary()) :: boolean()
  def omemo_node?(node) when is_binary(node) do
    node == @devicelist_node or String.starts_with?(node, @bundles_prefix) or
      node in @modern_devices_nodes or node in @modern_bundles_nodes
  end

  def omemo_node?(_), do: false

  @doc """
  Node configuration for an OMEMO node, used when the node is
  auto-created on first publish: access open, publish open,
  persistent; one item for device lists and legacy bundle nodes,
  unbounded items for the :1/:2 single bundles node. Returns
  keyword opts for `PubSub.create_node/3`.
  """
  @spec node_config(binary()) :: keyword()
  def node_config(node) when is_binary(node) do
    cond do
      multi_bundle_node?(node) ->
        [
          access_model: "open",
          publish_model: "open",
          max_items: @max_items_unbounded,
          persist_items: true
        ]

      omemo_node?(node) ->
        [access_model: "open", publish_model: "open", max_items: 1, persist_items: true]

      true ->
        []
    end
  end

  @impl true
  def start(host, _opts) do
    Logger.info("mod_omemo started for #{host} (XEP-0384 legacy/:1/:2 nodes over PEP)")
    :ok
  end

  @impl true
  def stop(_host), do: :ok
end
