defmodule Exjabberd.Mod.Omemo do
  @moduledoc """
  OMEMO — XEP-0384 (legacy `eu.siacs.conversations.axolotl`
  generation, the one Conversations / Gajim / slixmpp speak) over
  PEP (XEP-0163).

  The server does not do any cryptography: OMEMO key material is
  opaque payload in PEP nodes, and the Signal sessions live
  entirely in the clients. What the server owes XEP-0384 is the
  *plumbing*, and it lives here plus in `Exjabberd.Mod.PubSub`
  (PEP namespacing, auto-create, publish-options) and
  `Exjabberd.Mod.Disco` (bare-JID disco):

  * Device list node `eu.siacs.conversations.axolotl.devicelist`
    — one item, the current `<list/>` of `<device id/>` elements.
  * One bundle node per device,
    `eu.siacs.conversations.axolotl.bundles:<deviceId>` — one item,
    the `<bundle/>` with the identity key, signed pre-key and
    pre-keys (XEP-0384 §4.3, Example 3).
  * Both node kinds are `access_model: open` (contacts without a
    presence subscription must still read them, XEP-0384 §4.2),
    `publish_model: open` (the owner publishes; PEP additionally
    restricts publishing to the owner — see `PubSub.handle_publish/5`),
    `max_items: 1` (one current list / one current bundle per node).

  A contact fetches a bundle with an IQ-get for `<items/>`
  addressed to the owner's *bare* JID (XEP-0384 §4.4, Example 4);
  the device list is discovered through disco#items on the bare
  JID, and the account advertises `urn:xmpp:omemo:0` in disco#info.

  Deliberately NOT implemented: the newer `urn:xmpp:omemo:1` /
  `urn:xmpp:omemo:2` generations (single `...:bundles` node with one
  item per device, `urn:xmpp:omemo:2:devices` node) — no client in
  the verification setup speaks them, and advertising them without
  the matching node layout would be a lie. The legacy nodes above
  are what the probes verify.
  """

  use Exjabberd.Mod.GenMod
  require Logger

  @devicelist_node "eu.siacs.conversations.axolotl.devicelist"
  @bundles_prefix "eu.siacs.conversations.axolotl.bundles:"
  @omemo_ns "urn:xmpp:omemo:0"
  @axolotl_ns "eu.siacs.conversations.axolotl"

  @doc "The OMEMO device list node name (XEP-0384 §4.2)."
  @spec devicelist_node() :: binary()
  def devicelist_node, do: @devicelist_node

  @doc "The bundle node name for one device id (XEP-0384 §4.3)."
  @spec bundle_node(binary() | non_neg_integer()) :: binary()
  def bundle_node(device_id), do: @bundles_prefix <> to_string(device_id)

  @doc "The OMEMO disco feature advertised on accounts."
  @spec disco_feature() :: binary()
  def disco_feature, do: @omemo_ns

  @doc "The legacy OMEMO payload namespace (`<list/>`, `<bundle/>`)."
  @spec axolotl_ns() :: binary()
  def axolotl_ns, do: @axolotl_ns

  @doc "True when `node` is an OMEMO device list or bundle node."
  @spec omemo_node?(binary()) :: boolean()
  def omemo_node?(node) when is_binary(node) do
    node == @devicelist_node or String.starts_with?(node, @bundles_prefix)
  end

  def omemo_node?(_), do: false

  @doc """
  Node configuration for an OMEMO node, used when the node is
  auto-created on first publish (XEP-0384: access open, publish
  open, one item). Returns keyword opts for `PubSub.create_node/3`.
  """
  @spec node_config(binary()) :: keyword()
  def node_config(node) when is_binary(node) do
    if omemo_node?(node) do
      [access_model: "open", publish_model: "open", max_items: 1, persist_items: true]
    else
      []
    end
  end

  @impl true
  def start(host, _opts) do
    Logger.info("mod_omemo started for #{host} (XEP-0384 legacy nodes over PEP)")
    :ok
  end

  @impl true
  def stop(_host), do: :ok
end
