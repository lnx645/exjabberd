defmodule Exjabberd.Mod.Avatar do
  @moduledoc """
  User Avatar — XEP-0084, over PEP (XEP-0163).

  Like OMEMO, the server does no image processing: avatar bytes
  are opaque payload in two PEP nodes on the owner's bare JID —

  * `urn:xmpp:avatar:data` — one `<data/>` item per avatar, item
    id = the avatar's SHA-1 hash;
  * `urn:xmpp:avatar:metadata` — one `<metadata/>` item per
    avatar (same id) describing it, or an empty `<metadata/>`
    item to stop publishing an avatar.

  What the server owes XEP-0084 is the same plumbing as XEP-0384
  (see `Exjabberd.Mod.Omemo`): the nodes are auto-created on
  first publish with `access_model: open` — a contact WITHOUT a
  presence subscription must still be able to fetch an avatar
  (XEP-0084 §2: the data/metadata nodes are world-readable by
  design, avatars are public) — and `publish_model: open` (PEP
  itself restricts publishing to the owner). The account
  advertises `urn:xmpp:avatar:metadata` in bare-JID disco#info.

  Deliberately NOT implemented: the vCard-temp avatar conversion
  (`mod_avatar`'s vcard_convert in ejabberd) — XEP-0153 photos in
  vCards keep working through `mod_vcard` itself, they are just
  not mirrored into PEP.
  """

  use Exjabberd.Mod.GenMod
  require Logger

  @data_node "urn:xmpp:avatar:data"
  @metadata_node "urn:xmpp:avatar:metadata"

  @doc "The avatar data node name (XEP-0084 §2.1)."
  @spec data_node() :: binary()
  def data_node, do: @data_node

  @doc "The avatar metadata node name (XEP-0084 §2.2)."
  @spec metadata_node() :: binary()
  def metadata_node, do: @metadata_node

  @doc "The disco feature advertised on accounts for avatar metadata."
  @spec disco_feature() :: binary()
  def disco_feature, do: @metadata_node

  @doc "True when `node` is one of the XEP-0084 avatar nodes."
  @spec avatar_node?(binary()) :: boolean()
  def avatar_node?(node) when is_binary(node), do: node in [@data_node, @metadata_node]
  def avatar_node?(_), do: false

  @doc """
  Node configuration for an avatar node, used when the node is
  auto-created on first publish (open access, open publish,
  persistent). Returns keyword opts for `PubSub.create_node/3`.
  """
  @spec node_config(binary()) :: keyword()
  def node_config(node) when is_binary(node) do
    if avatar_node?(node) do
      [access_model: "open", publish_model: "open", persist_items: true]
    else
      []
    end
  end

  @impl true
  def start(host, _opts) do
    Logger.info("mod_avatar started for #{host} (XEP-0084 nodes over PEP)")
    :ok
  end

  @impl true
  def stop(_host), do: :ok
end
