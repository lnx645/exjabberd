defmodule Exjabberd.OmemoTest do
  @moduledoc """
  Unit tests for the OMEMO (XEP-0384) PEP node classification and
  auto-create configuration across all three wire generations
  (legacy axolotl, `urn:xmpp:omemo:1`, `urn:xmpp:omemo:2`). The
  live publish/fetch behaviour is covered by
  `test_omemo2_phase18.py` (modern generations) and
  `test_jingle_phase5.py` (legacy generation).
  """

  use ExUnit.Case, async: true

  alias Exjabberd.Mod.Omemo

  test "legacy nodes are OMEMO nodes with one item and open access" do
    assert Omemo.omemo_node?("eu.siacs.conversations.axolotl.devicelist")
    assert Omemo.omemo_node?("eu.siacs.conversations.axolotl.bundles:31415")
    refute Omemo.multi_bundle_node?("eu.siacs.conversations.axolotl.bundles:31415")

    cfg = Omemo.node_config("eu.siacs.conversations.axolotl.devicelist")
    assert cfg[:access_model] == "open"
    assert cfg[:publish_model] == "open"
    assert cfg[:max_items] == 1

    assert Omemo.node_config("eu.siacs.conversations.axolotl.bundles:31415")[:max_items] == 1
  end

  test "omemo:1 and omemo:2 devices nodes hold exactly one item" do
    for ns <- ["urn:xmpp:omemo:1", "urn:xmpp:omemo:2"] do
      node = ns <> ":devices"
      assert Omemo.omemo_node?(node)
      refute Omemo.multi_bundle_node?(node)
      cfg = Omemo.node_config(node)
      assert cfg[:access_model] == "open"
      assert cfg[:max_items] == 1
    end
  end

  test "omemo:1 and omemo:2 bundles node holds one item per device (max_items = max)" do
    for ns <- ["urn:xmpp:omemo:1", "urn:xmpp:omemo:2"] do
      node = ns <> ":bundles"
      assert Omemo.omemo_node?(node)
      assert Omemo.multi_bundle_node?(node)
      cfg = Omemo.node_config(node)
      assert cfg[:access_model] == "open"
      assert cfg[:publish_model] == "open"
      # "max" is encoded as 100_000, exactly like publish-options
      # pubsub#max_items=max in PubSub.config_from_form/1.
      assert cfg[:max_items] == 100_000
    end
  end

  test "non-OMEMO nodes get no special config" do
    refute Omemo.omemo_node?("urn:xmpp:omemo:2")
    refute Omemo.omemo_node?("urn:xmpp:omemo:3:devices")
    refute Omemo.omemo_node?("http://jabber.org/protocol/tune")
    refute Omemo.omemo_node?(nil)
    assert Omemo.node_config("http://jabber.org/protocol/tune") == []
  end

  test "all three generations are advertised as disco features" do
    assert Omemo.disco_features() == [
             "urn:xmpp:omemo:0",
             "urn:xmpp:omemo:1",
             "urn:xmpp:omemo:2"
           ]

    assert Omemo.disco_feature() == "urn:xmpp:omemo:0"
  end
end
