defmodule Exjabberd.AvatarPushTest do
  @moduledoc """
  Unit tests for User Avatar (XEP-0084) node classification and
  Push Notifications (XEP-0357) registration handling + the
  notification publish builder. The live wire behaviour is
  covered by `test_avatar_push_phase20.py`.
  """

  use ExUnit.Case, async: false

  alias Exjabberd.Mod.{Avatar, Push}

  # --- XEP-0084 ---

  test "avatar nodes are classified and get open/open persistent config" do
    assert Avatar.avatar_node?("urn:xmpp:avatar:data")
    assert Avatar.avatar_node?("urn:xmpp:avatar:metadata")
    refute Avatar.avatar_node?("urn:xmpp:avatar")
    refute Avatar.avatar_node?("http://jabber.org/protocol/tune")
    refute Avatar.avatar_node?(nil)

    for node <- ["urn:xmpp:avatar:data", "urn:xmpp:avatar:metadata"] do
      cfg = Avatar.node_config(node)
      assert cfg[:access_model] == "open"
      assert cfg[:publish_model] == "open"
      assert cfg[:persist_items] == true
    end

    assert Avatar.node_config("http://jabber.org/protocol/tune") == []
    assert Avatar.disco_feature() == "urn:xmpp:avatar:metadata"
  end

  # --- XEP-0357 store ---

  test "registrations can be added, replaced, and removed per user" do
    bare = "pushunit@localhost"
    Push.unregister(bare)

    assert Push.registrations(bare) == []
    Push.register(bare, "pubsub.localhost", "push-1", %{"secret" => "s3cr3t"})
    Push.register(bare, "push.example.com", "node-2")

    regs = Push.registrations(bare)
    assert length(regs) == 2
    assert Enum.find(regs, &(&1.node == "push-1")).options == %{"secret" => "s3cr3t"}

    # Re-registering the same (service, node) replaces, not duplicates.
    Push.register(bare, "pubsub.localhost", "push-1")
    assert length(Push.registrations(bare)) == 2
    assert Enum.find(Push.registrations(bare), &(&1.node == "push-1")).options == %{}

    # Targeted disable removes one; blanket disable removes all.
    Push.unregister(bare, "pubsub.localhost", "push-1")
    assert [%{node: "node-2"}] = Push.registrations(bare)
    Push.unregister(bare)
    assert Push.registrations(bare) == []
  end

  # --- XEP-0357 IQ handling ---

  defp iq(payload, from \\ "pushiq@localhost/phone") do
    %{
      name: :iq,
      id: "p1",
      type: "set",
      from: from,
      to: "localhost",
      payload: payload
    }
  end

  test "enable IQ registers the push service; disable removes it" do
    bare = "pushiq@localhost"
    Push.unregister(bare)

    enable = %{
      name: "enable",
      attrs: %{"xmlns" => "urn:xmpp:push:0", "jid" => "pubsub.localhost", "node" => "push-x"},
      children: []
    }

    assert {:ok, %{type: "result"}} = Push.handle_push_iq(iq([enable]), "localhost")
    assert [%{service: "pubsub.localhost", node: "push-x"}] = Push.registrations(bare)

    disable = %{
      name: "disable",
      attrs: %{"xmlns" => "urn:xmpp:push:0", "jid" => "pubsub.localhost", "node" => "push-x"},
      children: []
    }

    assert {:ok, %{type: "result"}} = Push.handle_push_iq(iq([disable]), "localhost")
    assert Push.registrations(bare) == []
  end

  test "enable without jid/node is a bad-request and stores nothing" do
    bare = "pushbad@localhost"
    Push.unregister(bare)

    enable = %{name: "enable", attrs: %{"xmlns" => "urn:xmpp:push:0"}, children: []}

    assert {:error, :bad_request, %{type: "error"}} =
             Push.handle_push_iq(iq([enable], "pushbad@localhost/phone"), "localhost")

    assert Push.registrations(bare) == []
  end

  test "enable options are kept for the pass-through form" do
    x = %{
      name: "x",
      attrs: %{"xmlns" => "jabber:x:data", "type" => "submit"},
      children: [
        %{name: "field", attrs: %{"var" => "FORM_TYPE"}, children: [
          %{name: "value", attrs: %{}, children: ["urn:xmpp:push:options"]}]},
        %{name: "field", attrs: %{"var" => "secret"}, children: [
          %{name: "value", attrs: %{}, children: ["abc123"]}]}
      ]
    }

    enable = %{
      name: "enable",
      attrs: %{"xmlns" => "urn:xmpp:push:0", "jid" => "push.example.com", "node" => "n1"},
      children: [%{name: "options", attrs: %{}, children: [x]}]
    }

    assert {:ok, %{type: "result"}} = Push.handle_push_iq(iq([enable]), "localhost")
    assert [%{options: %{"secret" => "abc123"}}] = Push.registrations("pushiq@localhost")
    Push.unregister("pushiq@localhost")
  end

  # --- XEP-0357 notification builder ---

  test "publish_iq builds a pubsub publish with summary + options forms" do
    reg = %{service: "push.example.com", node: "n1", options: %{"secret" => "abc123"}}

    iq =
      Push.publish_iq(
        "user@localhost",
        reg,
        3,
        "friend@localhost",
        "Halo, apa kabar?"
      )

    assert iq.name == :iq and iq.type == "set"
    assert iq.from == "user@localhost" and iq.to == "push.example.com"

    [pubsub] = iq.payload
    assert pubsub.name == "pubsub"
    [publish] = pubsub.children
    assert publish.attrs["node"] == "n1"
    [item] = publish.children
    [notification] = item.children
    assert notification.name == "notification"
    assert notification.attrs["xmlns"] == "urn:xmpp:push:0"

    assert [summary, options] = notification.children

    form_type = fn x ->
      x.children
      |> Enum.find(&(&1.attrs["var"] == "FORM_TYPE"))
      |> Map.get(:children)
      |> hd()
      |> Map.get(:children)
    end

    field = fn x, var ->
      x.children
      |> Enum.find(&(&1.attrs["var"] == var))
      |> Map.get(:children)
      |> hd()
      |> Map.get(:children)
      |> hd()
    end

    assert form_type.(summary) == ["urn:xmpp:push:summary"]
    assert field.(summary, "message-count") == "3"
    assert field.(summary, "last-message-sender") == "friend@localhost"
    assert field.(summary, "last-message-body") == "Halo, apa kabar?"
    assert form_type.(options) == ["urn:xmpp:push:options"]
    assert field.(options, "secret") == "abc123"

    # Without options only the summary form is sent.
    bare_iq =
      Push.publish_iq("u@localhost", %{service: "s", node: "n", options: %{}}, 1, "f@localhost", "hi")

    [ps] = bare_iq.payload
    [pub] = ps.children
    [it] = pub.children
    [notif] = it.children
    assert length(notif.children) == 1
  end
end
