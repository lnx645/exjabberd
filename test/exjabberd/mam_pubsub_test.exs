defmodule Exjabberd.MamPubsubTest do
  @moduledoc """
  Live C2S integration tests for XEP-0313 (Message Archive
  Management) and XEP-0060 (Publish-Subscribe), speaking real XMPP
  over raw sockets against the booted application (port 5222).

  Run with the dev server stopped (it also binds 5222):

      ELIXIR_ERL_OPTIONS="+fnu -sname exjabberd-test" mix test

  Mirrors `test_mam_pubsub.py` at the repo root, which is the
  repeatable raw-socket probe for the same behaviour.
  """
  use ExUnit.Case, async: false

  alias Exjabberd.Mod.{Mam, PubSub}

  @host ~c"127.0.0.1"
  @port 5222
  @stream_open "<?xml version='1.0'?><stream:stream to='localhost' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"

  # Fresh users per test: MAM archives accumulate per user, so tests
  # sharing users would see each other's messages.
  setup do
    suffix = System.unique_integer([:positive])

    users = %{
      andi: "mpandi#{suffix}",
      budi: "mpbudi#{suffix}",
      carol: "mpcarol#{suffix}"
    }

    for {_k, user} <- users do
      case Exjabberd.Auth.create_user("localhost", user, "secret") do
        :ok -> :ok
        {:error, _} -> :ok
      end
    end

    {:ok, users: users, tag: "MPT-#{suffix}"}
  end

  # --- socket helpers (same shape as LiveC2STest) ---

  defp connect do
    {:ok, sock} = :gen_tcp.connect(@host, @port, [:binary, packet: 0, active: false], 5_000)
    sock
  end

  defp send_recv(sock, data, needle, timeout \\ 6_000) do
    :ok = :gen_tcp.send(sock, data)
    recv_until(sock, needle, timeout)
  end

  defp recv_until(sock, needle, timeout), do: recv_until(sock, needle, timeout, "")

  defp recv_until(sock, needle, timeout, acc) do
    if String.contains?(acc, needle) do
      acc
    else
      case :gen_tcp.recv(sock, 0, timeout) do
        {:ok, data} -> recv_until(sock, needle, timeout, acc <> data)
        {:error, _} -> acc
      end
    end
  end

  # Whatever arrives within `timeout` ("" when nothing does).
  defp recv_any(sock, timeout \\ 1_500) do
    case :gen_tcp.recv(sock, 0, timeout) do
      {:ok, data} -> data
      {:error, _} -> ""
    end
  end

  defp login(sock, user, pass, resource) do
    _ = send_recv(sock, @stream_open, "stream:features")
    b64 = Base.encode64("\0#{user}\0#{pass}")

    r =
      send_recv(
        sock,
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>#{b64}</auth>",
        "success"
      )

    assert r =~ "<success", "PLAIN auth failed for #{user}: #{r}"
    _ = send_recv(sock, @stream_open, "stream:features")

    r =
      send_recv(
        sock,
        "<iq type='set' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>#{resource}</resource></bind></iq>",
        "bind"
      )

    assert r =~ "<jid>#{user}@localhost/#{resource}</jid>", "bind failed: #{r}"
    :ok
  end

  defp mam_query(sock, qid, extra \\ "") do
    :ok =
      :gen_tcp.send(
        sock,
        "<iq type='set' id='#{qid}'><query xmlns='urn:xmpp:mam:2' queryid='#{qid}'>#{extra}</query></iq>"
      )

    Process.sleep(700)
    recv_any(sock, 3_000)
  end

  defp mam_bodies(xml) do
    Regex.scan(~r/<result[^>]*? id='[^']+'[^>]*>.*?<body>([^<]*)<\/body>/s, xml,
      capture: :all_but_first
    )
    |> List.flatten()
  end

  # --- configuration ---

  test "mam and pubsub modules are loaded with configured options" do
    loaded = Exjabberd.Mod.Supervisor.loaded("localhost")
    assert Exjabberd.Mod.Mam in loaded
    assert Exjabberd.Mod.PubSub in loaded
    assert Mam.default_pref("localhost") == "always"
    assert Mam.max_archive_size("localhost") == 500
    assert PubSub.service_jid("localhost") == "pubsub.localhost"
  end

  test "disco advertises mam and pubsub", %{users: users} do
    sock = connect()
    login(sock, users.andi, "secret", "disco")

    r =
      send_recv(
        sock,
        "<iq type='get' id='d1' to='localhost'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>",
        "d1"
      )

    assert r =~ "urn:xmpp:mam:2"
    assert r =~ "http://jabber.org/protocol/pubsub"
    :gen_tcp.close(sock)
  end

  # --- MAM ---

  test "mam archives 1-1 messages and queries them in order", %{users: users, tag: tag} do
    andi = connect()
    budi = connect()
    login(andi, users.andi, "secret", "m1")
    login(budi, users.budi, "secret", "m1")
    _ = recv_any(andi)
    _ = recv_any(budi)

    :ok =
      :gen_tcp.send(
        andi,
        "<message type='chat' to='#{users.budi}@localhost'><body>#{tag} satu</body></message>"
      )

    # Separate C2S processes archive in arrival order; human-scale
    # spacing keeps the expected order deterministic.
    Process.sleep(400)

    :ok =
      :gen_tcp.send(
        andi,
        "<message type='chat' to='#{users.budi}@localhost'><body>#{tag} dua</body></message>"
      )

    Process.sleep(400)

    :ok =
      :gen_tcp.send(
        budi,
        "<message type='chat' to='#{users.andi}@localhost'><body>#{tag} balas</body></message>"
      )

    Process.sleep(800)
    _ = recv_any(budi)
    _ = recv_any(andi)

    r = mam_query(budi, "q1")
    assert mam_bodies(r) == ["#{tag} satu", "#{tag} dua", "#{tag} balas"]
    assert r =~ "<delay"
    assert r =~ "xmlns='urn:xmpp:mam:2'"
    assert r =~ "<fin"
    assert r =~ "<count>3</count>"

    r = mam_query(andi, "q2")
    assert mam_bodies(r) == ["#{tag} satu", "#{tag} dua", "#{tag} balas"]

    :gen_tcp.close(andi)
    :gen_tcp.close(budi)
  end

  test "mam with/start/end filters and rsm paging", %{users: users, tag: tag} do
    andi = connect()
    budi = connect()
    login(andi, users.andi, "secret", "m2")
    login(budi, users.budi, "secret", "m2")
    _ = recv_any(andi)
    _ = recv_any(budi)

    :ok =
      :gen_tcp.send(
        andi,
        "<message type='chat' to='#{users.budi}@localhost'><body>#{tag} awal</body></message>"
      )

    Process.sleep(1_200)
    mid = DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()
    Process.sleep(300)

    :ok =
      :gen_tcp.send(
        andi,
        "<message type='chat' to='#{users.budi}@localhost'><body>#{tag} akhir</body></message>"
      )

    Process.sleep(800)
    _ = recv_any(budi)

    xdata = fn fields ->
      inner =
        Enum.map_join(fields, "", fn {k, v} ->
          "<field var='#{k}'><value>#{v}</value></field>"
        end)

      "<x xmlns='jabber:x:data' type='submit'>#{inner}</x>"
    end

    r = mam_query(budi, "qf1", xdata.(%{"with" => "#{users.andi}@localhost"}))
    assert mam_bodies(r) == ["#{tag} awal", "#{tag} akhir"]

    r = mam_query(budi, "qf2", xdata.(%{"with" => "#{users.carol}@localhost"}))
    assert mam_bodies(r) == []
    assert r =~ "<count>0</count>"

    r = mam_query(budi, "qf3", xdata.(%{"start" => mid}))
    assert mam_bodies(r) == ["#{tag} akhir"]

    r = mam_query(budi, "qf4", xdata.(%{"end" => mid}))
    assert mam_bodies(r) == ["#{tag} awal"]

    rsm = fn inner ->
      "<set xmlns='http://jabber.org/protocol/rsm'>#{inner}</set>"
    end

    r =
      mam_query(
        budi,
        "qr1",
        xdata.(%{"with" => "#{users.andi}@localhost"}) <> rsm.("<max>1</max>")
      )

    assert mam_bodies(r) == ["#{tag} awal"]
    assert r =~ "complete='false'"
    assert r =~ "<count>2</count>"
    [_, first_id] = Regex.run(~r/<result[^>]*? id='([^']+)'/, r)

    r =
      mam_query(
        budi,
        "qr2",
        xdata.(%{"with" => "#{users.andi}@localhost"}) <>
          rsm.("<max>1</max><after>#{first_id}</after>")
      )

    assert mam_bodies(r) == ["#{tag} akhir"]

    :gen_tcp.close(andi)
    :gen_tcp.close(budi)
  end

  test "mam prefs never stops archiving, always resumes", %{users: users, tag: tag} do
    andi = connect()
    carol = connect()
    login(andi, users.andi, "secret", "m3")
    login(carol, users.carol, "secret", "m3")
    _ = recv_any(andi)
    _ = recv_any(carol)

    r =
      send_recv(
        carol,
        "<iq type='set' id='pf1'><prefs xmlns='urn:xmpp:mam:2' default='never'><always/><never/></prefs></iq>",
        "pf1"
      )

    assert r =~ "default='never'"

    :ok =
      :gen_tcp.send(
        andi,
        "<message type='chat' to='#{users.carol}@localhost'><body>#{tag} jangan</body></message>"
      )

    Process.sleep(800)
    _ = recv_any(carol)
    assert mam_query(carol, "qp1") |> mam_bodies() == []

    _ =
      send_recv(
        carol,
        "<iq type='set' id='pf2'><prefs xmlns='urn:xmpp:mam:2' default='always'><always/><never/></prefs></iq>",
        "pf2"
      )

    :ok =
      :gen_tcp.send(
        andi,
        "<message type='chat' to='#{users.carol}@localhost'><body>#{tag} ya</body></message>"
      )

    Process.sleep(800)
    _ = recv_any(carol)
    assert mam_query(carol, "qp2") |> mam_bodies() == ["#{tag} ya"]

    :gen_tcp.close(andi)
    :gen_tcp.close(carol)
  end

  test "mam archives muc room history", %{users: users, tag: tag} do
    andi = connect()
    budi = connect()
    login(andi, users.andi, "secret", "m4")
    login(budi, users.budi, "secret", "m4")
    room = "mamroom#{System.unique_integer([:positive])}@conference.localhost"
    :ok = :gen_tcp.send(andi, "<presence to='#{room}/andi-nick'/>")
    :ok = :gen_tcp.send(budi, "<presence to='#{room}/budi-nick'/>")
    Process.sleep(1_000)
    _ = recv_any(andi)
    _ = recv_any(budi)

    :ok =
      :gen_tcp.send(
        andi,
        "<message type='groupchat' to='#{room}'><body>#{tag} obrolan</body></message>"
      )

    Process.sleep(800)
    _ = recv_any(budi)

    r =
      send_recv(
        andi,
        "<iq type='set' id='qm1' to='#{room}'><query xmlns='urn:xmpp:mam:2' queryid='qm1'/></iq>",
        "qm1",
        6_000
      )

    # The room MAM results arrive as messages before the IQ result.
    r = r <> recv_any(andi, 3_000)
    assert mam_bodies(r) == ["#{tag} obrolan"]
    assert r =~ "<count>1</count>"

    :gen_tcp.close(andi)
    :gen_tcp.close(budi)
  end

  # --- PubSub ---

  test "pubsub create/subscribe/publish/items/retract/unsubscribe/delete", %{
    users: users,
    tag: tag
  } do
    node = "exunit-#{System.unique_integer([:positive])}"
    andi = connect()
    budi = connect()
    login(andi, users.andi, "secret", "p1")
    login(budi, users.budi, "secret", "p1")
    _ = recv_any(andi)
    _ = recv_any(budi)

    r =
      send_recv(
        andi,
        "<iq type='set' id='c1' to='pubsub.localhost'><pubsub xmlns='http://jabber.org/protocol/pubsub'><create node='#{node}'/></pubsub></iq>",
        "c1"
      )

    assert r =~ "type='result'"

    r =
      send_recv(
        andi,
        "<iq type='set' id='c2' to='pubsub.localhost'><pubsub xmlns='http://jabber.org/protocol/pubsub'><create node='#{node}'/></pubsub></iq>",
        "c2"
      )

    assert r =~ "type='error'" and r =~ "conflict"

    r =
      send_recv(
        budi,
        "<iq type='set' id='s1' to='pubsub.localhost'><pubsub xmlns='http://jabber.org/protocol/pubsub'><subscribe node='#{node}' jid='#{users.budi}@localhost'/></pubsub></iq>",
        "s1"
      )

    assert r =~ "subscription='subscribed'"
    assert r =~ "subid='"

    r =
      send_recv(
        andi,
        "<iq type='set' id='p1' to='pubsub.localhost'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='#{node}'><item id='it1'><entry>#{tag} berita</entry></item></publish></pubsub></iq>",
        "p1"
      )

    assert r =~ "type='result'"
    event = recv_any(budi, 3_000)
    assert event =~ "pubsub#event"
    assert event =~ "#{tag} berita"
    assert event =~ "it1"

    r =
      send_recv(
        budi,
        "<iq type='set' id='p2' to='pubsub.localhost'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='#{node}'><item id='it2'><entry>x</entry></item></publish></pubsub></iq>",
        "p2"
      )

    assert r =~ "type='error'" and r =~ "forbidden"

    r =
      send_recv(
        budi,
        "<iq type='get' id='g1' to='pubsub.localhost'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='#{node}'/></pubsub></iq>",
        "g1"
      )

    assert r =~ "it1" and r =~ "#{tag} berita"

    r =
      send_recv(
        andi,
        "<iq type='set' id='r1' to='pubsub.localhost'><pubsub xmlns='http://jabber.org/protocol/pubsub'><retract node='#{node}'><item id='it1'/></retract></pubsub></iq>",
        "r1"
      )

    assert r =~ "type='result'"
    event = recv_any(budi, 3_000)
    assert event =~ "retract" and event =~ "it1"

    r =
      send_recv(
        budi,
        "<iq type='get' id='g2' to='pubsub.localhost'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='#{node}'/></pubsub></iq>",
        "g2"
      )

    refute r =~ "it1"

    r =
      send_recv(
        budi,
        "<iq type='set' id='u1' to='pubsub.localhost'><pubsub xmlns='http://jabber.org/protocol/pubsub'><unsubscribe node='#{node}' jid='#{users.budi}@localhost'/></pubsub></iq>",
        "u1"
      )

    assert r =~ "type='result'"

    r =
      send_recv(
        andi,
        "<iq type='set' id='d1' to='pubsub.localhost'><pubsub xmlns='http://jabber.org/protocol/pubsub#owner'><delete node='#{node}'/></pubsub></iq>",
        "d1"
      )

    assert r =~ "type='result'"

    r =
      send_recv(
        budi,
        "<iq type='get' id='g3' to='pubsub.localhost'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='#{node}'/></pubsub></iq>",
        "g3"
      )

    assert r =~ "type='error'" and r =~ "item-not-found"

    :gen_tcp.close(andi)
    :gen_tcp.close(budi)
  end

  test "pubsub disco lists nodes and node info", %{users: users} do
    node = "exunit-disco-#{System.unique_integer([:positive])}"
    andi = connect()
    login(andi, users.andi, "secret", "p2")
    _ = recv_any(andi)

    r =
      send_recv(
        andi,
        "<iq type='set' id='c1' to='pubsub.localhost'><pubsub xmlns='http://jabber.org/protocol/pubsub'><create node='#{node}'/></pubsub></iq>",
        "c1"
      )

    assert r =~ "type='result'"

    r =
      send_recv(
        andi,
        "<iq type='get' id='di1' to='pubsub.localhost'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>",
        "di1"
      )

    assert r =~ "node='#{node}'"

    r =
      send_recv(
        andi,
        "<iq type='get' id='di2' to='pubsub.localhost'><query xmlns='http://jabber.org/protocol/disco#info' node='#{node}'/></iq>",
        "di2"
      )

    assert r =~ "category='pubsub'" and r =~ "type='leaf'"

    :gen_tcp.close(andi)
  end
end
