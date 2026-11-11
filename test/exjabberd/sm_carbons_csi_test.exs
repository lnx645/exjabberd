defmodule Exjabberd.SmCarbonsCsiTest do
  @moduledoc """
  Live C2S integration tests for XEP-0198 (Stream Management),
  XEP-0280 (Message Carbons) and XEP-0352 (Client State
  Indication), speaking real XMPP over raw sockets against the
  booted application (port 5222).

  Run with the dev server stopped (it also binds 5222):

      ELIXIR_ERL_OPTIONS="+fnu -sname exjabberd-test" mix test

  Mirrors `test_sm_carbons_csi.py` at the repo root, which is the
  repeatable raw-socket probe for the same behaviour.
  """
  use ExUnit.Case, async: false

  alias Exjabberd.Mod.{Carbons, Csi, StreamMgmt}
  alias Exjabberd.Xmpp.Stanza

  @host ~c"127.0.0.1"
  @port 5222
  @stream_open "<?xml version='1.0'?><stream:stream to='localhost' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"

  setup_all do
    for {user, pass} <- [{"testandi", "secret"}, {"testbudi", "secret"}] do
      case Exjabberd.Auth.create_user("localhost", user, pass) do
        :ok -> :ok
        {:error, _} -> :ok
      end
    end

    :ok
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

  defp recv_until(sock, needle, timeout \\ 6_000), do: recv_until(sock, needle, timeout, "")

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

  defp uniq, do: System.unique_integer([:positive])

  # --- configuration ---

  test "stream management, carbons and CSI modules are loaded with configured options" do
    loaded = Exjabberd.Mod.Supervisor.loaded("localhost")
    assert Exjabberd.Mod.StreamMgmt in loaded
    assert Exjabberd.Mod.Carbons in loaded
    assert Exjabberd.Mod.Csi in loaded
    assert StreamMgmt.max_ack_queue("localhost") == 100
    assert StreamMgmt.resume_timeout("localhost") == 60
    assert Csi.max_queue("localhost") == 100
  end

  test "stream features advertise sm, csi and carbons after auth" do
    sock = connect()
    login(sock, "testandi", "secret", "feat#{uniq()}")
    _ = send_recv(sock, @stream_open, "stream:features")
    # The features block arrives with the stream header; re-open to
    # read a fresh copy.
    r = send_recv(sock, @stream_open, "stream:features")
    assert r =~ "urn:xmpp:sm:3"
    assert r =~ "urn:xmpp:csi:0"
    assert r =~ "urn:xmpp:carbons:2"
    :gen_tcp.close(sock)
  end

  # --- XEP-0198 ---

  test "SM: enable before bind fails, enable after bind acks and counts" do
    sock = connect()
    _ = send_recv(sock, @stream_open, "stream:features")
    b64 = Base.encode64("\0testandi\0secret")

    r =
      send_recv(
        sock,
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>#{b64}</auth>",
        "success"
      )

    assert r =~ "<success"
    r = send_recv(sock, "<enable xmlns='urn:xmpp:sm:3'/>", "failed")
    assert r =~ "<failed" and r =~ "unexpected-request"
    :gen_tcp.close(sock)

    sock = connect()
    login(sock, "testandi", "secret", "smc#{uniq()}")
    r = send_recv(sock, "<enable xmlns='urn:xmpp:sm:3' resume='true'/>", "enabled")
    assert r =~ "<enabled" and r =~ "resume='true'" and r =~ "max='60'"
    assert r =~ "previd='"

    r =
      send_recv(
        sock,
        "<iq type='get' id='roster1'><query xmlns='jabber:iq:roster'/></iq><r xmlns='urn:xmpp:sm:3'/>",
        "<a "
      )

    assert r =~ "<a xmlns='urn:xmpp:sm:3' h='1'/>"
    :gen_tcp.close(sock)
  end

  test "SM: drop TCP, resume replays only the unacked stanza" do
    res_a = "smr#{uniq()}"
    res_b = "smr#{uniq()}"
    a = connect()
    login(a, "testandi", "secret", res_a)
    r = send_recv(a, "<enable xmlns='urn:xmpp:sm:3' resume='true'/>", "enabled")
    [_, smid] = Regex.run(~r/id='([^']+)'/, r)

    b = connect()
    login(b, "testbudi", "secret", res_b)

    # Server sends andi exactly one stanza (budi's message, seq 1).
    :ok =
      :gen_tcp.send(
        b,
        "<message to='testandi@localhost/#{res_a}' type='chat' id='mB1'><body>pesan sebelum putus</body></message>"
      )

    assert recv_until(a, "pesan sebelum putus") =~ "pesan sebelum putus"
    # andi does NOT ack it.
    :gen_tcp.close(a)
    Process.sleep(1_000)

    # While detached, a second message is queued server-side.
    :ok =
      :gen_tcp.send(
        b,
        "<message to='testandi@localhost/#{res_a}' type='chat' id='mB2'><body>pesan saat putus</body></message>"
      )

    Process.sleep(500)

    a2 = connect()
    _ = send_recv(a2, @stream_open, "stream:features")

    r =
      send_recv(
        a2,
        "<resume xmlns='urn:xmpp:sm:3' h='1' previd='#{smid}'/>",
        "resumed"
      )

    assert r =~ "<resumed" and r =~ "previd='#{smid}'"
    r = recv_until(a2, "pesan saat putus")
    assert r =~ "pesan saat putus"
    refute r =~ "pesan sebelum putus"

    # Counters carried over: andi sent 0 stanzas before the drop,
    # so the first stanza after resume is in_h 1.
    r =
      send_recv(
        a2,
        "<message to='testbudi@localhost/#{res_b}' type='chat' id='mA2'><body>setelah resume</body></message><r xmlns='urn:xmpp:sm:3'/>",
        "<a "
      )

    assert r =~ "h='1'"
    assert recv_until(b, "setelah resume") =~ "setelah resume"
    :gen_tcp.close(a2)
    :gen_tcp.close(b)
  end

  test "SM: resume with unknown previd fails but the stream stays usable" do
    sock = connect()
    _ = send_recv(sock, @stream_open, "stream:features")

    r =
      send_recv(
        sock,
        "<resume xmlns='urn:xmpp:sm:3' h='0' previd='bogus-previd'/>",
        "failed"
      )

    assert r =~ "<failed" and r =~ "item-not-found"
    login(sock, "testandi", "secret", "smw#{uniq()}")
    :gen_tcp.close(sock)
  end

  # --- XEP-0280 ---

  test "Carbons: sent/received copies, disable stops them, private is not copied" do
    ra1 = "c1#{uniq()}"
    ra2 = "c2#{uniq()}"
    rb = "c3#{uniq()}"
    a1 = connect()
    login(a1, "testandi", "secret", ra1)
    a2 = connect()
    login(a2, "testandi", "secret", ra2)
    b = connect()
    login(b, "testbudi", "secret", rb)

    for {sock, id} <- [{a1, "ce1"}, {a2, "ce2"}] do
      r =
        send_recv(
          sock,
          "<iq type='set' id='#{id}'><enable xmlns='urn:xmpp:carbons:2'/></iq>",
          id
        )

      assert r =~ "type='result'", "carbons enable failed: #{r}"
    end

    :ok =
      :gen_tcp.send(
        a1,
        "<message to='testbudi@localhost/#{rb}' type='chat' id='cm1'><body>halo dari carb1</body></message>"
      )

    assert recv_until(b, "halo dari carb1") =~ "halo dari carb1"
    r = recv_until(a2, "carbons:2")
    assert r =~ "<sent" and r =~ "halo dari carb1"

    :ok =
      :gen_tcp.send(
        b,
        "<message to='testandi@localhost/#{ra1}' type='chat' id='cm2'><body>balasan budi</body></message>"
      )

    assert recv_until(a1, "balasan budi") =~ "balasan budi"
    r = recv_until(a2, "carbons:2")
    assert r =~ "<received" and r =~ "balasan budi"

    r =
      send_recv(
        a2,
        "<iq type='set' id='cd1'><disable xmlns='urn:xmpp:carbons:2'/></iq>",
        "cd1"
      )

    assert r =~ "type='result'"

    :ok =
      :gen_tcp.send(
        a1,
        "<message to='testbudi@localhost/#{rb}' type='chat' id='cm3'><body>setelah disable</body></message>"
      )

    assert recv_until(b, "setelah disable") =~ "setelah disable"
    assert recv_any(a2) == ""

    :ok =
      :gen_tcp.send(
        a2,
        "<iq type='set' id='ce3'><enable xmlns='urn:xmpp:carbons:2'/></iq>"
      )

    _ = recv_until(a2, "ce3")

    :ok =
      :gen_tcp.send(
        a1,
        "<message to='testbudi@localhost/#{rb}' type='chat' id='cm4'><body>rahasia</body><private xmlns='urn:xmpp:carbons:2'/></message>"
      )

    assert recv_until(b, "rahasia") =~ "rahasia"
    assert recv_any(a2) == ""

    :gen_tcp.close(a1)
    :gen_tcp.close(a2)
    :gen_tcp.close(b)
  end

  test "Carbons.eligible?/1 follows XEP-0280 section 6.1" do
    chat =
      Stanza.new(:message, type: "chat", payload: [%{name: "body", attrs: %{}, children: ["hi"]}])

    assert Carbons.eligible?(chat)

    normal_body =
      Stanza.new(:message,
        type: "normal",
        payload: [%{name: "body", attrs: %{}, children: ["hi"]}]
      )

    assert Carbons.eligible?(normal_body)

    normal_bare = Stanza.new(:message, type: "normal", payload: [])
    refute Carbons.eligible?(normal_bare)

    error = Stanza.new(:message, type: "error", payload: [])
    refute Carbons.eligible?(error)

    groupchat =
      Stanza.new(:message,
        type: "groupchat",
        payload: [%{name: "body", attrs: %{}, children: ["hi"]}]
      )

    refute Carbons.eligible?(groupchat)

    private =
      Stanza.new(:message,
        type: "chat",
        payload: [
          %{name: "body", attrs: %{}, children: ["hi"]},
          %{name: "private", attrs: %{"xmlns" => "urn:xmpp:carbons:2"}, children: []}
        ]
      )

    refute Carbons.eligible?(private)

    carbon =
      Stanza.new(:message,
        payload: [
          %{
            name: "sent",
            attrs: %{"xmlns" => "urn:xmpp:carbons:2"},
            children: []
          }
        ]
      )

    refute Carbons.eligible?(carbon)
    refute Carbons.eligible?(Stanza.new(:presence))
  end

  # --- XEP-0352 ---

  test "CSI: inactive holds message and presence, ping still answers, active flushes" do
    ra = "csi#{uniq()}"
    rb = "csi#{uniq()}"
    a = connect()
    login(a, "testandi", "secret", ra)
    b = connect()
    login(b, "testbudi", "secret", rb)

    :ok = :gen_tcp.send(a, "<inactive xmlns='urn:xmpp:csi:0'/>")
    Process.sleep(500)

    :ok =
      :gen_tcp.send(
        b,
        "<message to='testandi@localhost/#{ra}' type='chat' id='csi-m1'><body>pesan ditahan</body></message>"
      )

    assert recv_any(a) == ""
    :ok = :gen_tcp.send(b, "<presence/>")
    assert recv_any(a) == ""

    r =
      send_recv(
        a,
        "<iq type='get' id='csi-ping1' to='localhost'><ping xmlns='urn:xmpp:ping'/></iq>",
        "csi-ping1"
      )

    assert r =~ "type='result'"

    :ok = :gen_tcp.send(a, "<active xmlns='urn:xmpp:csi:0'/>")
    # Flushed in order (message first, then presence), possibly in a
    # single TCP packet — one read for both.
    r = recv_until(a, "presence")
    assert r =~ "pesan ditahan"
    assert r =~ "<presence"

    :ok =
      :gen_tcp.send(
        b,
        "<message to='testandi@localhost/#{ra}' type='chat' id='csi-m2'><body>sesudah aktif</body></message>"
      )

    assert recv_until(a, "sesudah aktif") =~ "sesudah aktif"
    :gen_tcp.close(a)
    :gen_tcp.close(b)
  end

  test "Csi.deliver_now?/1 lets IQ and error stanzas through" do
    assert Csi.deliver_now?(Stanza.new(:iq, type: "get"))
    assert Csi.deliver_now?(Stanza.new(:message, type: "error"))
    refute Csi.deliver_now?(Stanza.new(:message, type: "chat"))
    refute Csi.deliver_now?(Stanza.new(:presence))
  end
end
