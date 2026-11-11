defmodule Exjabberd.JingleOmemoTest do
  @moduledoc """
  Live C2S integration tests for Fase 5 — Jingle signaling
  (XEP-0166 + XEP-0176), STUN/TURN (RFC 5389/5766, port 5478) and
  OMEMO over PEP (XEP-0384 legacy nodes, XEP-0163) — speaking real
  XMPP over raw sockets and real STUN/TURN over raw UDP/TCP against
  the booted application.

  Run with the dev server stopped (it also binds 5222/5478):

      ELIXIR_ERL_OPTIONS="+fnu -sname exjabberd-test" mix test

  Mirrors `test_jingle_phase5.py` and `test_stun_turn_phase5.py` at
  the repo root, the repeatable raw-socket probes for the same
  behaviour.
  """
  use ExUnit.Case, async: false

  require Logger

  alias Exjabberd.Mod.Jingle
  alias Exjabberd.StunTurn
  alias Exjabberd.StunTurn.Allocation

  @host ~c"127.0.0.1"
  @port 5222
  @stun_port 5478
  @stream_open "<?xml version='1.0'?><stream:stream to='localhost' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"

  setup do
    suffix = System.unique_integer([:positive])

    users = %{
      andi: "jgandi#{suffix}",
      budi: "jgbudi#{suffix}",
      carol: "jgcarol#{suffix}"
    }

    for {_k, user} <- users do
      case Exjabberd.Auth.create_user("localhost", user, "secret") do
        :ok -> :ok
        {:error, _} -> :ok
      end
    end

    {:ok, users: users, tag: "JG-#{suffix}"}
  end

  # --- socket helpers (same shape as MamPubsubTest) ---

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

  defp iq_result(sock, id, from, to) do
    :ok =
      :gen_tcp.send(
        sock,
        "<iq type='result' id='#{id}' from='#{from}' to='#{to}'/>"
      )
  end

  # --- modules ---

  test "jingle, omemo and stun/turn are loaded and listening" do
    loaded = Exjabberd.Mod.Supervisor.loaded("localhost")
    assert Exjabberd.Mod.Jingle in loaded
    assert Exjabberd.Mod.Omemo in loaded
    assert Process.whereis(Exjabberd.StunTurn.Server) != nil
    assert Exjabberd.StunTurn.Server.list_allocations() == []
    assert Exjabberd.Config.turn()["port"] == 5478
  end

  # --- Jingle ---

  test "jingle initiate/accept/transport-info/terminate flow", %{users: users} do
    andi = connect()
    budi = connect()
    login(andi, users.andi, "secret", "m1")
    login(budi, users.budi, "secret", "m1")
    _ = recv_any(andi)
    _ = recv_any(budi)

    sid = "sid-#{users.andi}"
    a_jid = "#{users.andi}@localhost/m1"
    b_jid = "#{users.budi}@localhost/m1"

    initiate =
      "<iq type='set' id='j1' to='#{b_jid}'><jingle xmlns='urn:xmpp:jingle:1' action='session-initiate' sid='#{sid}' initiator='#{a_jid}'><content creator='initiator' name='audio'><description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'><payload-type id='0' name='PCMU' clockrate='8000'/></description><transport xmlns='urn:xmpp:jingle:transports:ice-udp:1'><candidate component='1' foundation='abc123' generation='0' id='c1' ip='192.0.2.1' network='1' port='5000' priority='100' protocol='udp' type='host'/></transport></content></jingle></iq>"

    :ok = :gen_tcp.send(andi, initiate)
    got = recv_until(budi, "session-initiate")
    assert got =~ "session-initiate", "initiate never reached budi: #{got}"
    assert got =~ sid
    assert got =~ "foundation='abc123'"
    assert got =~ "urn:xmpp:jingle:transports:ice-udp:1"

    # The server tracks the session as pending; the initiator gets
    # no reply until the responder answers.
    assert {:ok, %{state: :pending, initiator: ^a_jid, responder: ^b_jid}} =
             Jingle.get_session("localhost", sid)

    iq_result(budi, "j1", b_jid, a_jid)
    assert recv_until(andi, "j1") =~ "type='result'"

    accept =
      "<iq type='set' id='j2' to='#{a_jid}'><jingle xmlns='urn:xmpp:jingle:1' action='session-accept' sid='#{sid}' responder='#{b_jid}'><content creator='initiator' name='audio'><description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'/><transport xmlns='urn:xmpp:jingle:transports:ice-udp:1'/></content></jingle></iq>"

    :ok = :gen_tcp.send(budi, accept)
    assert recv_until(andi, "session-accept") =~ sid
    assert {:ok, %{state: :active}} = Jingle.get_session("localhost", sid)
    iq_result(andi, "j2", a_jid, b_jid)

    transport =
      "<iq type='set' id='j3' to='#{b_jid}'><jingle xmlns='urn:xmpp:jingle:1' action='transport-info' sid='#{sid}'><content creator='initiator' name='audio'><transport xmlns='urn:xmpp:jingle:transports:ice-udp:1'><candidate component='1' foundation='def456' generation='0' id='c2' ip='192.0.2.1' network='1' port='5001' priority='90' protocol='udp' type='host'/></transport></content></jingle></iq>"

    :ok = :gen_tcp.send(andi, transport)
    assert recv_until(budi, "transport-info") =~ "foundation='def456'"
    iq_result(budi, "j3", b_jid, a_jid)

    terminate =
      "<iq type='set' id='j4' to='#{a_jid}'><jingle xmlns='urn:xmpp:jingle:1' action='session-terminate' sid='#{sid}'><reason><success/></reason></jingle></iq>"

    :ok = :gen_tcp.send(budi, terminate)
    assert recv_until(andi, "session-terminate") =~ sid
    assert {:error, :not_found} = Jingle.get_session("localhost", sid)
    iq_result(andi, "j4", a_jid, b_jid)

    :gen_tcp.close(andi)
    :gen_tcp.close(budi)
  end

  test "jingle errors: unknown session and unknown action", %{users: users} do
    andi = connect()
    budi = connect()
    login(andi, users.andi, "secret", "m1")
    login(budi, users.budi, "secret", "m1")
    _ = recv_any(andi)
    _ = recv_any(budi)

    b_jid = "#{users.budi}@localhost/m1"

    :ok =
      :gen_tcp.send(
        andi,
        "<iq type='set' id='e1' to='#{b_jid}'><jingle xmlns='urn:xmpp:jingle:1' action='transport-info' sid='no-such-session'><content creator='initiator' name='audio'/></jingle></iq>"
      )

    r = recv_until(andi, "e1")
    assert r =~ "unknown-session", "expected unknown-session: #{r}"
    assert r =~ "item-not-found"

    :ok =
      :gen_tcp.send(
        andi,
        "<iq type='set' id='e2' to='#{b_jid}'><jingle xmlns='urn:xmpp:jingle:1' action='session-bogus' sid='x'><content creator='initiator' name='audio'/></jingle></iq>"
      )

    r2 = recv_until(andi, "e2")
    assert r2 =~ "feature-not-implemented", "expected feature-not-implemented: #{r2}"

    :gen_tcp.close(andi)
    :gen_tcp.close(budi)
  end

  test "extdisco advertises stun and turn with credentials", %{users: users} do
    sock = connect()
    login(sock, users.andi, "secret", "m1")
    _ = recv_any(sock)

    r =
      send_recv(
        sock,
        "<iq type='get' id='x1' to='localhost'><services xmlns='urn:xmpp:extdisco:2'/></iq>",
        "x1"
      )

    assert r =~ "type='stun'", "no stun service: #{r}"
    assert r =~ "type='turn'", "no turn service: #{r}"
    assert r =~ "port='5478'"
    assert r =~ "username='", "no turn credentials: #{r}"
    assert r =~ "#{users.andi}@localhost", "credential username is not user-bound: #{r}"

    d =
      send_recv(
        sock,
        "<iq type='get' id='x2' to='localhost'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>",
        "x2"
      )

    assert d =~ "urn:xmpp:jingle:1"
    assert d =~ "urn:xmpp:extdisco:2"
    :gen_tcp.close(sock)
  end

  # --- OMEMO over PEP ---

  test "omemo devicelist and bundle publish/fetch, per-user isolation", %{users: users} do
    alice = connect()
    bob = connect()
    carol = connect()
    login(alice, users.andi, "secret", "m1")
    login(bob, users.budi, "secret", "m1")
    login(carol, users.carol, "secret", "m1")
    _ = recv_any(alice)
    _ = recv_any(bob)
    _ = recv_any(carol)

    a_bare = "#{users.andi}@localhost"
    b_bare = "#{users.budi}@localhost"
    c_bare = "#{users.carol}@localhost"

    devicelist = fn devices ->
      inner = Enum.map_join(devices, "", fn id -> "<device id='#{id}'/>" end)

      "<list xmlns='eu.siacs.conversations.axolotl'>#{inner}</list>"
    end

    bundle =
      "<bundle xmlns='eu.siacs.conversations.axolotl'><signedPreKeyPublic signedPreKeyId='1'>QUJDREVGR0g=</signedPreKeyPublic><signedPreKeySignature>U0lHTkFUVVJF</signedPreKeySignature><identityKey>SURFTlRJVFlLRVk=</identityKey><prekeys><preKeyPublic preKeyId='1'>UFJFS0VZMQ==</preKeyPublic><preKeyPublic preKeyId='2'>UFJFS0VZMg==</preKeyPublic></prekeys></bundle>"

    # Alice announces two devices + her bundle for 31415.
    r =
      send_recv(
        alice,
        "<iq type='set' id='o1' to='#{a_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='eu.siacs.conversations.axolotl.devicelist'><item id='current'>#{devicelist.([31_415, 27_182])}</item></publish></pubsub></iq>",
        "o1"
      )

    assert r =~ "type='result'", "devicelist publish failed: #{r}"

    r =
      send_recv(
        alice,
        "<iq type='set' id='o2' to='#{a_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='eu.siacs.conversations.axolotl.bundles:31415'><item id='31415'>#{bundle}</item></publish></pubsub></iq>",
        "o2"
      )

    assert r =~ "type='result'", "bundle publish failed: #{r}"

    # Bob fetches both from Alice's bare JID — byte-identical payload.
    r =
      send_recv(
        bob,
        "<iq type='get' id='o3' to='#{a_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='eu.siacs.conversations.axolotl.devicelist'/></pubsub></iq>",
        "o3"
      )

    assert r =~ "device id='31415'", "devicelist fetch: #{r}"
    assert r =~ "device id='27182'"

    r =
      send_recv(
        bob,
        "<iq type='get' id='o4' to='#{a_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='eu.siacs.conversations.axolotl.bundles:31415'/></pubsub></iq>",
        "o4"
      )

    assert r =~ "signedPreKeyPublic", "bundle fetch: #{r}"
    assert r =~ "QUJDREVGR0g="
    assert r =~ "UFJFS0VZMg=="

    # Republish replaces the list (max_items 1): only the new device stays.
    r =
      send_recv(
        alice,
        "<iq type='set' id='o5' to='#{a_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='eu.siacs.conversations.axolotl.devicelist'><item id='current'>#{devicelist.([999])}</item></publish></pubsub></iq>",
        "o5"
      )

    assert r =~ "type='result'"

    r =
      send_recv(
        bob,
        "<iq type='get' id='o6' to='#{a_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='eu.siacs.conversations.axolotl.devicelist'/></pubsub></iq>",
        "o6"
      )

    assert r =~ "device id='999'"
    refute r =~ "device id='31415'"

    # Per-user isolation: Carol's list is hers alone.
    r =
      send_recv(
        carol,
        "<iq type='set' id='o7' to='#{c_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='eu.siacs.conversations.axolotl.devicelist'><item id='current'>#{devicelist.([555])}</item></publish></pubsub></iq>",
        "o7"
      )

    assert r =~ "type='result'"

    r =
      send_recv(
        bob,
        "<iq type='get' id='o8' to='#{c_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='eu.siacs.conversations.axolotl.devicelist'/></pubsub></iq>",
        "o8"
      )

    assert r =~ "device id='555'"
    refute r =~ "device id='999'"

    # A non-owner may not publish to someone else's PEP nodes.
    r =
      send_recv(
        bob,
        "<iq type='set' id='o9' to='#{a_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='eu.siacs.conversations.axolotl.devicelist'><item id='current'>#{devicelist.([1])}</item></publish></pubsub></iq>",
        "o9"
      )

    assert r =~ "forbidden", "non-owner publish should be forbidden: #{r}"

    # Disco on the bare JID lists the PEP nodes and advertises OMEMO.
    r =
      send_recv(
        bob,
        "<iq type='get' id='o10' to='#{a_bare}'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>",
        "o10"
      )

    assert r =~ "eu.siacs.conversations.axolotl.devicelist", "disco#items: #{r}"
    assert r =~ "eu.siacs.conversations.axolotl.bundles:31415"

    r =
      send_recv(
        bob,
        "<iq type='get' id='o11' to='#{a_bare}'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>",
        "o11"
      )

    assert r =~ "urn:xmpp:omemo:0", "disco#info should advertise omemo: #{r}"

    # Unknown bundle node is item-not-found, not a crash.
    r =
      send_recv(
        bob,
        "<iq type='get' id='o12' to='#{b_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='eu.siacs.conversations.axolotl.bundles:1'/></pubsub></iq>",
        "o12"
      )

    assert r =~ "item-not-found", "unknown bundle node: #{r}"

    :gen_tcp.close(alice)
    :gen_tcp.close(bob)
    :gen_tcp.close(carol)
  end

  test "omemo devicelist subscription notifies on republish", %{users: users} do
    alice = connect()
    bob = connect()
    login(alice, users.andi, "secret", "m1")
    login(bob, users.budi, "secret", "m1")
    _ = recv_any(alice)
    _ = recv_any(bob)

    a_bare = "#{users.andi}@localhost"
    b_bare = "#{users.budi}@localhost"

    # Alice publishes first (auto-creates the node); subscribing
    # to a node that does not exist yet is item-not-found per
    # XEP-0060, so the subscribe comes after the first publish.
    r =
      send_recv(
        alice,
        "<iq type='set' id='s0' to='#{a_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='eu.siacs.conversations.axolotl.devicelist'><item id='current'><list xmlns='eu.siacs.conversations.axolotl'><device id='1111'/></list></item></publish></pubsub></iq>",
        "s0"
      )

    assert r =~ "type='result'", "first publish failed: #{r}"

    r =
      send_recv(
        bob,
        "<iq type='set' id='s1' to='#{a_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><subscribe node='eu.siacs.conversations.axolotl.devicelist' jid='#{b_bare}'/></pubsub></iq>",
        "s1"
      )

    assert r =~ "subscription", "subscribe failed: #{r}"

    # Alice publishes; Bob must get a headline notification from
    # Alice's bare JID with the new list.
    :ok =
      :gen_tcp.send(
        alice,
        "<iq type='set' id='s2' to='#{a_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='eu.siacs.conversations.axolotl.devicelist'><item id='current'><list xmlns='eu.siacs.conversations.axolotl'><device id='4242'/></list></item></publish></pubsub></iq>"
      )

    assert recv_until(alice, "s2") =~ "type='result'"
    note = recv_until(bob, "device id='4242'")
    assert note =~ "eu.siacs.conversations.axolotl.devicelist", "no PEP notification: #{note}"
    assert note =~ "from='#{a_bare}'", "notification must come from the bare JID: #{note}"

    :gen_tcp.close(alice)
    :gen_tcp.close(bob)
  end

  # --- STUN / TURN (live, raw UDP + TCP) ---

  # The sandbox blocks UDP sendto with EPERM (proven by a minimal
  # Python repro: `socket.sendto` to 127.0.0.1 fails with
  # `PermissionError`). Where UDP works these tests run for real;
  # where it does not they are skipped loudly instead of failing
  # on the environment. The same server/allocation logic is covered
  # in-process below (synthetic `{:udp, ...}` messages and an
  # Allocation with `server: self()`), and the saved probe
  # `test_stun_turn_phase5.py` runs the wire version wherever UDP
  # is allowed.
  defp udp_available? do
    {:ok, a} = :gen_udp.open(0, [:binary, active: false])
    {:ok, b} = :gen_udp.open(0, [:binary, active: false])
    {:ok, {_, port}} = :inet.sockname(b)
    result = :gen_udp.send(a, {127, 0, 0, 1}, port, "probe")
    :gen_udp.close(a)
    :gen_udp.close(b)
    result == :ok
  end

  defp udp_open do
    {:ok, sock} = :gen_udp.open(0, [:binary, active: false])
    {:ok, {_ip, port}} = :inet.sockname(sock)
    {sock, port}
  end

  defp stun_request(type, tid, attrs, opts \\ []) do
    StunTurn.encode(%{type: type, transaction_id: tid, attrs: attrs}, opts)
  end

  defp udp_roundtrip(sock, data, timeout \\ 3_000) do
    :ok = :gen_udp.send(sock, {127, 0, 0, 1}, @stun_port, data)

    case :gen_udp.recv(sock, 0, timeout) do
      {:ok, {_ip, _port, packet}} -> {:ok, packet}
      {:error, reason} -> {:error, reason}
    end
  end

  defp turn_allocate(sock, username, password, realm) do
    # First attempt: no credentials -> 401 with REALM + NONCE.
    tid = StunTurn.new_transaction_id()

    req =
      stun_request(StunTurn.allocate_request(), tid, [
        {StunTurn.attr_requested_transport(), 17}
      ])

    assert {:ok, raw} = udp_roundtrip(sock, req)
    assert {:ok, err} = StunTurn.decode(raw)
    assert StunTurn.attr(err, StunTurn.attr_error_code()) |> elem(0) == 401
    nonce = StunTurn.attr(err, StunTurn.attr_nonce())
    assert is_binary(nonce) and nonce != ""

    # Second attempt: long-term credentials + fingerprint.
    key = StunTurn.long_term_key(username, realm, password)
    tid2 = StunTurn.new_transaction_id()

    req2 =
      stun_request(
        StunTurn.allocate_request(),
        tid2,
        [
          {StunTurn.attr_username(), username},
          {StunTurn.attr_realm(), realm},
          {StunTurn.attr_nonce(), nonce},
          {StunTurn.attr_requested_transport(), 17},
          {StunTurn.attr_lifetime(), 600}
        ],
        integrity_key: key,
        fingerprint: true
      )

    assert {:ok, raw2} = udp_roundtrip(sock, req2)
    assert {:ok, ok} = StunTurn.decode(raw2)
    assert ok.type == 0x0103, "allocate failed: #{inspect(ok)}"
    assert StunTurn.verify_integrity(raw2, key) == :ok
    assert StunTurn.verify_fingerprint(raw2) == :ok

    relay = StunTurn.address_attr(ok, StunTurn.attr_xor_relayed_address())
    assert match?({:ipv4, {127, 0, 0, 1}, _}, relay)
    assert StunTurn.attr(ok, StunTurn.attr_lifetime()) == 600
    {relay, key, nonce}
  end

  # Build an authenticated TURN request. `attrs_fn` receives the
  # message transaction id so XOR address attributes are encoded
  # with the same tid the server decodes them with.
  defp turn_request(sock, type, username, realm, key, nonce, attrs_fn) do
    tid = StunTurn.new_transaction_id()

    req =
      stun_request(
        type,
        tid,
        [
          {StunTurn.attr_username(), username},
          {StunTurn.attr_realm(), realm},
          {StunTurn.attr_nonce(), nonce}
        ] ++ attrs_fn.(tid),
        integrity_key: key,
        fingerprint: true
      )

    assert {:ok, raw} = udp_roundtrip(sock, req)
    assert {:ok, msg} = StunTurn.decode(raw)
    {raw, msg}
  end

  # Read one complete STUN/ChannelData frame from a TCP socket.
  defp tcp_recv_frame(sock, acc \\ "") do
    case try_frame(acc) do
      {:ok, frame, _rest} ->
        {:ok, frame}

      :incomplete ->
        case :gen_tcp.recv(sock, 0, 3_000) do
          {:ok, data} -> tcp_recv_frame(sock, acc <> data)
          {:error, reason} -> {:error, reason}
        end
    end
  end

  defp try_frame(<<first::16, len::16, _::binary>> = bin) when byte_size(bin) >= 4 do
    cond do
      first >= 0x4000 and first <= 0x7FFF ->
        padded = len + rem(4 - rem(len, 4), 4)

        if byte_size(bin) >= 4 + padded do
          <<frame::binary-size(4 + padded), rest::binary>> = bin
          {:ok, frame, rest}
        else
          :incomplete
        end

      first < 0x4000 ->
        if byte_size(bin) >= 20 + len do
          <<frame::binary-size(20 + len), rest::binary>> = bin
          {:ok, frame, rest}
        else
          :incomplete
        end

      true ->
        :incomplete
    end
  end

  defp try_frame(_), do: :incomplete

  test "stun binding returns the caller's xor-mapped address" do
    if udp_available?() do
      {sock, port} = udp_open()
      tid = StunTurn.new_transaction_id()
      assert {:ok, raw} = udp_roundtrip(sock, stun_request(StunTurn.binding_request(), tid, []))
      assert {:ok, msg} = StunTurn.decode(raw)
      assert msg.type == StunTurn.binding_success()

      assert StunTurn.address_attr(msg, StunTurn.attr_xor_mapped_address()) ==
               {:ipv4, {127, 0, 0, 1}, port}

      :gen_udp.close(sock)
    else
      Logger.warning("UDP send blocked (EPERM) here — live STUN binding test skipped")
    end
  end

  test "turn allocate/permission/send/channel/refresh/delete over UDP", %{users: users} do
    if udp_available?() do
      bare = "#{users.andi}@localhost"
      cred = Jingle.turn_credential("localhost", bare)
      realm = "localhost"

      {sock, _port} = udp_open()
      {relay, key, nonce} = turn_allocate(sock, cred.username, cred.password, realm)
      {:ipv4, relay_ip, relay_port} = relay

      # Wrong password must fail with 401.
      bad_key = StunTurn.long_term_key(cred.username, realm, "wrong-password")
      tid = StunTurn.new_transaction_id()

      bad =
        stun_request(
          StunTurn.allocate_request(),
          tid,
          [
            {StunTurn.attr_username(), cred.username},
            {StunTurn.attr_realm(), realm},
            {StunTurn.attr_nonce(), nonce},
            {StunTurn.attr_requested_transport(), 17}
          ],
          integrity_key: bad_key
        )

      assert {:ok, raw} = udp_roundtrip(sock, bad)
      assert {:ok, err} = StunTurn.decode(raw)
      assert StunTurn.attr(err, StunTurn.attr_error_code()) |> elem(0) == 401

      # A peer socket that the relay will talk to.
      {:ok, peer} = :gen_udp.open(0, [:binary, active: false])
      {:ok, {_, peer_port}} = :inet.sockname(peer)
      peer_addr = {:ipv4, {127, 0, 0, 1}, peer_port}

      # CreatePermission for the peer.
      {_raw, msg} =
        turn_request(
          sock,
          StunTurn.create_permission_request(),
          cred.username,
          realm,
          key,
          nonce,
          fn tid ->
            [{StunTurn.attr_xor_peer_address(), {:xor, peer_addr, tid}}]
          end
        )

      assert msg.type == 0x0108, "create-permission failed: #{inspect(msg)}"

      # Send indication: relay forwards the data to the peer.
      send_tid = StunTurn.new_transaction_id()

      send_req =
        stun_request(StunTurn.send_indication(), send_tid, [
          {StunTurn.attr_xor_peer_address(), {:xor, peer_addr, send_tid}},
          {StunTurn.attr_data(), "hello-relay"}
        ])

      # Send indication: no reply expected; the relay forwards the
      # data to the peer.
      :ok = :gen_udp.send(sock, {127, 0, 0, 1}, @stun_port, send_req)

      assert {:ok, {{127, 0, 0, 1}, ^relay_port, "hello-relay"}} =
               :gen_udp.recv(peer, 0, 3_000)

      # Peer replies to the relay address: client gets a Data indication.
      :ok = :gen_udp.send(peer, relay_ip, relay_port, "hello-back")
      assert {:ok, {_ip, _port, indication}} = :gen_udp.recv(sock, 0, 3_000)
      assert {:ok, ind} = StunTurn.decode(indication)
      assert ind.type == StunTurn.data_indication()
      assert StunTurn.attr(ind, StunTurn.attr_data()) == "hello-back"
      assert StunTurn.address_attr(ind, StunTurn.attr_xor_peer_address()) == peer_addr

      # ChannelBind, then ChannelData both ways.
      {_raw, msg} =
        turn_request(
          sock,
          StunTurn.channel_bind_request(),
          cred.username,
          realm,
          key,
          nonce,
          fn tid ->
            [
              {StunTurn.attr_channel_number(), 0x4000},
              {StunTurn.attr_xor_peer_address(), {:xor, peer_addr, tid}}
            ]
          end
        )

      assert msg.type == 0x0109, "channel-bind failed: #{inspect(msg)}"

      :ok =
        :gen_udp.send(
          sock,
          {127, 0, 0, 1},
          @stun_port,
          StunTurn.encode_channel_data(0x4000, "chan-data")
        )

      assert {:ok, {{127, 0, 0, 1}, ^relay_port, "chan-data"}} = :gen_udp.recv(peer, 0, 3_000)

      :ok = :gen_udp.send(peer, relay_ip, relay_port, "chan-back")
      assert {:ok, {_ip, _port, frame}} = :gen_udp.recv(sock, 0, 3_000)
      assert {:ok, 0x4000, "chan-back", ""} = StunTurn.decode_channel_data(frame)

      # Refresh extends, Refresh with lifetime 0 deletes.
      {_raw, msg} =
        turn_request(
          sock,
          StunTurn.refresh_request(),
          cred.username,
          realm,
          key,
          nonce,
          fn _tid ->
            [{StunTurn.attr_lifetime(), 600}]
          end
        )

      assert msg.type == 0x0104
      assert StunTurn.attr(msg, StunTurn.attr_lifetime()) == 600

      {_raw, msg} =
        turn_request(
          sock,
          StunTurn.refresh_request(),
          cred.username,
          realm,
          key,
          nonce,
          fn _tid ->
            [{StunTurn.attr_lifetime(), 0}]
          end
        )

      assert msg.type == 0x0104
      assert StunTurn.attr(msg, StunTurn.attr_lifetime()) == 0
      Process.sleep(100)
      assert Exjabberd.StunTurn.Server.list_allocations() == []

      :gen_udp.close(peer)
      :gen_udp.close(sock)
    else
      Logger.warning("UDP send blocked (EPERM) here — live TURN-over-UDP test skipped")
    end
  end

  test "turn allocate over TCP", %{users: users} do
    bare = "#{users.andi}@localhost"
    cred = Jingle.turn_credential("localhost", bare)
    realm = "localhost"

    {:ok, sock} =
      :gen_tcp.connect({127, 0, 0, 1}, @stun_port, [:binary, packet: 0, active: false], 5_000)

    # No credentials -> 401 with REALM + NONCE.
    tid = StunTurn.new_transaction_id()

    :ok =
      :gen_tcp.send(
        sock,
        stun_request(StunTurn.allocate_request(), tid, [{StunTurn.attr_requested_transport(), 17}])
      )

    assert {:ok, raw} = tcp_recv_frame(sock)
    assert {:ok, err} = StunTurn.decode(raw)
    assert StunTurn.attr(err, StunTurn.attr_error_code()) |> elem(0) == 401
    nonce = StunTurn.attr(err, StunTurn.attr_nonce())

    key = StunTurn.long_term_key(cred.username, realm, cred.password)
    tid2 = StunTurn.new_transaction_id()

    req =
      stun_request(
        StunTurn.allocate_request(),
        tid2,
        [
          {StunTurn.attr_username(), cred.username},
          {StunTurn.attr_realm(), realm},
          {StunTurn.attr_nonce(), nonce},
          {StunTurn.attr_requested_transport(), 17},
          {StunTurn.attr_lifetime(), 600}
        ],
        integrity_key: key,
        fingerprint: true
      )

    :ok = :gen_tcp.send(sock, req)
    assert {:ok, raw2} = tcp_recv_frame(sock)
    assert {:ok, ok} = StunTurn.decode(raw2)
    assert ok.type == 0x0103, "TCP allocate failed: #{inspect(ok)}"

    assert match?(
             {:ipv4, {127, 0, 0, 1}, _},
             StunTurn.address_attr(ok, StunTurn.attr_xor_relayed_address())
           )

    # Closing the TCP connection drops the allocation.
    :gen_tcp.close(sock)
    Process.sleep(200)
    assert Exjabberd.StunTurn.Server.list_allocations() == []
  end

  # --- in-process TURN logic (no UDP syscalls) ---

  # The server's UDP dispatch/auth/allocate/permission/refresh
  # logic, driven with synthetic `{:udp, ...}` messages. The only
  # part this cannot observe is the socket write itself (dropped
  # by the sandbox's UDP block); the wire version of the same flow
  # is the guarded test above + `test_stun_turn_phase5.py`.
  test "turn server logic over synthetic udp messages" do
    server = Process.whereis(Exjabberd.StunTurn.Server)
    assert server != nil
    udp_socket = :sys.get_state(server).udp_socket
    secret = Exjabberd.Config.turn_secret()
    ip = {127, 0, 0, 1}
    port = 40_001
    client_key = {:udp, ip, port}
    username = "1234:alice@localhost"
    password = StunTurn.turn_password(username, secret)
    key = StunTurn.long_term_key(username, "localhost", password)

    authed = fn type, tid, extra_attrs ->
      StunTurn.encode(
        %{
          type: type,
          transaction_id: tid,
          attrs:
            [
              {StunTurn.attr_username(), username},
              {StunTurn.attr_realm(), "localhost"},
              {StunTurn.attr_nonce(), StunTurn.make_nonce(secret)}
            ] ++ extra_attrs
        },
        integrity_key: key,
        fingerprint: true
      )
    end

    # Unauthenticated Allocate: no allocation is created.
    tid = StunTurn.new_transaction_id()

    req =
      StunTurn.encode(%{
        type: StunTurn.allocate_request(),
        transaction_id: tid,
        attrs: [{StunTurn.attr_requested_transport(), 17}]
      })

    send(server, {:udp, udp_socket, ip, port, req})
    Process.sleep(200)
    assert Exjabberd.StunTurn.Server.list_allocations() == []

    # Authenticated Allocate: allocation appears with a reachable relay.
    req =
      authed.(StunTurn.allocate_request(), StunTurn.new_transaction_id(), [
        {StunTurn.attr_requested_transport(), 17},
        {StunTurn.attr_lifetime(), 600}
      ])

    send(server, {:udp, udp_socket, ip, port, req})
    Process.sleep(200)

    assert [{^client_key, {:ipv4, {127, 0, 0, 1}, relay_port}}] =
             Exjabberd.StunTurn.Server.list_allocations()

    assert is_integer(relay_port) and relay_port > 0

    pid = :sys.get_state(server).allocations[client_key]
    assert is_pid(pid)

    # Duplicate Allocate is an allocation mismatch: same allocation.
    req =
      authed.(StunTurn.allocate_request(), StunTurn.new_transaction_id(), [
        {StunTurn.attr_requested_transport(), 17}
      ])

    send(server, {:udp, udp_socket, ip, port, req})
    Process.sleep(200)

    assert [{^client_key, {:ipv4, {127, 0, 0, 1}, ^relay_port}}] =
             Exjabberd.StunTurn.Server.list_allocations()

    # CreatePermission for a peer, then the allocation accepts sends.
    peer = {127, 0, 0, 1}
    assert {:error, :no_permission} = Allocation.send_to_peer(pid, {peer, 9999}, "x")
    tid = StunTurn.new_transaction_id()

    req =
      authed.(StunTurn.create_permission_request(), tid, [
        {StunTurn.attr_xor_peer_address(), {:xor, {:ipv4, peer, 9999}, tid}}
      ])

    send(server, {:udp, udp_socket, ip, port, req})
    Process.sleep(200)
    assert :ok = Allocation.send_to_peer(pid, {peer, 9999}, "x")

    # Refresh with lifetime 0 deletes the allocation.
    req =
      authed.(StunTurn.refresh_request(), StunTurn.new_transaction_id(), [
        {StunTurn.attr_lifetime(), 0}
      ])

    send(server, {:udp, udp_socket, ip, port, req})
    Process.sleep(200)
    assert Exjabberd.StunTurn.Server.list_allocations() == []
  end

  test "allocation relays peer packets as data indication / channel data" do
    {:ok, pid} =
      Allocation.start_link(
        server: self(),
        client_key: {:udp, {127, 0, 0, 1}, 9999},
        bind_ip: {0, 0, 0, 0},
        advertise_ip: {127, 0, 0, 1},
        lifetime: 600
      )

    relay_socket = :sys.get_state(pid).relay_socket
    assert match?({:ipv4, {127, 0, 0, 1}, _}, Allocation.relay_addr(pid))

    peer = {127, 0, 0, 1}
    peer_port = 5555

    # No permission yet: the packet is dropped silently.
    send(pid, {:udp, relay_socket, peer, peer_port, "nope"})
    refute_receive {:relay_to_client, _, _}, 200

    :ok = Allocation.create_permission(pid, peer)
    send(pid, {:udp, relay_socket, peer, peer_port, "hello-back"})
    assert_receive {:relay_to_client, {:udp, {127, 0, 0, 1}, 9999}, datagram}, 1000
    assert {:ok, ind} = StunTurn.decode(datagram)
    assert ind.type == StunTurn.data_indication()
    assert StunTurn.attr(ind, StunTurn.attr_data()) == "hello-back"

    assert StunTurn.address_attr(ind, StunTurn.attr_xor_peer_address()) ==
             {:ipv4, peer, peer_port}

    # After a ChannelBind the same peer's packets become ChannelData.
    :ok = Allocation.channel_bind(pid, 0x4000, {peer, peer_port})
    send(pid, {:udp, relay_socket, peer, peer_port, "chan-back"})
    assert_receive {:relay_to_client, {:udp, {127, 0, 0, 1}, 9999}, frame}, 1000
    assert {:ok, 0x4000, "chan-back", ""} = StunTurn.decode_channel_data(frame)

    # Outbound permission / channel enforcement.
    assert {:error, :no_permission} = Allocation.send_to_peer(pid, {{127, 0, 0, 2}, 1}, "x")
    assert :ok = Allocation.send_to_peer(pid, {peer, peer_port}, "x")
    assert {:error, :no_channel} = Allocation.channel_data(pid, 0x4001, "x")
    assert :ok = Allocation.channel_data(pid, 0x4000, "x")

    assert {:ok, 300} = Allocation.refresh(pid, 300)
    ref = Process.monitor(pid)
    :ok = Allocation.delete(pid)
    assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 1000
  end
end
