#!/usr/bin/env python3
"""Raw-socket live probe for Fase 20 — item 64 long tail, the two
sub-features this round wire-verifies:

* XEP-0084 User Avatar over PEP: the `urn:xmpp:avatar:data` and
  `urn:xmpp:avatar:metadata` nodes are auto-created on first
  publish WITHOUT publish-options with open access (a contact with
  no presence subscription can fetch data + metadata), the account
  advertises `urn:xmpp:avatar:metadata` in bare-JID disco#info,
  subscribers get PEP notifications, an empty <metadata/> stops
  the avatar, and non-owners cannot publish.

* XEP-0357 Push Notifications: a client creates a node on the
  pubsub service (playing the app server), registers it with
  <enable/> to the server domain, goes offline; a chat message
  then makes the server publish a <notification/> item with the
  summary form (message-count, last-message-sender,
  last-message-body) to that node. <disable/> stops it, malformed
  <enable/> is a bad-request, and a no-store hint suppresses it.

Usage: start the server first (ELIXIR_ERL_OPTIONS="+fnu" elixir
--sname exjabberd -S mix run --no-halt), then:
python3 test_avatar_push_phase20.py

Users are created fresh per run via RPC. Records PASS/FAIL.
"""
import socket, time, sys, base64, subprocess, uuid, os

HOST, PORT = "127.0.0.1", 5222
RUN = uuid.uuid4().hex[:8]
results = []

def log(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail}")

def rpc_create(user):
    code = (
        f':rpc.call(:"exjabberd@{socket.gethostname()}", Exjabberd.Auth, '
        f':create_user, ["localhost", "{user}", "secret"]) |> IO.inspect()'
    )
    env = dict(os.environ)
    env["PATH"] = ("/home/hatch/workspace/.toolchain/otp-28.1/bin:"
                   "/home/hatch/workspace/.toolchain/elixir-1.19.7/bin:"
                   + env.get("PATH", ""))
    env["ELIXIR_ERL_OPTIONS"] = "+fnu"
    r = subprocess.run(
        ["elixir", "--sname", "probe", "-e", code],
        capture_output=True, text=True, timeout=60, env=env,
    )
    return ":ok" in (r.stdout + r.stderr)

STREAM = ("<?xml version='1.0'?><stream:stream to='localhost' "
          "xmlns='jabber:client' "
          "xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")

class Conn:
    def __init__(self, name):
        self.name = name
        self.s = socket.create_connection((HOST, PORT), timeout=10)
        self.s.settimeout(6)
        self.buf = b""

    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.s.sendall(data)

    def recv_until(self, needle, timeout=6):
        self.s.settimeout(timeout)
        end = time.time() + timeout
        while time.time() < end:
            if needle.encode() in self.buf:
                out, self.buf = self.buf, b""
                return out.decode(errors="replace")
            try:
                chunk = self.s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            self.buf += chunk
        out, self.buf = self.buf, b""
        return out.decode(errors="replace")

    def recv_any(self, timeout=1.5):
        self.s.settimeout(timeout)
        end = time.time() + timeout
        out = self.buf
        self.buf = b""
        while time.time() < end:
            try:
                chunk = self.s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk
        return out.decode(errors="replace")

    def drain(self, timeout=0.8):
        return self.recv_any(timeout)

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass

def login(c, user, resource="m1"):
    c.send(STREAM)
    r = c.recv_until("stream:features")
    assert "stream:features" in r, f"no features for {user}: {r[:200]}"
    b64 = base64.b64encode(f"\0{user}\0secret".encode()).decode()
    c.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{b64}</auth>")
    r = c.recv_until("success")
    assert "<success" in r, f"auth failed for {user}: {r[:200]}"
    c.send(STREAM)
    c.recv_until("stream:features")
    c.send(f"<iq type='set' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>{resource}</resource></bind></iq>")
    r = c.recv_until("bind")
    assert f"<jid>{user}@localhost/{resource}</jid>" in r, f"bind failed: {r[:200]}"

PUBSUB = "http://jabber.org/protocol/pubsub"
DATA_NODE = "urn:xmpp:avatar:data"
META_NODE = "urn:xmpp:avatar:metadata"
HASH1 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"
HASH2 = "2c26b46b68ffc68ff99b453c1d30413413422d70"

def publish(c, iq_id, to_bare, node, item_id, payload):
    c.send(
        f"<iq type='set' id='{iq_id}' to='{to_bare}'>"
        f"<pubsub xmlns='{PUBSUB}'><publish node='{node}'>"
        f"<item id='{item_id}'>{payload}</item></publish></pubsub></iq>")

def fetch(c, iq_id, to_bare, node, service=False):
    target = "pubsub.localhost" if service else to_bare
    c.send(
        f"<iq type='get' id='{iq_id}' to='{target}'>"
        f"<pubsub xmlns='{PUBSUB}'><items node='{node}'/></pubsub></iq>")
    return c.recv_until(iq_id)

def main():
    av = f"a20{RUN}"
    peer = f"b20{RUN}"
    pushu = f"p20{RUN}"
    sender = f"s20{RUN}"
    for u in (av, peer, pushu, sender):
        assert rpc_create(u), f"cannot create {u}"
    av_bare = f"{av}@localhost"
    push_bare = f"{pushu}@localhost"
    sender_bare = f"{sender}@localhost"

    A = Conn("av"); P = Conn("peer")
    login(A, av); login(P, peer)
    A.drain(); P.drain()

    # ---------- XEP-0084 avatars ----------
    # First publish has NO publish-options: the node must be
    # auto-created with the XEP-0084 config (open access).
    publish(A, "a1", av_bare, DATA_NODE, HASH1,
            f"<data xmlns='{DATA_NODE}' type='image/png'>QVZBUkRBVEE=</data>")
    r = A.recv_until("a1")
    log("avatar data publish (no options, auto-create)", "type='result'" in r, r[:200])

    r = fetch(P, "a2", av_bare, DATA_NODE)
    log("peer without subscription fetches avatar data (open access)",
        "QVZBUkRBVEE=" in r and HASH1 in r, r[:300])

    publish(A, "a3", av_bare, META_NODE, HASH1,
            f"<metadata xmlns='{META_NODE}'><info id='{HASH1}' type='image/png' "
            f"bytes='8' width='2' height='2'/></metadata>")
    r = A.recv_until("a3")
    log("avatar metadata publish", "type='result'" in r, r[:200])

    r = fetch(P, "a4", av_bare, META_NODE)
    log("peer fetches avatar metadata", HASH1 in r and "image/png" in r, r[:300])

    P.send(f"<iq type='get' id='a5' to='{av_bare}'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")
    r = P.recv_until("a5")
    log("disco#info advertises urn:xmpp:avatar:metadata",
        "urn:xmpp:avatar:metadata" in r, r[:300])

    # PEP notification for a new avatar while the peer is subscribed.
    P.send(f"<iq type='set' id='a6' to='{av_bare}'><pubsub xmlns='{PUBSUB}'><subscribe node='{META_NODE}' jid='{peer}@localhost'/></pubsub></iq>")
    r = P.recv_until("a6")
    log("peer subscribes to avatar metadata node", "subscription" in r, r[:250])
    publish(A, "a7", av_bare, DATA_NODE, HASH2,
            f"<data xmlns='{DATA_NODE}' type='image/png'>TkVXQVZBUg==</data>")
    A.recv_until("a7")
    publish(A, "a8", av_bare, META_NODE, HASH2,
            f"<metadata xmlns='{META_NODE}'><info id='{HASH2}' type='image/png' "
            f"bytes='8' width='2' height='2'/></metadata>")
    A.recv_until("a8")
    note = P.recv_until(HASH2)
    log("metadata republish notifies subscriber (PEP event)",
        META_NODE in note and f"from='{av_bare}'" in note, note[:300])

    r = fetch(P, "a9", av_bare, DATA_NODE)
    log("new avatar data fetchable by hash item id",
        "TkVXQVZBUg==" in r and HASH2 in r, r[:300])

    # Stop publishing: an empty <metadata/> item.
    publish(A, "a10", av_bare, META_NODE, "stop",
            f"<metadata xmlns='{META_NODE}'/>")
    A.recv_until("a10")
    r = fetch(P, "a11", av_bare, META_NODE)
    log("empty metadata stop item is stored",
        f"<metadata xmlns='{META_NODE}'/>" in r or f"<metadata xmlns=\"{META_NODE}\"/>" in r,
        r[:400])

    publish(P, "a12", av_bare, DATA_NODE, "deadbeef",
            f"<data xmlns='{DATA_NODE}' type='image/png'>RVZJTA==</data>")
    r = P.recv_until("a12")
    log("non-owner avatar publish -> forbidden", "forbidden" in r, r[:250])

    A.close(); P.close()

    # ---------- XEP-0357 push ----------
    node = f"push-{RUN}"
    U = Conn("push"); S = Conn("sender")
    login(U, pushu); login(S, sender)
    U.drain(); S.drain()

    # The app server side: a plain pubsub node owned by the user.
    U.send(f"<iq type='set' id='p1' to='pubsub.localhost'>"
           f"<pubsub xmlns='{PUBSUB}'><create node='{node}'/></pubsub></iq>")
    r = U.recv_until("p1")
    log("push service node created on pubsub service", "type='result'" in r, r[:200])

    U.send(f"<iq type='set' id='p2' to='localhost'>"
           f"<enable xmlns='urn:xmpp:push:0' jid='pubsub.localhost' node='{node}'/></iq>")
    r = U.recv_until("p2")
    log("push <enable/> accepted", "type='result'" in r, r[:200])

    U.send(f"<iq type='set' id='p3' to='localhost'>"
           f"<enable xmlns='urn:xmpp:push:0' jid='pubsub.localhost'/></iq>")
    r = U.recv_until("p3")
    log("malformed <enable/> (no node) -> bad-request", "bad-request" in r, r[:250])

    # Go offline; TWO chat messages in the SAME offline period must
    # trigger two notification publishes, with message-count 1 then
    # 2 (the count of messages waiting, XEP-0357 §4 — a login in
    # between would flush the queue and reset the count, so both
    # messages are sent before any reconnect).
    U.close()
    time.sleep(0.5)
    S.send(f"<message type='chat' id='m1' to='{push_bare}'><body>HaloPushSatu-{RUN}</body></message>")
    time.sleep(0.4)
    S.send(f"<message type='chat' id='m2' to='{push_bare}'><body>HaloPushDua-{RUN}</body></message>")
    time.sleep(0.7)

    U = Conn("push2")
    login(U, pushu)
    U.drain(1.2)
    r = fetch(U, "p4", None, node, service=True)
    log("offline messages published <notification/> items to the push node",
        r.count("<notification") == 2 and "urn:xmpp:push:0" in r, r[:500])
    log("summary forms: message-count 1 then 2, sender, bodies",
        "<field var='message-count'><value>1</value></field>" in r
        and "<field var='message-count'><value>2</value></field>" in r
        and sender_bare in r and f"HaloPushSatu-{RUN}" in r
        and f"HaloPushDua-{RUN}" in r, r[-700:])

    # Disable stops further notifications (message is still stored).
    U.send(f"<iq type='set' id='p6' to='localhost'>"
           f"<disable xmlns='urn:xmpp:push:0' jid='pubsub.localhost' node='{node}'/></iq>")
    r = U.recv_until("p6")
    log("push <disable/> accepted", "type='result'" in r, r[:200])
    U.close()
    time.sleep(0.5)
    S.send(f"<message type='chat' id='m3' to='{push_bare}'><body>HaloPushTiga-{RUN}</body></message>")
    time.sleep(0.7)
    U = Conn("push4")
    login(U, pushu)
    U.drain(1.2)
    r = fetch(U, "p7", None, node, service=True)
    log("after disable, no new notification",
        r.count("<notification") == 2, r[:500])

    # A no-store hint suppresses the notification.
    U.send(f"<iq type='set' id='p8' to='localhost'>"
           f"<enable xmlns='urn:xmpp:push:0' jid='pubsub.localhost' node='{node}'/></iq>")
    r = U.recv_until("p8")
    log("push re-enabled", "type='result'" in r, r[:200])
    U.close()
    time.sleep(0.5)
    S.send(f"<message type='chat' id='m4' to='{push_bare}'><body>JanganPush-{RUN}</body>"
           f"<no-store xmlns='urn:xmpp:hints'/></message>")
    time.sleep(0.7)
    U = Conn("push5")
    login(U, pushu)
    U.drain(1.2)
    r = fetch(U, "p9", None, node, service=True)
    log("no-store hint suppresses notification",
        r.count("<notification") == 2 and f"JanganPush-{RUN}" not in r, r[:500])

    U.close(); S.close()
    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main()
