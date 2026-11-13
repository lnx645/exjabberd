#!/usr/bin/env python3
"""Raw-socket live test for RFC 6121 roster subscriptions (Fase 11):
presence fan-out only to subscribed contacts, the subscribe /
subscribed / unsubscribe / unsubscribed state machine on both
roster items, presence replay on initial presence, denial clearing
`ask`, and server-generated unavailable presence on disconnect.

Assumes a dev server on 127.0.0.1:5222. Users andi/budi/carol/dave
(password "secret") are created via RPC when missing.
"""
import socket, time, sys, re, os, subprocess, base64

HOST, PORT = "127.0.0.1", 5222
results = []

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
    r = subprocess.run(["elixir", "--sname", "probe11", "-e", code],
                       capture_output=True, text=True, timeout=60, env=env)
    return ":ok" in (r.stdout + r.stderr)

def ensure_users(users):
    for u in users:
        ok = rpc_create(u)
        print(f"[SETUP] user {u}@localhost: {'ok' if ok else 'FAILED'}", flush=True)
        if not ok:
            print("SETUP FAILED: is the dev server running on 5222?", file=sys.stderr)
            sys.exit(2)

def log(name, ok, detail=""):
    results.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail[:220]}")

class Conn:
    def __init__(self, name):
        self.name = name
        self.s = socket.create_connection((HOST, PORT), timeout=10)
        self.s.settimeout(6)
        self.buf = b""
    def send(self, data):
        if isinstance(data, str): data = data.encode()
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
    def drain(self, timeout=0.7):
        self.recv_until("\x00NEVER\x00", timeout=timeout)
    def close(self):
        try: self.s.close()
        except Exception: pass

STREAM_OPEN = ("<?xml version='1.0'?><stream:stream to='localhost' "
               "xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")

def login(conn, user, pw, resource="test"):
    conn.send(STREAM_OPEN)
    conn.recv_until("stream:features")
    b64 = base64.b64encode(f"\0{user}\0{pw}".encode()).decode()
    conn.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{b64}</auth>")
    r = conn.recv_until("success")
    if "<success" not in r:
        return False
    conn.send(STREAM_OPEN)
    conn.recv_until("stream:features")
    conn.send(f"<iq type='set' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>{resource}</resource></bind></iq>")
    r = conn.recv_until("bind")
    return "<jid>" in r

def roster_item(conn, iqid, jid):
    """Roster get; return the <item ...> tag for jid or ''."""
    conn.send(f"<iq type='get' id='{iqid}'><query xmlns='jabber:iq:roster'/></iq>")
    r = conn.recv_until("</iq>")
    m = re.search(rf"<item[^>]*jid='{re.escape(jid)}'[^>]*/?>", r)
    return (m.group(0) if m else ""), r

def roster_remove(conn, iqid, jid):
    conn.send(f"<iq type='set' id='{iqid}'><query xmlns='jabber:iq:roster'>"
              f"<item jid='{jid}' subscription='remove'/></query></iq>")
    conn.recv_until("</iq>")

RUN = str(int(time.time()))[-6:]
def M(tag):
    return f"marker-{tag}-{RUN}"

try:
    ensure_users(["andi", "budi", "carol", "dave"])
    andi = Conn("andi"); budi = Conn("budi")
    assert login(andi, "andi", "secret", "sub1"), "andi login"
    assert login(budi, "budi", "secret", "sub2"), "budi login"
    print("[SETUP] logins ok", flush=True)

    # State independence: other probes in a verify run share this
    # server and may already have subscribed these users. Remove the
    # roster items this probe exercises so it starts from `none`.
    roster_remove(andi, "rm1", "budi@localhost")
    roster_remove(budi, "rm2", "andi@localhost")
    roster_remove(andi, "rm3", "carol@localhost")
    andi.drain(); budi.drain()

    # 1. No subscription: presence must NOT leak to a stranger.
    andi.send(f"<presence><status>{M('A0')}</status></presence>")
    r = budi.recv_until(M('A0'), timeout=3)
    log("subs: stranger receives no presence", M('A0') not in r, r[:160])

    # 2. subscribe: request delivered; ask=subscribe on requester item.
    andi.send("<presence type='subscribe' to='budi@localhost'/>")
    r = budi.recv_until("type='subscribe'", timeout=6)
    log("subs: subscribe request delivered to budi", "type='subscribe'" in r and "andi@localhost" in r, r[:200])
    item, _ = roster_item(andi, "rg1", "budi@localhost")
    log("subs: requester item none + ask=subscribe",
        "subscription='none'" in item and "ask='subscribe'" in item, item)
    item, _ = roster_item(budi, "rg2", "andi@localhost")
    log("subs: addressee item created as none", "subscription='none'" in item and "ask=" not in item, item)

    # 3. subscribed: states become to/from.
    budi.send("<presence type='subscribed' to='andi@localhost'/>")
    r = andi.recv_until("type='subscribed'", timeout=6)
    log("subs: subscribed delivered to andi", "type='subscribed'" in r, r[:200])
    item, _ = roster_item(andi, "rg3", "budi@localhost")
    log("subs: requester item -> to (ask cleared)",
        "subscription='to'" in item and "ask=" not in item, item)
    item, _ = roster_item(budi, "rg4", "andi@localhost")
    log("subs: approver item -> from", "subscription='from'" in item, item)

    # 4. One-way presence flow: budi -> andi yes, andi -> budi no.
    andi.drain(); budi.drain()
    budi.send(f"<presence><status>{M('B1')}</status></presence>")
    r = andi.recv_until(M('B1'), timeout=6)
    log("subs: subscribed contact's presence flows (budi->andi)", M('B1') in r, r[:200])
    andi.send(f"<presence><status>{M('A1')}</status></presence>")
    r = budi.recv_until(M('A1'), timeout=3)
    log("subs: reverse presence does not flow yet", M('A1') not in r, r[:160])

    # 5. Mutual subscription -> both/both, presence flows both ways.
    budi.send("<presence type='subscribe' to='andi@localhost'/>")
    andi.recv_until("type='subscribe'", timeout=6)
    andi.send("<presence type='subscribed' to='budi@localhost'/>")
    budi.recv_until("type='subscribed'", timeout=6)
    item, _ = roster_item(andi, "rg5", "budi@localhost")
    ok_a = "subscription='both'" in item
    item, _ = roster_item(budi, "rg6", "andi@localhost")
    ok_b = "subscription='both'" in item
    log("subs: mutual -> both/both", ok_a and ok_b, f"andi={ok_a} budi={ok_b}")
    andi.drain(); budi.drain()
    andi.send(f"<presence><status>{M('A2')}</status></presence>")
    r = budi.recv_until(M('A2'), timeout=6)
    log("subs: mutual presence flows (andi->budi)", M('A2') in r, r[:200])

    # 6. Initial-presence replay: carol subscribes to andi (approved),
    #    then her first presence gets andi's recorded presence back.
    carol = Conn("carol")
    assert login(carol, "carol", "secret", "sub3"), "carol login"
    roster_remove(carol, "rm4", "andi@localhost")
    roster_remove(carol, "rm5", "dave@localhost")
    carol.drain()
    carol.send("<presence type='subscribe' to='andi@localhost'/>")
    andi.recv_until("type='subscribe'", timeout=6)
    andi.send("<presence type='subscribed' to='carol@localhost'/>")
    carol.recv_until("type='subscribed'", timeout=6)
    carol.drain()
    carol.send("<presence/>")
    r = carol.recv_until(M('A2'), timeout=6)
    log("subs: initial presence replays contact's current presence", M('A2') in r, r[:240])

    # 7. unsubscribe: andi cancels own subscription to budi.
    andi.send("<presence type='unsubscribe' to='budi@localhost'/>")
    budi.recv_until("type='unsubscribe'", timeout=6)
    item, _ = roster_item(andi, "rg7", "budi@localhost")
    ok_a = "subscription='from'" in item
    item, _ = roster_item(budi, "rg8", "andi@localhost")
    ok_b = "subscription='to'" in item
    log("subs: unsubscribe -> from/to", ok_a and ok_b, f"andi={ok_a} budi={ok_b}")
    andi.drain(); budi.drain()
    budi.send(f"<presence><status>{M('B2')}</status></presence>")
    r = andi.recv_until(M('B2'), timeout=3)
    log("subs: after unsubscribe, budi's presence stops flowing to andi", M('B2') not in r, r[:160])
    andi.send(f"<presence><status>{M('A3')}</status></presence>")
    r = budi.recv_until(M('A3'), timeout=6)
    log("subs: andi's presence still flows to budi (from)", M('A3') in r, r[:200])

    # 8. Denial: dave refuses carol's request -> ask cleared.
    dave = Conn("dave")
    assert login(dave, "dave", "secret", "sub4"), "dave login"
    carol.send("<presence type='subscribe' to='dave@localhost'/>")
    dave.recv_until("type='subscribe'", timeout=6)
    dave.send("<presence type='unsubscribed' to='carol@localhost'/>")
    carol.recv_until("type='unsubscribed'", timeout=6)
    item, _ = roster_item(carol, "rg9", "dave@localhost")
    log("subs: denial clears ask, subscription stays none",
        "subscription='none'" in item and "ask=" not in item, item)
    dave.close(); carol.close()

    # 9. Disconnect -> server-generated unavailable for subscribers.
    andi.send("<presence type='subscribe' to='budi@localhost'/>")
    budi.recv_until("type='subscribe'", timeout=6)
    budi.send("<presence type='subscribed' to='andi@localhost'/>")
    andi.recv_until("type='subscribed'", timeout=6)
    budi.send(f"<presence><status>{M('B3')}</status></presence>")
    andi.recv_until(M('B3'), timeout=6)
    budi.close()
    r = andi.recv_until("unavailable", timeout=8)
    log("subs: abrupt disconnect -> unavailable presence to subscriber",
        "unavailable" in r and "budi@localhost" in r, r[:240])

    andi.close()
finally:
    passed = sum(1 for _, ok in results if ok)
    print(f"SUMMARY: {passed}/{len(results)} passed")
    sys.exit(0 if passed == len(results) and results else 1)
