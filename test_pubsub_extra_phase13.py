#!/usr/bin/env python3
"""Raw-socket live test for PubSub collections and the authorize
approval flow (Fase 13, XEP-0060 sections 6.5 and 15):

* create a collection node; disco#info reports type 'collection'
* create a leaf inside it (pubsub#collection); disco#items on the
  collection lists the leaf; publishing to the collection fails;
  items on the collection aggregate the leaf's items
* access_model=authorize: subscribe lands 'pending', the owner gets
  a subscribe_authorization form message, a non-owner reply is
  ignored, deny settles to 'none', approve settles to 'subscribed'
  and publish notifications start flowing

Assumes a dev server on 127.0.0.1:5222. Users andi/budi/carol
(password "secret"). Node names carry a per-run suffix.
"""
import socket, time, sys, re, os, subprocess, base64

HOST, PORT = "127.0.0.1", 5222
PS = "pubsub.localhost"
RUN = str(int(time.time()))[-6:]
COL = f"col-{RUN}"
LEAF = f"leaf-{RUN}"
AUTHZ = f"authz-{RUN}"
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
    r = subprocess.run(["elixir", "--sname", "probe13", "-e", code],
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
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail[:240]}", flush=True)

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

def create(conn, iqid, node, fields=None):
    cfg = ""
    if fields:
        body = "".join(
            f"<field var='{k}'>{''.join(f'<value>{v}</value>' for v in vs)}</field>"
            for k, vs in fields.items())
        cfg = (f"<configure><x xmlns='jabber:x:data' type='submit'>"
               f"<field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field>"
               f"{body}</x></configure>")
    conn.send(f"<iq type='set' id='{iqid}' to='{PS}'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
              f"<create node='{node}'>{cfg}</create></pubsub></iq>")
    return conn.recv_until(iqid)

def authz_reply(conn, node, subid, subscriber, allow):
    conn.send(
        f"<message to='{PS}'><x xmlns='jabber:x:data' type='submit'>"
        f"<field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#subscribe_authorization</value></field>"
        f"<field var='pubsub#node'><value>{node}</value></field>"
        f"<field var='pubsub#subscriber_jid'><value>{subscriber}</value></field>"
        f"<field var='pubsub#subid'><value>{subid}</value></field>"
        f"<field var='pubsub#allow'><value>{allow}</value></field>"
        f"</x></message>")

def subscribe(conn, iqid, node, jid):
    conn.send(f"<iq type='set' id='{iqid}' to='{PS}'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
              f"<subscribe node='{node}' jid='{jid}'/></pubsub></iq>")
    return conn.recv_until(iqid)

def subscriptions_state(conn, iqid, node):
    conn.send(f"<iq type='get' id='{iqid}' to='{PS}'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
              f"<subscriptions/></pubsub></iq>")
    return conn.recv_until(iqid)

try:
    ensure_users(["andi", "budi", "carol"])
    andi = Conn("andi"); budi = Conn("budi"); carol = Conn("carol")
    assert login(andi, "andi", "secret", "p13a"), "andi login"
    assert login(budi, "budi", "secret", "p13b"), "budi login"
    assert login(carol, "carol", "secret", "p13c"), "carol login"
    print("[SETUP] logins ok", flush=True)

    # --- collections ---
    r = create(andi, "c1", COL, {"pubsub#type": ["collection"]})
    log("pubsub: create collection node", "type='result'" in r, r[:200])
    andi.send(f"<iq type='get' id='c2' to='{PS}'><query xmlns='http://jabber.org/protocol/disco#info' node='{COL}'/></iq>")
    r = andi.recv_until("c2")
    log("pubsub: disco#info says collection",
        "type='collection'" in r and "category='pubsub'" in r, r[:300])
    r = create(andi, "c3", LEAF, {"pubsub#collection": [COL]})
    log("pubsub: create leaf in collection", "type='result'" in r, r[:200])
    andi.send(f"<iq type='get' id='c4' to='{PS}'><query xmlns='http://jabber.org/protocol/disco#items' node='{COL}'/></iq>")
    r = andi.recv_until("c4")
    log("pubsub: disco#items on collection lists leaf",
        f"node='{LEAF}'" in r, r[:300])
    andi.send(f"<iq type='set' id='c5' to='{PS}'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
              f"<publish node='{COL}'><item id='x1'><entry>nope</entry></item></publish></pubsub></iq>")
    r = andi.recv_until("c5")
    log("pubsub: publish to collection -> error", "type='error'" in r, r[:220])
    andi.send(f"<iq type='set' id='c6' to='{PS}'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
              f"<publish node='{LEAF}'><item id='li1'><entry>dalam-koleksi-{RUN}</entry></item></publish></pubsub></iq>")
    r = andi.recv_until("c6")
    andi.send(f"<iq type='get' id='c7' to='{PS}'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
              f"<items node='{COL}'/></pubsub></iq>")
    r2 = andi.recv_until("c7")
    log("pubsub: items on collection aggregate leaf items",
        "type='result'" in r and f"dalam-koleksi-{RUN}" in r2, r2[:300])

    # --- authorize flow ---
    r = create(andi, "a1", AUTHZ, {"pubsub#access_model": ["authorize"],
                                   "pubsub#publish_model": ["publishers"]})
    log("pubsub: create authorize node", "type='result'" in r, r[:200])
    r = subscribe(budi, "a2", AUTHZ, "budi@localhost")
    log("pubsub: subscribe to authorize node -> pending",
        "subscription='pending'" in r, r[:300])
    r = andi.recv_until("subscribe_authorization", timeout=8)
    m = re.search(r"var='pubsub#subid'><value>([^<]+)</value>", r)
    subid = m.group(1) if m else None
    log("pubsub: owner receives authorization request form",
        "subscribe_authorization" in r and subid is not None and AUTHZ in r, r[:340])

    # Non-owner approval is ignored.
    if subid:
        authz_reply(carol, AUTHZ, subid, "budi@localhost", "1")
        time.sleep(1.0)
        r = subscriptions_state(budi, "a3", AUTHZ)
        log("pubsub: non-owner approval ignored (still pending)",
            "subscription='pending'" in r, r[:280])
        # Owner denies.
        authz_reply(andi, AUTHZ, subid, "budi@localhost", "0")
        r = budi.recv_until("subscription='none'", timeout=8)
        log("pubsub: owner deny -> subscriber notified none",
            "subscription='none'" in r, r[:280])
        r = subscriptions_state(budi, "a4", AUTHZ)
        log("pubsub: denied subscription gone from list",
            AUTHZ not in r, r[:220])
    else:
        log("pubsub: non-owner approval ignored (still pending)", False, "no subid")
        log("pubsub: owner deny -> subscriber notified none", False, "no subid")
        log("pubsub: denied subscription gone from list", False, "no subid")

    # Second round: owner approves.
    r = subscribe(budi, "a5", AUTHZ, "budi@localhost")
    r2 = andi.recv_until("subscribe_authorization", timeout=8)
    m = re.search(r"var='pubsub#subid'><value>([^<]+)</value>", r2)
    subid2 = m.group(1) if m else None
    log("pubsub: second subscribe pending + form to owner",
        "subscription='pending'" in r and subid2 is not None and subid2 != subid, (r + r2)[:300])
    if subid2:
        authz_reply(andi, AUTHZ, subid2, "budi@localhost", "1")
        r = budi.recv_until("subscription='subscribed'", timeout=8)
        log("pubsub: owner approve -> subscriber notified subscribed",
            "subscription='subscribed'" in r, r[:300])
        r = subscriptions_state(budi, "a6", AUTHZ)
        log("pubsub: subscription list shows subscribed",
            "subscription='subscribed'" in r, r[:280])
        andi.send(f"<iq type='set' id='a7' to='{PS}'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
                  f"<publish node='{AUTHZ}'><item id='n1'><entry>disetujui-{RUN}</entry></item></publish></pubsub></iq>")
        andi.recv_until("a7")
        r = budi.recv_until(f"disetujui-{RUN}", timeout=8)
        log("pubsub: approved subscriber receives publish event",
            f"disetujui-{RUN}" in r, r[:280])
    else:
        log("pubsub: owner approve -> subscriber notified subscribed", False, "no subid2")
        log("pubsub: subscription list shows subscribed", False, "no subid2")
        log("pubsub: approved subscriber receives publish event", False, "no subid2")

    andi.close(); budi.close(); carol.close()
finally:
    passed = sum(1 for _, ok in results if ok)
    print(f"SUMMARY: {passed}/{len(results)} passed")
    sys.exit(0 if passed == len(results) and results else 1)
