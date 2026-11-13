#!/usr/bin/env python3
"""Raw-socket live test for MIX channels (Fase 14, XEP-0369 core:0):
service discovery, channel create/destroy, join with stable
participant JIDs, participants-node retrieval, anonymized message
reflection with <mix> nick/jid, setnick, leave, and the
non-participant / non-owner error paths.

Assumes a dev server on 127.0.0.1:5222. Users andi/budi/carol
(password "secret"). The channel name carries a per-run suffix.
"""
import socket, time, sys, re, os, subprocess, base64

HOST, PORT = "127.0.0.1", 5222
MIX = "mix.localhost"
MIX_NS = "urn:xmpp:mix:core:0"
RUN = str(int(time.time()))[-6:]
CHAN_NAME = f"mixchan-{RUN}"
CHAN = f"{CHAN_NAME}@{MIX}"
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
    r = subprocess.run(["elixir", "--sname", "probe14", "-e", code],
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

def join_mix(conn, iqid, nick):
    conn.send(f"<iq type='set' id='{iqid}' to='{CHAN}'><join xmlns='{MIX_NS}' id='j-{iqid}'>"
              f"<subscribe node='urn:xmpp:mix:nodes:messages'/>"
              f"<subscribe node='urn:xmpp:mix:nodes:participants'/>"
              f"<nick>{nick}</nick></join></iq>")
    return conn.recv_until(iqid)

try:
    ensure_users(["andi", "budi", "carol"])
    andi = Conn("andi"); budi = Conn("budi"); carol = Conn("carol")
    assert login(andi, "andi", "secret", "x14a"), "andi login"
    assert login(budi, "budi", "secret", "x14b"), "budi login"
    assert login(carol, "carol", "secret", "x14c"), "carol login"
    print("[SETUP] logins ok", flush=True)

    andi.send(f"<iq type='get' id='d1' to='{MIX}'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")
    r = andi.recv_until("d1")
    log("mix: service disco#info identity + core feature",
        "type='mix'" in r and MIX_NS in r, r[:300])

    andi.send(f"<iq type='set' id='k1' to='{MIX}'><create xmlns='{MIX_NS}' channel='{CHAN_NAME}'/></iq>")
    r = andi.recv_until("k1")
    log("mix: create channel", "type='result'" in r and f"channel='{CHAN}'" in r, r[:260])
    andi.send(f"<iq type='set' id='k2' to='{MIX}'><create xmlns='{MIX_NS}' channel='{CHAN_NAME}'/></iq>")
    r = andi.recv_until("k2")
    log("mix: duplicate create -> conflict", "conflict" in r, r[:220])

    andi.send(f"<iq type='get' id='d2' to='{MIX}'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")
    r = andi.recv_until("d2")
    log("mix: service disco#items lists channel", f"jid='{CHAN}'" in r, r[:280])

    r = join_mix(budi, "j1", "BudiNick")
    m = re.search(r"<jid>([^<]+)</jid>", r)
    budi_stable = m.group(1) if m else ""
    log("mix: budi join -> stable participant jid + nick",
        "type='result'" in r and budi_stable.endswith("@" + CHAN) and "<nick>BudiNick</nick>" in r
        and "urn:xmpp:mix:nodes:messages" in r, r[:340])
    r = join_mix(andi, "j2", "AndiNick")
    m = re.search(r"<jid>([^<]+)</jid>", r)
    andi_stable = m.group(1) if m else ""
    log("mix: andi join -> stable participant jid",
        andi_stable.endswith("@" + CHAN) and andi_stable != budi_stable, r[:300])

    budi.send(f"<iq type='get' id='p1' to='{CHAN}'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
              f"<items node='urn:xmpp:mix:nodes:participants'/></pubsub></iq>")
    r = budi.recv_until("p1")
    log("mix: participants node lists both with real jids + nicks",
        "andi@localhost" in r and "budi@localhost" in r and "AndiNick" in r and "BudiNick" in r,
        r[:380])

    andi.send(f"<message type='groupchat' to='{CHAN}'><body>halo-mix-{RUN}</body></message>")
    r = budi.recv_until(f"halo-mix-{RUN}")
    log("mix: message reflected to participant with stable from + <mix> nick/jid",
        f"halo-mix-{RUN}" in r and f"from='{andi_stable}'" in r
        and "<nick>AndiNick</nick>" in r and "<jid>andi@localhost</jid>" in r, r[:340])
    r = andi.recv_until(f"halo-mix-{RUN}")
    log("mix: sender gets own reflection", f"halo-mix-{RUN}" in r, r[:200])

    carol.send(f"<message type='groupchat' to='{CHAN}'><body>intrusi-{RUN}</body></message>")
    time.sleep(1.2)
    andi.send(f"<message type='groupchat' to='{CHAN}'><body>penanda-{RUN}</body></message>")
    r = budi.recv_until(f"penanda-{RUN}")
    log("mix: non-participant message not reflected",
        f"intrusi-{RUN}" not in r and f"penanda-{RUN}" in r, r[:260])

    budi.send(f"<iq type='set' id='n1' to='{CHAN}'><setnick xmlns='{MIX_NS}'><nick>BudiBaru</nick></setnick></iq>")
    r = budi.recv_until("n1")
    log("mix: setnick result", "type='result'" in r and "BudiBaru" in r, r[:240])
    budi.send(f"<message type='groupchat' to='{CHAN}'><body>nick-baru-{RUN}</body></message>")
    r = andi.recv_until(f"nick-baru-{RUN}")
    log("mix: reflection carries new nick", "<nick>BudiBaru</nick>" in r, r[:300])

    budi.send(f"<iq type='set' id='l1' to='{CHAN}'><leave xmlns='{MIX_NS}'/></iq>")
    r = budi.recv_until("l1")
    log("mix: leave result", "type='result'" in r, r[:200])
    andi.send(f"<iq type='get' id='p2' to='{CHAN}'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
              f"<items node='urn:xmpp:mix:nodes:participants'/></pubsub></iq>")
    r = andi.recv_until("p2")
    log("mix: participants after leave = only andi",
        "andi@localhost" in r and "budi@localhost" not in r, r[:300])

    carol.send(f"<iq type='set' id='k3' to='{MIX}'><destroy xmlns='{MIX_NS}' channel='{CHAN_NAME}'/></iq>")
    r = carol.recv_until("k3")
    log("mix: destroy by non-owner -> forbidden", "forbidden" in r, r[:220])
    andi.send(f"<iq type='set' id='k4' to='{MIX}'><destroy xmlns='{MIX_NS}' channel='{CHAN_NAME}'/></iq>")
    r = andi.recv_until("k4")
    log("mix: owner destroy ok", "type='result'" in r, r[:200])
    r = join_mix(budi, "j9", "BudiNick")
    log("mix: join destroyed channel -> item-not-found", "item-not-found" in r, r[:220])

    andi.close(); budi.close(); carol.close()
finally:
    passed = sum(1 for _, ok in results if ok)
    print(f"SUMMARY: {passed}/{len(results)} passed")
    sys.exit(0 if passed == len(results) and results else 1)
