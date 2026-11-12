#!/usr/bin/env python3
"""Raw-socket live probe for XEP-0198 (Stream Management), XEP-0280
(Message Carbons) and XEP-0352 (Client State Indication) against
exjabberd C2S on 127.0.0.1:5222.

Usage: start the server first (ELIXIR_ERL_OPTIONS="+fnu -sname
exjabberd" mix run --no-halt), then: python3 test_sm_carbons_csi.py
Test users (andi/budi/carol, password "secret") are created via RPC
when missing, so the probe works on a fresh clone too.

Records PASS/FAIL per check with wire transcript excerpts.
"""
import socket, time, sys, re, base64, os, subprocess

HOST, PORT = "127.0.0.1", 5222
results = []

def log(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail}")

def rpc_create(user):
    """Create a test account on the running node via RPC (idempotent:
    already-existing users report :ok too)."""
    code = (
        f':rpc.call(:"exjabberd@{socket.gethostname()}", Exjabberd.Auth, '
        f':create_user, ["localhost", "{user}", "secret"]) |> IO.inspect()'
    )
    env = dict(os.environ)
    env["PATH"] = ("/home/hatch/workspace/.toolchain/otp-28.1/bin:"
                   "/home/hatch/workspace/.toolchain/elixir-1.19.7/bin:"
                   + env.get("PATH", ""))
    env["ELIXIR_ERL_OPTIONS"] = "+fnu"
    r = subprocess.run(["elixir", "--sname", "probe", "-e", code],
                       capture_output=True, text=True, timeout=60, env=env)
    return ":ok" in (r.stdout + r.stderr)

def ensure_users(users):
    # Setup lines are printed, not counted in the SUMMARY: they are a
    # precondition, not a feature check. A failure here aborts loudly
    # instead of producing confusing auth failures below.
    for u in users:
        ok = rpc_create(u)
        print(f"[SETUP] user {u}@localhost: {'ok' if ok else 'FAILED'}", flush=True)
        if not ok:
            print("SETUP FAILED: is the dev server running on 5222?", file=sys.stderr)
            sys.exit(2)

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
        """Return whatever arrives within timeout ('' on timeout)."""
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

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass

STREAM_OPEN = ("<?xml version='1.0'?><stream:stream to='localhost' "
               "xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")

def login(conn, user, pw, resource):
    conn.send(STREAM_OPEN)
    r = conn.recv_until("stream:features")
    if "stream:features" not in r:
        return False, r
    b64 = base64.b64encode(f"\0{user}\0{pw}".encode()).decode()
    conn.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{b64}</auth>")
    r = conn.recv_until("success")
    if "<success" not in r:
        return False, r
    conn.send(STREAM_OPEN)
    r = conn.recv_until("stream:features")
    conn.send(f"<iq type='set' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>{resource}</resource></bind></iq>")
    r = conn.recv_until("bind")
    return (f"<jid>{user}@localhost/{resource}</jid>" in r), r

def features_of(conn):
    conn.send(STREAM_OPEN)
    return conn.recv_until("stream:features")

# ---------------------------------------------------------------- SM
smid = None
ensure_users(["andi", "budi", "carol"])
try:
    a = Conn("andi-sm")
    r = features_of(a)
    log("SM: <sm/> advertised pre-auth", "urn:xmpp:sm:3" in r, r[r.find("<stream:features>"):][:300])
    ok, _ = login(a, "andi", "secret", "sm1")
    log("SM: login andi/sm1", ok)

    # enable before bind -> failed (fresh connection, auth only)
    e = Conn("andi-early")
    e.send(STREAM_OPEN)
    e.recv_until("stream:features")
    b64 = base64.b64encode(b"\0andi\0secret").decode()
    e.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{b64}</auth>")
    e.recv_until("success")
    e.send("<enable xmlns='urn:xmpp:sm:3'/>")
    r = e.recv_until("failed", timeout=4)
    log("SM: enable before bind -> <failed/>", "<failed" in r and "unexpected-request" in r, r[:200])
    e.close()

    # enable with resume
    a.send("<enable xmlns='urn:xmpp:sm:3' resume='true'/>")
    r = a.recv_until("enabled")
    m = re.search(r"id='([^']+)'", r)
    smid = m.group(1) if m else None
    log("SM: enable -> <enabled id previd max resume/>",
        "<enabled" in r and smid is not None and "previd='" in r and "max='60'" in r and "resume='true'" in r,
        r[:250])

    # ack counting: roster IQ is stanza 1, message is stanza 2
    a.send("<iq type='get' id='roster1'><query xmlns='jabber:iq:roster'/></iq><r xmlns='urn:xmpp:sm:3'/>")
    r = a.recv_until("<a ", timeout=6)
    log("SM: <r/> after roster IQ -> <a h='1'/>", "<a xmlns='urn:xmpp:sm:3' h='1'/>" in r, r[:250])
    a.send("<message to='budi@localhost' type='chat' id='m1'><body>sm counting</body></message><r xmlns='urn:xmpp:sm:3'/>")
    r = a.recv_until("<a ", timeout=6)
    log("SM: <r/> after message -> <a h='2'/>", "h='2'" in r, r[:200])
    # andi has only RECEIVED 1 stanza so far (the roster result);
    # ack that, not 2.
    a.send("<a xmlns='urn:xmpp:sm:3' h='1'/>")
    time.sleep(0.3)

    # second enable -> failed, session stays alive
    a.send("<enable xmlns='urn:xmpp:sm:3'/>")
    r = a.recv_until("failed", timeout=4)
    log("SM: second <enable/> -> <failed/> (session survives)", "<failed" in r, r[:200])

    # budi online to feed andi stanzas
    b = Conn("budi-sm")
    ok, _ = login(b, "budi", "secret", "sm2")
    log("SM: login budi/sm2", ok)
    b.send("<message to='andi@localhost/sm1' type='chat' id='mB1'><body>pesan sebelum putus</body></message>")
    r = a.recv_until("pesan sebelum putus", timeout=6)
    log("SM: budi -> andi delivered pre-drop", "pesan sebelum putus" in r, r[:250])
    # andi deliberately does NOT ack (no <a/> for seq 3)

    # drop TCP without </stream:stream>
    a.close()
    time.sleep(1.0)
    # while detached: another message is queued server-side, never sent
    b.send("<message to='andi@localhost/sm1' type='chat' id='mB2'><body>pesan saat putus</body></message>")
    time.sleep(0.5)

    # resume with wrong previd -> failed, stream still usable
    w = Conn("andi-wrong")
    w.send(STREAM_OPEN)
    w.recv_until("stream:features")
    w.send("<resume xmlns='urn:xmpp:sm:3' h='0' previd='bogus-previd'/>")
    r = w.recv_until("failed", timeout=4)
    log("SM: resume wrong previd -> <failed/> item-not-found",
        "<failed" in r and "item-not-found" in r, r[:200])
    ok, _ = login(w, "andi", "secret", "sm-wrong")
    log("SM: stream usable after failed resume (fresh login works)", ok)
    w.close()

    # resume for real: andi handled 2 stanzas from the server
    # (roster result seq 1, budi M1 seq 2); M2 was queued as seq 3.
    a2 = Conn("andi-resume")
    a2.send(STREAM_OPEN)
    a2.recv_until("stream:features")
    a2.send(f"<resume xmlns='urn:xmpp:sm:3' h='2' previd='{smid}'/>")
    r = a2.recv_until("resumed", timeout=6)
    log("SM: resume -> <resumed h='2' previd/>",
        "<resumed" in r and "h='2'" in r and f"previd='{smid}'" in r, r[:250])
    r = a2.recv_until("pesan saat putus", timeout=6)
    log("SM: unacked stanza replayed on resume (M2, no dup of M1)",
        "pesan saat putus" in r and "pesan sebelum putus" not in r, r[:300])
    # post-resume traffic still works; in_h carried over (roster=1, msg=2 -> next=3? no:
    # andi sent roster IQ (in_h=1) + message m1 (in_h=2) before drop; now one more message -> 3)
    a2.send("<message to='budi@localhost/sm2' type='chat' id='mA2'><body>setelah resume</body></message><r xmlns='urn:xmpp:sm:3'/>")
    r = a2.recv_until("<a ", timeout=6)
    log("SM: post-resume <r/> -> <a h='3'/> (counters carried over)", "h='3'" in r, r[:200])
    r = b.recv_until("setelah resume", timeout=6)
    log("SM: post-resume message delivered to budi", "setelah resume" in r, r[:200])
    a2.close()
    b.close()
except Exception as ex:
    log("SM: probe crashed", False, repr(ex))

# ------------------------------------------------------------ Carbons
try:
    a1 = Conn("andi-c1")
    ok, _ = login(a1, "andi", "secret", "carb1")
    log("Carbons: login andi/carb1", ok)
    a2 = Conn("andi-c2")
    ok, _ = login(a2, "andi", "secret", "carb2")
    log("Carbons: login andi/carb2", ok)
    b = Conn("budi-c")
    ok, _ = login(b, "budi", "secret", "carb3")
    log("Carbons: login budi/carb3", ok)

    for c, rid in ((a1, "ce1"), (a2, "ce2")):
        c.send(f"<iq type='set' id='{rid}'><enable xmlns='urn:xmpp:carbons:2'/></iq>")
        r = c.recv_until(rid, timeout=6)
        log(f"Carbons: enable on {c.name} -> result", "type='result'" in r, r[:200])

    # outbound: a1 -> budi, a2 must get a <sent/> carbon
    a1.send("<message to='budi@localhost/carb3' type='chat' id='cm1'><body>halo dari carb1</body></message>")
    r = b.recv_until("halo dari carb1", timeout=6)
    log("Carbons: original reaches budi", "halo dari carb1" in r, r[:200])
    r = a2.recv_until("carbons:2", timeout=6)
    log("Carbons: other resource gets <sent/> carbon",
        "<sent" in r and "urn:xmpp:carbons:2" in r and "halo dari carb1" in r, r[:400])

    # inbound: budi -> a1, a2 must get a <received/> carbon
    b.send("<message to='andi@localhost/carb1' type='chat' id='cm2'><body>balasan budi</body></message>")
    r = a1.recv_until("balasan budi", timeout=6)
    log("Carbons: reply reaches a1", "balasan budi" in r, r[:200])
    r = a2.recv_until("carbons:2", timeout=6)
    log("Carbons: other resource gets <received/> carbon",
        "<received" in r and "balasan budi" in r, r[:400])

    # disable on a2 -> no more carbons
    a2.send("<iq type='set' id='cd1'><disable xmlns='urn:xmpp:carbons:2'/></iq>")
    r = a2.recv_until("cd1", timeout=6)
    log("Carbons: disable -> result", "type='result'" in r, r[:200])
    a1.send("<message to='budi@localhost/carb3' type='chat' id='cm3'><body>setelah disable</body></message>")
    b.recv_until("setelah disable", timeout=6)
    r = a2.recv_any(timeout=1.5)
    log("Carbons: disabled resource gets nothing", r == "", r[:200] or "(nothing)")

    # private hint -> no carbon (re-enable first)
    a2.send("<iq type='set' id='ce3'><enable xmlns='urn:xmpp:carbons:2'/></iq>")
    a2.recv_until("ce3", timeout=6)
    a1.send("<message to='budi@localhost/carb3' type='chat' id='cm4'><body>rahasia</body><private xmlns='urn:xmpp:carbons:2'/></message>")
    b.recv_until("rahasia", timeout=6)
    r = a2.recv_any(timeout=1.5)
    log("Carbons: <private/> message is not carboned", r == "", r[:200] or "(nothing)")

    # error message -> no carbon
    a1.send("<message to='budi@localhost/carb3' type='error' id='cm5'><body>error</body></message>")
    time.sleep(0.5)
    r = a2.recv_any(timeout=1.5)
    log("Carbons: type='error' message is not carboned", r == "", r[:200] or "(nothing)")
    a1.close(); a2.close(); b.close()
except Exception as ex:
    log("Carbons: probe crashed", False, repr(ex))

# ---------------------------------------------------------------- CSI
try:
    a = Conn("andi-csi")
    ok, _ = login(a, "andi", "secret", "csi1")
    log("CSI: login andi/csi1", ok)
    b = Conn("budi-csi")
    ok, _ = login(b, "budi", "secret", "csi2")
    log("CSI: login budi/csi2", ok)

    a.send("<inactive xmlns='urn:xmpp:csi:0'/>")
    time.sleep(0.5)
    b.send("<message to='andi@localhost/csi1' type='chat' id='csi-m1'><body>pesan ditahan</body></message>")
    r = a.recv_any(timeout=1.5)
    log("CSI: message held while inactive", r == "", r[:200] or "(nothing)")
    b.send("<presence/>")
    r = a.recv_any(timeout=1.5)
    log("CSI: presence held while inactive", r == "", r[:200] or "(nothing)")
    # IQ while inactive must still be answered immediately
    a.send("<iq type='get' id='csi-ping1' to='localhost'><ping xmlns='urn:xmpp:ping'/></iq>")
    r = a.recv_until("csi-ping1", timeout=6)
    log("CSI: ping answered immediately while inactive", "type='result'" in r, r[:200])
    # back to active -> flush in order (message first, then presence)
    a.send("<active xmlns='urn:xmpp:csi:0'/>")
    r = a.recv_until("pesan ditahan", timeout=6)
    log("CSI: queued message flushed on <active/>", "pesan ditahan" in r, r[:300])
    r = a.recv_until("presence", timeout=6)
    log("CSI: queued presence flushed on <active/>", "<presence" in r, r[:300])
    # normal traffic again
    b.send("<message to='andi@localhost/csi1' type='chat' id='csi-m2'><body>sesudah aktif</body></message>")
    r = a.recv_until("sesudah aktif", timeout=6)
    log("CSI: message flows immediately when active", "sesudah aktif" in r, r[:200])
    a.close(); b.close()
except Exception as ex:
    log("CSI: probe crashed", False, repr(ex))

passed = sum(1 for _, ok, _ in results if ok)
print(f"\nSUMMARY: {passed}/{len(results)} passed")
sys.exit(0 if passed == len(results) else 1)
