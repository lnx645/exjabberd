#!/usr/bin/env python3
"""Raw-socket live test against exjabberd C2S on 127.0.0.1:5222.
Records PASS/FAIL per check with wire transcript excerpts.
Usage: python3 exj-raw-test.py
"""
import socket, time, sys, re

HOST, PORT = "127.0.0.1", 5222
results = []

def log(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail}")

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
    r = conn.recv_until("stream:features")
    has_features = "stream:features" in r
    log(f"{conn.name}: stream open -> features", has_features, r[:400].replace("\n", " "))
    # SASL PLAIN: \0user\0pass
    import base64
    b64 = base64.b64encode(f"\0{user}\0{pw}".encode()).decode()
    conn.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{b64}</auth>")
    r2 = conn.recv_until("success")
    ok = "<success" in r2
    log(f"{conn.name}: SASL PLAIN {user}", ok, r2[:300].replace("\n", " "))
    if not ok:
        return False
    conn.send(STREAM_OPEN)
    r3 = conn.recv_until("stream:features")
    conn.send(f"<iq type='set' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>{resource}</resource></bind></iq>")
    r4 = conn.recv_until("bind")
    m = re.search(r"<jid>([^<]+)</jid>", r4)
    ok = m is not None
    log(f"{conn.name}: resource bind", ok, (m.group(1) if m else r4[:300]).replace("\n", " "))
    return ok

def iq_wait(conn, iq_xml, marker, timeout=6):
    conn.send(iq_xml)
    return conn.recv_until(marker, timeout=timeout)

try:
    andi = Conn("andi")
    budi = Conn("budi")
    ok_a = login(andi, "andi", "secret", "raw1")
    ok_b = login(budi, "budi", "secret", "raw2")

    if ok_a:
        # roster get
        r = iq_wait(andi, "<iq type='get' id='roster1'><query xmlns='jabber:iq:roster'/></iq>", "roster", timeout=6)
        log("andi: roster get IQ answered", "query" in r and "type='result'" in r, r[:300].replace("\n", " ") or "(no reply in 6s)")
        # disco info
        r = iq_wait(andi, "<iq type='get' id='disco1' to='localhost'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>", "query", timeout=6)
        log("andi: disco#info answered", "query" in r and "type='result'" in r, r[:300].replace("\n", " ") or "(no reply in 6s)")
        # ping
        r = iq_wait(andi, "<iq type='get' id='ping1' to='localhost'><ping xmlns='urn:xmpp:ping'/></iq>", "iq", timeout=6)
        log("andi: XEP-0199 ping answered", "type='result'" in r, r[:300].replace("\n", " ") or "(no reply in 6s)")
        # entity time (XEP-0202)
        r = iq_wait(andi, "<iq type='get' id='time1' to='localhost'><time xmlns='urn:xmpp:time'/></iq>", "iq", timeout=6)
        log("andi: XEP-0202 entity time answered", "type='result'" in r, r[:300].replace("\n", " ") or "(no reply in 6s)")
        # version (XEP-0092)
        r = iq_wait(andi, "<iq type='get' id='ver1' to='localhost'><query xmlns='jabber:iq:version'/></iq>", "iq", timeout=6)
        log("andi: XEP-0092 version answered", "type='result'" in r, r[:300].replace("\n", " ") or "(no reply in 6s)")

    if ok_a and ok_b:
        # presence both ways
        andi.send("<presence/>")
        time.sleep(0.5)
        r = budi.recv_until("presence", timeout=4)
        log("presence andi -> budi delivered", "<presence" in r, r[:200].replace("\n", " ") or "(nothing received)")
        # 1-1 message
        andi.send("<message to='budi@localhost/raw2' type='chat' id='m1'><body>halo budi</body></message>")
        time.sleep(0.5)
        r = budi.recv_until("halo budi", timeout=4)
        log("message andi -> budi delivered", "halo budi" in r, r[:300].replace("\n", " ") or "(nothing received)")
        budi.send("<message to='andi@localhost/raw1' type='chat' id='m2'><body>halo andi</body></message>")
        time.sleep(0.5)
        r = andi.recv_until("halo andi", timeout=4)
        log("message budi -> andi delivered", "halo andi" in r, r[:300].replace("\n", " ") or "(nothing received)")
        # message to known offline user: stored, no error (offline storage)
        andi.send("<message to='carol@localhost' type='chat' id='m3'><body>untuk carol offline</body></message>")
        time.sleep(0.5)
        r = andi.recv_until("error", timeout=3)
        log("message to known offline user -> stored, no error", "error" not in r, r[:200].replace("\n", " ") or "(no error, stored)")
        # message to unknown user: error reply (RFC 6121)
        andi.send("<message to='ghost@localhost' type='chat' id='m3b'><body>untuk ghost</body></message>")
        time.sleep(0.5)
        r = andi.recv_until("error", timeout=4)
        log("message to unknown user -> error reply", "error" in r and "service-unavailable" in r, r[:200].replace("\n", " ") or "(no reply)")

    # robustness: malformed stanza
    c3 = Conn("abuse")
    c3.send(STREAM_OPEN)
    c3.recv_until("stream:features")
    c3.send("<message><broken")
    time.sleep(1)
    try:
        c3.send("<presence/>")
        r = c3.recv_until("stream:error", timeout=3)
        log("abuse: malformed stanza -> stream error or close", ("stream:error" in r) or r == "", f"reply={r[:150]!r}")
    except Exception as e:
        log("abuse: malformed stanza -> connection dropped", True, f"exc={e}")
    c3.close()
    # oversized stanza
    c4 = Conn("abuse2")
    c4.send(STREAM_OPEN)
    c4.recv_until("stream:features")
    c4.send("<message to='budi@localhost'>" + "x" * 300000 + "</message>")
    time.sleep(1)
    try:
        c4.s.settimeout(3)
        data = c4.s.recv(4096)
        log("abuse: 300KB stanza -> connection closed or error", data == b"" or b"error" in data, f"got {len(data)} bytes: {data[:120]!r}")
    except socket.timeout:
        log("abuse: 300KB stanza -> connection still open (no limit enforced?)", False, "no reply, socket alive")
    except Exception as e:
        log("abuse: 300KB stanza -> connection dropped", True, f"exc={e}")
    c4.close()
    andi.close(); budi.close()
except Exception as e:
    print("HARNESS ERROR:", e)
    import traceback; traceback.print_exc()

print()
n_pass = sum(1 for _, ok, _ in results if ok)
print(f"SUMMARY: {n_pass}/{len(results)} passed")
sys.exit(0 if n_pass == len(results) else 1)
