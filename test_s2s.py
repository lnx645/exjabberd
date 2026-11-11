#!/usr/bin/env python3
"""Raw-socket live probe for Fase 3: S2S/federation (RFC 6120 §4 +
XEP-0220 Server Dialback) between TWO real exjabberd nodes.

Topology (started separately from two working copies of the repo):
  node A: domain a.localhost, C2S 127.0.0.1:5222, S2S 127.0.0.1:5269
  node B: domain b.localhost, C2S 127.0.0.1:5223, S2S 127.0.0.1:5270
  node A overrides b.localhost -> 127.0.0.1:5270 (+ ghost.localhost ->
  127.0.0.1:59999, closed port, for the unreachable-domain check)
  node B overrides a.localhost -> 127.0.0.1:5269
  dialback secrets (must match the node configs):
  A = test-secret-node-a-7f3a9c, B = test-secret-node-b-41bd27

Usage: start both nodes first, then: python3 test_s2s.py
Users are created fresh per run via RPC. Records PASS/FAIL per check.
"""
import socket, time, sys, re, base64, subprocess, uuid, os, ssl, hmac, hashlib

RUN = uuid.uuid4().hex[:8]
HOSTNAME = socket.gethostname()
results = []

A_C2S, A_S2S, A_DOM, A_SECRET = ("127.0.0.1", 5222), ("127.0.0.1", 5269), "a.localhost", "test-secret-node-a-7f3a9c"
B_C2S, B_S2S, B_DOM, B_SECRET = ("127.0.0.1", 5223), ("127.0.0.1", 5270), "b.localhost", "test-secret-node-b-41bd27"

def log(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail}", flush=True)

def dialback_key(secret, stream_id, frm, to):
    """XEP-0220 §2.1.1: HMAC-SHA256(hex(SHA256(secret)), 'to from id')."""
    hkey = hashlib.sha256(secret.encode()).hexdigest().encode()
    msg = f"{to} {frm} {stream_id}".encode()
    return hmac.new(hkey, msg, hashlib.sha256).hexdigest()

def rpc_create(node, host, user):
    code = (
        f':rpc.call(:"{node}@{HOSTNAME}", Exjabberd.Auth, '
        f':create_user, ["{host}", "{user}", "secret"]) |> IO.inspect()'
    )
    env = dict(os.environ)
    env["PATH"] = ("/home/hatch/workspace/.toolchain/otp-28.1/bin:"
                   "/home/hatch/workspace/.toolchain/elixir-1.19.7/bin:"
                   + env.get("PATH", ""))
    env["ELIXIR_ERL_OPTIONS"] = "+fnu"
    r = subprocess.run(["elixir", "--sname", "probe", "-e", code],
                       capture_output=True, text=True, timeout=60, env=env)
    return ":ok" in (r.stdout + r.stderr)

class Conn:
    def __init__(self, name, host, port):
        self.name = name
        self.s = socket.create_connection((host, port), timeout=10)
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

def stream_open(domain, server=True):
    ns = "jabber:server" if server else "jabber:client"
    return (f"<?xml version='1.0'?><stream:stream to='{domain}' "
            f"xmlns='{ns}' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")

def login(conn, domain, user, pw, resource):
    conn.send(stream_open(domain, server=False))
    r = conn.recv_until("stream:features")
    assert "stream:features" in r, f"{conn.name}: no features: {r[:200]}"
    sm = "urn:xmpp:sm:3" in r
    b64 = base64.b64encode(f"\0{user}\0{pw}".encode()).decode()
    conn.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{b64}</auth>")
    r2 = conn.recv_until("success")
    assert "<success" in r2, f"{conn.name}: auth failed: {r2[:200]}"
    conn.send(stream_open(domain, server=False))
    conn.recv_until("stream:features")
    conn.send(f"<iq type='set' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
              f"<resource>{resource}</resource></bind></iq>")
    r4 = conn.recv_until("bind")
    m = re.search(r"<jid>([^<]+)</jid>", r4)
    assert m, f"{conn.name}: bind failed: {r4[:200]}"
    return m.group(1), sm

# --- setup: users ---
ok_a = rpc_create("exjabberd-a", A_DOM, "andi")
ok_b = rpc_create("exjabberd-b", B_DOM, "budi")
log("setup: user andi@a.localhost", ok_a)
log("setup: user budi@b.localhost", ok_b)

# --- 1. S2S stream features on node B ---
try:
    s = Conn("s2s-probe", *B_S2S)
    s.send(stream_open(B_DOM, server=True).replace("to='b.localhost'",
          "from='a.localhost' to='b.localhost'"))
    feats = s.recv_until("stream:features", timeout=6)
    log("s2s: features advertise STARTTLS + dialback",
        "starttls" in feats and "dialback" in feats, feats[:300].replace("\n", " "))
    s.close()
except Exception as e:
    log("s2s: features advertise STARTTLS + dialback", False, str(e))

# --- 2. C2S logins (both nodes) ---
try:
    andi = Conn("andi", *A_C2S)
    andi_jid, andi_sm = login(andi, A_DOM, "andi", "secret", f"probe-{RUN}")
    log("c2s: andi@a.localhost login + bind", andi_jid.startswith("andi@a.localhost/"), andi_jid)
    log("c2s: andi stream features include SM (host fix)", andi_sm)
except Exception as e:
    log("c2s: andi@a.localhost login + bind", False, str(e))
    andi = None

try:
    budi = Conn("budi", *B_C2S)
    budi_jid, budi_sm = login(budi, B_DOM, "budi", "secret", f"probe-{RUN}")
    log("c2s: budi@b.localhost login + bind", budi_jid.startswith("budi@b.localhost/"), budi_jid)
    log("c2s: budi stream features include SM (host fix)", budi_sm)
except Exception as e:
    log("c2s: budi@b.localhost login + bind", False, str(e))
    budi = None

if andi and budi:
    # --- 3. message A -> B (first federated stanza: triggers dialback) ---
    try:
        andi.send(f"<message id='m1-{RUN}' to='budi@b.localhost' type='chat'>"
                  f"<body>hello-s2s-{RUN}</body></message>")
        got = budi.recv_until(f"hello-s2s-{RUN}", timeout=12)
        log("s2s: message andi@a -> budi@b delivered",
            f"hello-s2s-{RUN}" in got and "andi@a.localhost" in got, got[:300].replace("\n", " "))
    except Exception as e:
        log("s2s: message andi@a -> budi@b delivered", False, str(e))

    # --- 4. reply B -> A (reverse connection, dialback B -> A) ---
    try:
        budi.send(f"<message id='m2-{RUN}' to='andi@a.localhost' type='chat'>"
                  f"<body>reply-s2s-{RUN}</body></message>")
        got = andi.recv_until(f"reply-s2s-{RUN}", timeout=12)
        log("s2s: reply budi@b -> andi@a delivered",
            f"reply-s2s-{RUN}" in got and "budi@b.localhost" in got, got[:300].replace("\n", " "))
    except Exception as e:
        log("s2s: reply budi@b -> andi@a delivered", False, str(e))

    # --- 5. directed presence A -> B ---
    try:
        andi.drain()
        budi.drain()
        andi.send(f"<presence id='p1-{RUN}' to='budi@b.localhost'/>")
        got = budi.recv_until("presence", timeout=10)
        log("s2s: directed presence andi@a -> budi@b",
            "andi@a.localhost" in got and "<presence" in got, got[:300].replace("\n", " "))
    except Exception as e:
        log("s2s: directed presence andi@a -> budi@b", False, str(e))

    # --- 6. dialback invalid: unknown domain, bogus key ---
    try:
        s = Conn("evil", *B_S2S)
        s.send(stream_open(B_DOM, server=True).replace("to='b.localhost'",
               "from='evil.example' to='b.localhost'"))
        hdr = s.recv_until("stream:features", timeout=6)
        sid = re.search(r"id='([^']+)'", hdr).group(1)
        s.send(f"<db:result xmlns:db='jabber:server:dialback' from='evil.example' "
               f"to='b.localhost' id='{sid}'>{'0' * 64}</db:result>")
        got = s.recv_until("db:result", timeout=20)
        log("dialback: bogus key from evil.example rejected + stream closed",
            "invalid" in got, got[:300].replace("\n", " "))
        s.close()
    except Exception as e:
        log("dialback: bogus key from evil.example rejected + stream closed", False, str(e))

    # --- 7. dialback forged: claims a.localhost, wrong key, stanza smuggled ---
    try:
        s = Conn("forged", *B_S2S)
        s.send(stream_open(B_DOM, server=True).replace("to='b.localhost'",
               "from='a.localhost' to='b.localhost'"))
        hdr = s.recv_until("stream:features", timeout=6)
        sid = re.search(r"id='([^']+)'", hdr).group(1)
        good = dialback_key(A_SECRET, sid, "a.localhost", "b.localhost")
        bad = ("0" if good[0] != "0" else "1") + good[1:]
        budi.drain()
        s.send(f"<db:result xmlns:db='jabber:server:dialback' from='a.localhost' "
               f"to='b.localhost' id='{sid}'>{bad}</db:result>"
               f"<message id='m3-{RUN}' from='andi@a.localhost' to='budi@b.localhost' "
               f"type='chat'><body>forged-{RUN}</body></message>")
        got = s.recv_until("db:result", timeout=8)
        leaked = budi.recv_any(timeout=2.5)
        log("dialback: forged a.localhost key rejected",
            "invalid" in got, got[:300].replace("\n", " "))
        log("dialback: no stanza leaks from unverified connection",
            f"forged-{RUN}" not in leaked, leaked[:200].replace("\n", " "))
        s.close()
    except Exception as e:
        log("dialback: forged a.localhost key rejected", False, str(e))

    # --- 8. STARTTLS S2S: TLS handshake + dialback + stanza over TLS ---
    try:
        raw = socket.create_connection(B_S2S, timeout=10)
        raw.settimeout(6)
        bufbox = [b""]
        def recv_until_sock(sock, needle, timeout=6):
            sock.settimeout(timeout)
            end = time.time() + timeout
            while time.time() < end:
                if needle.encode() in bufbox[0]:
                    out, bufbox[0] = bufbox[0], b""
                    return out.decode(errors="replace")
                chunk = sock.recv(4096)
                if not chunk:
                    break
                bufbox[0] += chunk
            out, bufbox[0] = bufbox[0], b""
            return out.decode(errors="replace")
        raw.sendall(stream_open(B_DOM, server=True).replace(
            "to='b.localhost'", "from='a.localhost' to='b.localhost'").encode())
        feats = recv_until_sock(raw, "stream:features")
        assert "starttls" in feats, f"no starttls: {feats[:200]}"
        raw.sendall(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        proc = recv_until_sock(raw, "proceed")
        assert "proceed" in proc, f"no proceed: {proc[:200]}"
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(raw, server_hostname="b.localhost")
        cipher = tls.cipher()
        tls.sendall(stream_open(B_DOM, server=True).replace(
            "to='b.localhost'", "from='a.localhost' to='b.localhost'").encode())
        feats2 = recv_until_sock(tls, "stream:features")
        sid = re.search(r"id='([^']+)'", feats2).group(1)
        key = dialback_key(A_SECRET, sid, "a.localhost", "b.localhost")
        tls.sendall(f"<db:result xmlns:db='jabber:server:dialback' from='a.localhost' "
                    f"to='b.localhost' id='{sid}'>{key}</db:result>".encode())
        res = recv_until_sock(tls, "db:result", timeout=8)
        budi.drain()
        tls.sendall(f"<message id='m4-{RUN}' from='andi@a.localhost' to='budi@b.localhost' "
                    f"type='chat'><body>tls-s2s-{RUN}</body></message>".encode())
        got = budi.recv_until(f"tls-s2s-{RUN}", timeout=10)
        log("s2s STARTTLS: handshake + dialback valid over TLS",
            "valid" in res and cipher and cipher[1].startswith("TLS"),
            f"cipher={cipher} res={res[:160]}")
        log("s2s STARTTLS: stanza over TLS delivered to budi",
            f"tls-s2s-{RUN}" in got, got[:200].replace("\n", " "))
        tls.close()
    except Exception as e:
        log("s2s STARTTLS: handshake + dialback valid over TLS", False, str(e))
        log("s2s STARTTLS: stanza over TLS delivered to budi", False, str(e))

    # --- 9. unreachable domain -> error stanza, not silent loss ---
    try:
        andi.drain()
        andi.send(f"<message id='m5-{RUN}' to='ghost@ghost.localhost' type='chat'>"
                  f"<body>ghost-{RUN}</body></message>")
        got = andi.recv_until("remote-server-not-found", timeout=12)
        log("s2s: message to unreachable domain bounces remote-server-not-found",
            "remote-server-not-found" in got and "type='error'" in got,
            got[:400].replace("\n", " "))
    except Exception as e:
        log("s2s: message to unreachable domain bounces remote-server-not-found", False, str(e))

    # --- 10. IQ to the remote server domain, answered back over S2S ---
    try:
        andi.drain()
        andi.send(f"<iq id='iq1-{RUN}' to='b.localhost' type='get'>"
                  f"<query xmlns='http://jabber.org/protocol/disco#info'/></iq>")
        got = andi.recv_until(f"iq1-{RUN}", timeout=15)
        log("s2s: disco#info IQ to b.localhost answered",
            f"iq1-{RUN}" in got and "type='result'" in got, got[:400].replace("\n", " "))
    except Exception as e:
        log("s2s: disco#info IQ to b.localhost answered", False, str(e))

    andi.close()
    budi.close()

passed = sum(1 for _, ok, _ in results if ok)
print(f"\n{passed}/{len(results)} checks passed")
sys.exit(0 if passed == len(results) else 1)
