#!/usr/bin/env python3
"""Raw-socket live probe for Fase 19 — SASL EXTERNAL for S2S
(RFC 6120 §4.8) and bidirectional S2S streams (XEP-0288),
between the two real exjabberd nodes booted by boot_s2s_nodes.sh.

  node A: domain a.localhost, C2S 127.0.0.1:5222, S2S 127.0.0.1:5269
  node B: domain b.localhost, C2S 127.0.0.1:5223, S2S 127.0.0.1:5270

Trust setup (done by this probe): both nodes generate their own
self-signed certificate at boot (SANs name their domain since
Fase 19); the probe assembles priv/ssl/pinned.pem in both node
copies from the two certificates — SASL EXTERNAL then requires
(a) the handshake certificate to name the asserted domain and
(b) to be pinned. The probe flips `s2s_prefer_external` on both
nodes via RPC (config file default stays false), so the
node-to-node flows below authenticate with EXTERNAL; the older
test_s2s.py (dialback) runs BEFORE this probe in verify.sh.

Checks:
  * A->B federated message establishes A->B with auth_method
    :external and bidi requested (RPC status on A).
  * B->A message is delivered WITHOUT B opening an outbound
    connection (XEP-0288 channel on B, RPC-verified).
  * Raw EXTERNAL negatives against A: an unpinned rogue cert
    naming b.localhost -> failure; A's own pinned cert (names
    a.localhost) claiming to be b.localhost -> failure; EXTERNAL
    on a plaintext stream -> failure (encryption-required).
  * Raw EXTERNAL positive: B's real certificate -> <success/>,
    stream restart, stanza routed to an A user.
  * Raw bidi: the EXTERNAL connection asks <bidi/> -> channel
    registered on A (RPC); an A->B message then arrives on the
    RAW socket (and not at node B); a pre-auth <bidi/> from an
    unauthenticated connection registers nothing.

Usage: ./boot_s2s_nodes.sh start, then: python3 test_s2s_external_bidi_phase19.py
"""
import socket, time, sys, re, base64, subprocess, uuid, os, ssl

RUN = uuid.uuid4().hex[:8]
HOSTNAME = socket.gethostname()
results = []

A_C2S = ("127.0.0.1", 5222)
B_C2S = ("127.0.0.1", 5223)
A_S2S = ("127.0.0.1", 5269)
A_DOM, B_DOM = "a.localhost", "b.localhost"
A_DIR = "/tmp/exjabberd-s2s-a"
B_DIR = "/tmp/exjabberd-s2s-b"

TOOLCHAIN_PATH = ("/home/hatch/workspace/.toolchain/otp-28.1/bin:"
                  "/home/hatch/workspace/.toolchain/elixir-1.19.7/bin:")


def log(name, ok, detail=""):
    results.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail}", flush=True)


def rpc(node, code):
    env = dict(os.environ)
    env["PATH"] = TOOLCHAIN_PATH + env.get("PATH", "")
    env["ELIXIR_ERL_OPTIONS"] = "+fnu"
    full = f':rpc.call(:"{node}@{HOSTNAME}", {code}) |> IO.inspect()'
    r = subprocess.run(["elixir", "--sname", f"probe19-{RUN}", "-e", full],
                       capture_output=True, text=True, timeout=60, env=env)
    return r.stdout + r.stderr


def rpc_create(node, host, user):
    out = rpc(node, f'Exjabberd.Auth, :create_user, ["{host}", "{user}", "secret"]')
    return ":ok" in out


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


def stream_open(domain, server=True, frm=None):
    ns = "jabber:server" if server else "jabber:client"
    fr = f"from='{frm}' " if frm else ""
    return (f"<?xml version='1.0'?><stream:stream {fr}to='{domain}' "
            f"xmlns='{ns}' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")


def login(conn, domain, user, pw, resource):
    conn.send(stream_open(domain, server=False))
    r = conn.recv_until("stream:features")
    assert "stream:features" in r, f"{conn.name}: no features: {r[:200]}"
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
    return m.group(1)


def s2s_tls_connect(certfile, keyfile, frm, to, addr):
    """Plain stream -> STARTTLS (presenting certfile/keyfile) ->
    restarted stream. Returns (Conn-over-TLS, features text)."""
    c = Conn("raw-s2s", *addr)
    c.send(stream_open(to, server=True, frm=frm))
    feats = c.recv_until("stream:features")
    assert "starttls" in feats, f"no starttls offered: {feats[:200]}"
    c.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
    proc = c.recv_until("proceed")
    assert "proceed" in proc, f"no proceed: {proc[:200]}"
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if certfile:
        ctx.load_cert_chain(certfile, keyfile)
    c.s = ctx.wrap_socket(c.s, server_hostname=to)
    c.buf = b""
    c.send(stream_open(to, server=True, frm=frm))
    feats2 = c.recv_until("stream:features")
    return c, feats2


def try_external(c):
    c.send("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>=</auth>")
    out = ""
    end = time.time() + 10
    while time.time() < end and "<failure" not in out and "<success" not in out:
        out += c.recv_any(timeout=2)
    return out


# ---------------------------------------------------------------- setup
# Restart both nodes: earlier probes on this boot (test_s2s.py)
# leave established dialback connections behind, and the manager
# would reuse them — the assertions below need a clean slate so
# the connections this probe creates are provably EXTERNAL/bidi.
def wait_port(port, seconds=120):
    end = time.time() + seconds
    while time.time() < end:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=2)
            s.close()
            return True
        except OSError:
            time.sleep(1)
    return False


subprocess.run(["./boot_s2s_nodes.sh", "restart"],
               capture_output=True, timeout=300)
log("setup: both S2S nodes restarted clean",
    wait_port(5222) and wait_port(5223))
# Force both nodes to have generated their certificates, then pin
# both certificates on both nodes.
rpc("exjabberd-a", "Exjabberd.Tls, :ensure_cert, []")
rpc("exjabberd-b", "Exjabberd.Tls, :ensure_cert, []")
a_cert_path = os.path.join(A_DIR, "priv/ssl/cert.pem")
b_cert_path = os.path.join(B_DIR, "priv/ssl/cert.pem")
a_key_path = os.path.join(A_DIR, "priv/ssl/key.pem")
b_key_path = os.path.join(B_DIR, "priv/ssl/key.pem")
try:
    bundle = open(a_cert_path).read() + open(b_cert_path).read()
    for d in (A_DIR, B_DIR):
        with open(os.path.join(d, "priv/ssl/pinned.pem"), "w") as f:
            f.write(bundle)
    log("setup: pinned.pem assembled on both nodes", True)
except Exception as e:
    log("setup: pinned.pem assembled on both nodes", False, str(e))

for node in ("exjabberd-a", "exjabberd-b"):
    rpc(node, "Exjabberd.Config, :set, [:global, :s2s_prefer_external, true]")

ua, ub = f"exta{RUN}", f"extb{RUN}"
ok_a = rpc_create("exjabberd-a", A_DOM, ua)
ok_b = rpc_create("exjabberd-b", B_DOM, ub)
log("setup: users created on both nodes", ok_a and ok_b)

andi = Conn("andi", *A_C2S)
budi = Conn("budi", *B_C2S)
try:
    login(andi, A_DOM, ua, "secret", f"p19-{RUN}")
    login(budi, B_DOM, ub, "secret", f"p19-{RUN}")
    log("c2s: logins on both nodes", True)
except Exception as e:
    log("c2s: logins on both nodes", False, str(e))

# ------------------------------------------------- 1. EXTERNAL A -> B
try:
    andi.send(f"<message id='e1-{RUN}' to='{ub}@b.localhost' type='chat'>"
              f"<body>external-a2b-{RUN}</body></message>")
    got = budi.recv_until(f"external-a2b-{RUN}", timeout=15)
    log("external: A->B message delivered", f"external-a2b-{RUN}" in got, got[:200])
except Exception as e:
    log("external: A->B message delivered", False, str(e))

conns_a = rpc("exjabberd-a", "Exjabberd.S2S, :connections, []")
log("external: A->B connection used SASL EXTERNAL",
    "auth_method: :external" in conns_a and "b.localhost" in conns_a,
    conns_a.strip()[:300])
log("bidi: A->B connection requested bidi",
    "bidi: true" in conns_a, conns_a.strip()[:300])

# ------------------------------------------------- 2. Bidi B -> A
try:
    budi.send(f"<message id='e2-{RUN}' to='{ua}@a.localhost' type='chat'>"
              f"<body>bidi-b2a-{RUN}</body></message>")
    got = andi.recv_until(f"bidi-b2a-{RUN}", timeout=15)
    log("bidi: B->A message delivered", f"bidi-b2a-{RUN}" in got, got[:200])
except Exception as e:
    log("bidi: B->A message delivered", False, str(e))

conns_b = rpc("exjabberd-b", "Exjabberd.S2S, :connections, []")
channels_b = rpc("exjabberd-b", "Exjabberd.S2S, :bidi_channels, []")
log("bidi: B opened NO outbound connection to A (channel used)",
    "a.localhost" not in conns_b, conns_b.strip()[:200])
log("bidi: channel for a.localhost registered on B",
    "a.localhost" in channels_b, channels_b.strip()[:200])

# ------------------------------------------------- 3. Raw EXTERNAL vs A
# 3a. Rogue cert: names b.localhost but is NOT pinned.
rogue_dir = f"/tmp/rogue-{RUN}"
try:
    os.makedirs(rogue_dir, exist_ok=True)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", f"{rogue_dir}/key.pem", "-out", f"{rogue_dir}/cert.pem",
         "-days", "30", "-nodes", "-subj", "/CN=b.localhost",
         "-addext", "subjectAltName=DNS:b.localhost"],
        capture_output=True, timeout=30, check=True)
    c, feats = s2s_tls_connect(f"{rogue_dir}/cert.pem", f"{rogue_dir}/key.pem",
                               B_DOM, A_DOM, A_S2S)
    offered = "EXTERNAL" in feats
    r = try_external(c)
    log("external: mechanism offered on TLS stream", offered, feats[:250])
    log("external: unpinned rogue cert rejected",
        "<failure" in r and "not-authorized" in r, r[:250])
    c.close()
except Exception as e:
    log("external: unpinned rogue cert rejected", False, str(e))

# 3b. A's own cert: pinned, but names a.localhost while claiming b.localhost.
try:
    c, _feats = s2s_tls_connect(a_cert_path, a_key_path, B_DOM, A_DOM, A_S2S)
    r = try_external(c)
    log("external: pinned cert with wrong domain identity rejected",
        "<failure" in r and "not-authorized" in r, r[:250])
    c.close()
except Exception as e:
    log("external: pinned cert with wrong domain identity rejected", False, str(e))

# 3c. EXTERNAL on a plaintext stream.
try:
    c = Conn("plain", *A_S2S)
    c.send(stream_open(A_DOM, server=True, frm=B_DOM))
    c.recv_until("stream:features")
    r = try_external(c)
    log("external: plaintext attempt rejected (encryption-required)",
        "<failure" in r and "encryption-required" in r, r[:250])
    c.close()
except Exception as e:
    log("external: plaintext attempt rejected (encryption-required)", False, str(e))

# 3d. B's real cert: success, restart, stanza routed.
raw_b = None
try:
    raw_b, _feats = s2s_tls_connect(b_cert_path, b_key_path, B_DOM, A_DOM, A_S2S)
    r = try_external(raw_b)
    ok = "<success" in r
    log("external: B's pinned cert accepted (<success/>)", ok, r[:200])
    raw_b.send(stream_open(A_DOM, server=True, frm=B_DOM))
    raw_b.recv_until("stream:features")
    andi.drain()
    raw_b.send(f"<message id='e3-{RUN}' from='{ub}@b.localhost' to='{ua}@a.localhost' "
               f"type='chat'><body>raw-external-{RUN}</body></message>")
    got = andi.recv_until(f"raw-external-{RUN}", timeout=12)
    log("external: stanza over EXTERNAL connection delivered to A user",
        f"raw-external-{RUN}" in got, got[:200])
except Exception as e:
    log("external: B's pinned cert accepted (<success/>)", False, str(e))
    log("external: stanza over EXTERNAL connection delivered to A user", False, str(e))

# ------------------------------------------------- 4. Raw bidi
if raw_b is not None:
    try:
        raw_b.send("<bidi xmlns='urn:xmpp:bidi:0'/>")
        time.sleep(1.0)
        channels_a = rpc("exjabberd-a", "Exjabberd.S2S, :bidi_channels, []")
        log("bidi: raw EXTERNAL connection registered as channel on A",
            "b.localhost" in channels_a, channels_a.strip()[:200])

        budi.drain()
        andi.send(f"<message id='e4-{RUN}' to='{ub}@b.localhost' type='chat'>"
                  f"<body>over-bidi-{RUN}</body></message>")
        got_raw = raw_b.recv_until(f"over-bidi-{RUN}", timeout=12)
        leaked = budi.recv_any(timeout=2.5)
        log("bidi: A->B stanza arrives on the single (raw) connection",
            f"over-bidi-{RUN}" in got_raw, got_raw[:250])
        log("bidi: stanza did NOT also go to node B",
            f"over-bidi-{RUN}" not in leaked, leaked[:150])
    except Exception as e:
        log("bidi: raw EXTERNAL connection registered as channel on A", False, str(e))
    raw_b.close()

# Pre-auth bidi registers nothing.
try:
    c = Conn("preauth", *A_S2S)
    c.send(stream_open(A_DOM, server=True, frm="c.localhost"))
    c.recv_until("stream:features")
    c.send("<bidi xmlns='urn:xmpp:bidi:0'/>")
    time.sleep(1.0)
    channels_a = rpc("exjabberd-a", "Exjabberd.S2S, :bidi_channels, []")
    log("bidi: pre-auth <bidi/> registers no channel",
        "c.localhost" not in channels_a, channels_a.strip()[:200])
    c.close()
except Exception as e:
    log("bidi: pre-auth <bidi/> registers no channel", False, str(e))

andi.close()
budi.close()
failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
