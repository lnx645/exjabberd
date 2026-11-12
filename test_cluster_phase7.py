#!/usr/bin/env python3
"""Raw-socket live probe for Fase 7: clustering (distributed Erlang,
multi-node, same domain) between TWO real exjabberd nodes.

Topology (started separately via boot_cluster_nodes.sh):
  node A: exjabberd-a, domain localhost, C2S 127.0.0.1:5222
  node B: exjabberd-b, domain localhost, C2S 127.0.0.1:5225
  same cookie (EXJABBERD_ERLANG_COOKIE); B joined A's Mnesia schema.

Checks:
  (a) A and B see each other in the cluster (RPC Cluster.status)
  (b) andi on A <-> budi on B: chat message both ways (same domain,
      different nodes — NOT S2S)
  (c) bare presence andi -> budi and budi -> andi across nodes
  (d) roster item added on A is visible from B (shared Mnesia :roster)
  (e) kill B -> andi gets unavailable presence for budi; a message
      to budi is stored offline (or answered with an error), no hang
  (f) restart B -> cluster reforms; budi logs in and receives the
      stored offline message; chat works again
  (g) accounts (Mnesia :passwd) visible from both nodes

Usage: ./boot_cluster_nodes.sh start   # then:
       python3 test_cluster_phase7.py
Users are created fresh per run via RPC. Records PASS/FAIL per check.
"""
import socket, time, sys, re, base64, subprocess, uuid, os, signal

RUN = uuid.uuid4().hex[:8]
HOSTNAME = socket.gethostname()
REPO = os.path.dirname(os.path.abspath(__file__))
COOKIE = os.environ.get("EXJABBERD_ERLANG_COOKIE", "test-cluster-cookie-phase7")
results = []

A_NODE = f"exjabberd-a@{HOSTNAME}"
B_NODE = f"exjabberd-b@{HOSTNAME}"
A_C2S, B_C2S = 5222, 5225
DOMAIN = "localhost"

def log(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail}", flush=True)

def rpc_env():
    env = dict(os.environ)
    env["PATH"] = ("/home/hatch/workspace/.toolchain/otp-28.1/bin:"
                   "/home/hatch/workspace/.toolchain/elixir-1.19.7/bin:"
                   + env.get("PATH", ""))
    env["ELIXIR_ERL_OPTIONS"] = "+fnu -kernel net_ticktime 10"
    env["EXJABBERD_ERLANG_COOKIE"] = COOKIE
    return env

def rpc_call(node, module, fun, args="[]", timeout=60):
    code = (f'IO.inspect(:rpc.call(:"{node}", {module}, :{fun}, {args}), '
            f'label: "RPC")')
    # --cookie: the probe VM must carry the SAME Erlang cookie as the
    # cluster nodes (EXJABBERD_ERLANG_COOKIE is our own env var, the
    # VM itself only knows --cookie / ~/.erlang.cookie).
    r = subprocess.run(["elixir", "--sname", f"probe-{RUN}", "--cookie", COOKIE,
                        "-e", code],
                       capture_output=True, text=True, timeout=timeout, env=rpc_env())
    return r.stdout + r.stderr

def epmd_names():
    r = subprocess.run(["epmd", "-names"], capture_output=True, text=True, timeout=10)
    return r.stdout

def wait_epmd(node_short, want_present, timeout=90):
    """Fast liveness poll via epmd (no VM boot per check)."""
    end = time.time() + timeout
    while time.time() < end:
        present = f"name {node_short} at port" in epmd_names()
        if present == want_present:
            return True
        time.sleep(2)
    return False

def wait_port(port, want_open, timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=2)
            s.close()
            is_open = True
        except OSError:
            is_open = False
        if is_open == want_open:
            return True
        time.sleep(2)
    return False

def rpc_ok(node, module, fun, args="[]"):
    return ":ok" in rpc_call(node, module, fun, args)

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

    def wait_for(self, needle, timeout=10):
        """Wait until needle appears in the stream; returns all data seen."""
        end = time.time() + timeout
        out = b""
        self.s.settimeout(max(0.5, min(2, timeout)))
        while time.time() < end:
            if needle.encode() in self.buf:
                out += self.buf
                self.buf = b""
                return out.decode(errors="replace")
            try:
                chunk = self.s.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                break
            out += chunk
            self.buf += chunk
            if needle.encode() in self.buf:
                data = self.buf
                self.buf = b""
                return (out + b"").decode(errors="replace")
        return out.decode(errors="replace")

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass

def stream_open(domain):
    return (f"<?xml version='1.0'?><stream:stream to='{domain}' "
            f"xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")

def login(conn, domain, user, pw, resource):
    conn.send(stream_open(domain))
    r = conn.recv_until("stream:features")
    assert "stream:features" in r, f"{conn.name}: no features: {r[:200]}"
    b64 = base64.b64encode(f"\0{user}\0{pw}".encode()).decode()
    conn.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{b64}</auth>")
    r2 = conn.recv_until("success")
    assert "<success" in r2, f"{conn.name}: auth failed: {r2[:200]}"
    conn.send(stream_open(domain))
    conn.recv_until("stream:features")
    conn.send(f"<iq type='set' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
              f"<resource>{resource}</resource></bind></iq>")
    r3 = conn.recv_until("bind1")
    assert "bind" in r3 and "jid" in r3, f"{conn.name}: bind failed: {r3[:300]}"
    m = re.search(r"<jid>([^<]+)</jid>", r3)
    return m.group(1) if m else f"{user}@{domain}/{resource}"

def node_pid(which):
    try:
        with open(f"/tmp/exjabberd-{which}.pid") as f:
            return int(f.read().strip())
    except Exception:
        return None

def cluster_nodes_seen(node):
    out = rpc_call(node, "Exjabberd.Cluster", "status")
    # status map prints like %{nodes: [:"exjabberd-a@host", :"exjabberd-b@host"], ...}
    return out

def node_list(node):
    """Live Erlang nodes as seen by `node` (Node.list/0) — the
    authoritative membership list. (Cluster.status also prints
    mnesia db_nodes, which keeps a dead node listed, so substring
    checks on the whole status output are wrong for drop tests.)"""
    return rpc_call(node, "Node", "list")

def main():
    # ---- (a) cluster membership, both directions ----
    out_a = cluster_nodes_seen(A_NODE)
    out_b = cluster_nodes_seen(B_NODE)
    seen_a = "exjabberd-b@" in out_a
    seen_b = "exjabberd-a@" in out_b
    log("cluster-a-sees-b", seen_a, out_a.strip().splitlines()[-3:])
    log("cluster-b-sees-a", seen_b, out_b.strip().splitlines()[-3:])

    # ---- (g) accounts visible from both nodes ----
    ok_a = rpc_ok(A_NODE, "Exjabberd.Auth", "create_user", f'["{DOMAIN}", "andi", "secret"]')
    ok_b = rpc_ok(A_NODE, "Exjabberd.Auth", "create_user", f'["{DOMAIN}", "budi", "secret"]')
    # (create on A; B must see them via shared Mnesia — retry a few times)
    users_b = ""
    for _ in range(10):
        users_b = rpc_call(B_NODE, "Exjabberd.Auth.Mnesia", "get_users", f'["{DOMAIN}"]')
        if "andi" in users_b and "budi" in users_b:
            break
        time.sleep(1)
    log("users-created-on-a", ok_a and ok_b, f"andi={ok_a} budi={ok_b}")
    log("users-visible-from-b", "andi" in users_b and "budi" in users_b, users_b.strip()[:300])

    # ---- login both ----
    andi = Conn("andi@A", "127.0.0.1", A_C2S)
    budi = Conn("budi@B", "127.0.0.1", B_C2S)
    try:
        andi_jid = login(andi, DOMAIN, "andi", "secret", "laptop")
        budi_jid = login(budi, DOMAIN, "budi", "secret", "hp")
        log("login-andi-on-a", True, andi_jid)
        log("login-bidi-on-b", True, budi_jid)
    except AssertionError as e:
        log("login-andi-on-a", False, str(e))
        log("login-bidi-on-b", False, str(e))
        print_summary()
        return
    andi.drain(); budi.drain()

    # ---- (b) chat A -> B and B -> A ----
    andi.send(f"<message to='budi@{DOMAIN}' type='chat' id='m1'><body>halo dari A {RUN}</body></message>")
    got = budi.wait_for(f"halo dari A {RUN}", timeout=10)
    log("msg-a-to-b", f"halo dari A {RUN}" in got, got[:400])
    budi.send(f"<message to='andi@{DOMAIN}' type='chat' id='m2'><body>halo dari B {RUN}</body></message>")
    got = andi.wait_for(f"halo dari B {RUN}", timeout=10)
    log("msg-b-to-a", f"halo dari B {RUN}" in got, got[:400])

    # ---- (c) presence across nodes ----
    andi.send("<presence/>")
    got = budi.wait_for("andi@localhost", timeout=10)
    log("presence-a-to-b", "<presence" in got and "andi@localhost" in got, got[:400])
    budi.send("<presence/>")
    got = andi.wait_for("budi@localhost", timeout=10)
    log("presence-b-to-a", "<presence" in got and "budi@localhost" in got, got[:400])

    # ---- (d) roster item added on A visible from B ----
    andi.send(f"<iq type='set' id='roster1'><query xmlns='jabber:iq:roster'>"
              f"<item jid='budi@{DOMAIN}' name='Budi'/></query></iq>")
    andi.wait_for("roster1", timeout=5)
    roster_b = ""
    for _ in range(10):
        roster_b = rpc_call(B_NODE, "Exjabberd.Mod.Roster", "get_roster", f'["{DOMAIN}", "andi"]')
        if "budi@localhost" in roster_b:
            break
        time.sleep(1)
    log("roster-a-visible-from-b", "budi@localhost" in roster_b, roster_b.strip()[:300])

    # ---- (e) kill B ----
    pid_b = node_pid("b")
    if pid_b:
        os.kill(pid_b, signal.SIGTERM)
        log("kill-node-b", True, f"SIGTERM to pid {pid_b}")
    else:
        log("kill-node-b", False, "no pid file for B")
    # Wait until A no longer sees B (net_ticktime 10 -> ~10-20 s).
    # Fast poll via epmd first, then one RPC confirm on A's live
    # Node.list/0 (NOT the whole status output: mnesia db_nodes
    # keeps a dead node listed).
    gone = wait_epmd("exjabberd-b", False, timeout=60)
    if gone:
        out = node_list(A_NODE)
        gone = "exjabberd-b@" not in out
    log("cluster-a-drops-b", gone, "B gone from A's Node.list" if gone else "B still listed")
    # Unavailable presence for budi should reach andi.
    got = andi.wait_for("budi@localhost", timeout=30)
    unavail = ("unavailable" in got and "budi@localhost" in got)
    log("presence-unavailable-after-kill", unavail, got[:400])
    # Message to the dead node's user: stored offline or errored, never a hang.
    andi.send(f"<message to='budi@{DOMAIN}' type='chat' id='m3'><body>halo offline {RUN}</body></message>")
    got = andi.wait_for("service-unavailable", timeout=6)
    err_path = "service-unavailable" in got
    stored = 0
    for _ in range(10):
        out = rpc_call(A_NODE, "Exjabberd.Mod.Offline", "count", f'["budi@{DOMAIN}"]')
        m = re.search(r"RPC: (\d+)", out)
        if m:
            stored = int(m.group(1))
            if stored > 0:
                break
        time.sleep(1)
    offline_path = stored > 0
    log("msg-to-dead-node-offline-or-error", err_path or offline_path,
        f"error={err_path} offline_stored={stored} got={got[:200]}")
    andi.drain()

    # ---- (f) restart B, cluster reforms, offline delivery ----
    r = subprocess.run(["bash", os.path.join(REPO, "boot_cluster_nodes.sh"), "start-b"],
                       capture_output=True, text=True, timeout=180)
    log("restart-node-b", "up (C2S 5225" in r.stdout, (r.stdout + r.stderr).strip()[-300:])
    rejoined = wait_epmd("exjabberd-b", True, timeout=120) and wait_port(B_C2S, True, timeout=60)
    if rejoined:
        out = node_list(A_NODE)
        rejoined = "exjabberd-b@" in out
    log("cluster-reforms-after-restart", rejoined, "B back in A's Node.list" if rejoined else "B not back")
    # Budi logs in again on B.
    budi2 = Conn("budi@B2", "127.0.0.1", B_C2S)
    try:
        budi2_jid = login(budi2, DOMAIN, "budi", "secret", "hp2")
        log("login-bidi-after-restart", True, budi2_jid)
    except AssertionError as e:
        log("login-bidi-after-restart", False, str(e))
        budi2 = None
    if budi2 is not None:
        if offline_path:
            got = budi2.wait_for(f"halo offline {RUN}", timeout=15)
            log("offline-msg-delivered-on-relogin", f"halo offline {RUN}" in got, got[:400])
        else:
            log("offline-msg-delivered-on-relogin", True, "skipped: error path taken, nothing stored")
        budi2.drain()
        # Chat works again across the reformed cluster.
        andi.send(f"<message to='budi@{DOMAIN}' type='chat' id='m4'><body>halo lagi {RUN}</body></message>")
        got = budi2.wait_for(f"halo lagi {RUN}", timeout=10)
        log("msg-a-to-b-after-rejoin", f"halo lagi {RUN}" in got, got[:400])
        budi2.send(f"<message to='andi@{DOMAIN}' type='chat' id='m5'><body>balasan lagi {RUN}</body></message>")
        got = andi.wait_for(f"balasan lagi {RUN}", timeout=10)
        log("msg-b-to-a-after-rejoin", f"balasan lagi {RUN}" in got, got[:400])
        budi2.close()

    # ---- (g2) accounts still visible from B after restart ----
    users_b2 = rpc_call(B_NODE, "Exjabberd.Auth.Mnesia", "get_users", f'["{DOMAIN}"]')
    log("users-visible-from-b-after-restart", "andi" in users_b2 and "budi" in users_b2,
        users_b2.strip()[:300])

    andi.close()
    budi.close()
    print_summary()

def print_summary():
    failed = [n for n, ok, _ in results if not ok]
    print(f"\n==== cluster phase7: {len(results) - len(failed)}/{len(results)} PASS ====", flush=True)
    if failed:
        print("FAILED: " + ", ".join(failed), flush=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
