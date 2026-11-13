#!/usr/bin/env python3
"""Live test for `starttls_required` (Fase 11, XEP/RFC 6120 policy)
and anonymous auth (`auth_method: anonymous`, ejabberd_auth_anonymous).

Boots its OWN server twice with a temporarily modified exjabberd.yml
(the original file is always restored), like
test_auth_sqlite_phase8.py. Port 5222 must be free.
"""
import socket, ssl, time, sys, os, subprocess, signal, base64

REPO = os.path.dirname(os.path.abspath(__file__))
YML = os.path.join(REPO, "exjabberd.yml")
HOST, PORT = "127.0.0.1", 5222
results = []

def log(name, ok, detail=""):
    results.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail[:220]}", flush=True)

def tool_env(extra=None):
    env = dict(os.environ)
    env["PATH"] = ("/home/hatch/workspace/.toolchain/otp-28.1/bin:"
                   "/home/hatch/workspace/.toolchain/elixir-1.19.7/bin:"
                   + env.get("PATH", ""))
    if extra:
        env.update(extra)
    return env

def port_open():
    try:
        s = socket.create_connection((HOST, PORT), timeout=2)
        s.close()
        return True
    except OSError:
        return False

class Server:
    def __init__(self):
        self.proc = None
    def start(self, timeout=90):
        assert not port_open(), "port 5222 busy -- stop the dev server first"
        self.proc = subprocess.Popen(
            ["mix", "run", "--no-halt"], cwd=REPO,
            env=tool_env({"ELIXIR_ERL_OPTIONS": "+fnu -sname exjabberd"}),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if port_open():
                time.sleep(1)
                return True
            if self.proc.poll() is not None:
                return False
            time.sleep(1)
        return False
    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
        self.proc = None

STREAM_OPEN = ("<?xml version='1.0'?><stream:stream to='localhost' "
               "xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")

class Conn:
    def __init__(self):
        self.s = socket.create_connection((HOST, PORT), timeout=10)
        self.s.settimeout(8)
        self.buf = b""
    def send(self, data):
        if isinstance(data, str): data = data.encode()
        self.s.sendall(data)
    def recv_until(self, needle, timeout=8):
        end = time.time() + timeout
        while time.time() < end:
            if needle.encode() in self.buf:
                out, self.buf = self.buf, b""
                return out.decode(errors="replace")
            try:
                chunk = self.s.recv(4096)
            except (socket.timeout, ssl.SSLError):
                break
            if not chunk:
                break
            self.buf += chunk
        out, self.buf = self.buf, b""
        return out.decode(errors="replace")
    def close(self):
        try: self.s.close()
        except Exception: pass

def plain_auth(conn, user, pw):
    b64 = base64.b64encode(f"\0{user}\0{pw}".encode()).decode()
    conn.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{b64}</auth>")

def bind(conn, resource):
    conn.send(STREAM_OPEN)
    conn.recv_until("stream:features")
    conn.send(f"<iq type='set' id='b1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>{resource}</resource></bind></iq>")
    return conn.recv_until("bind")

def main():
    with open(YML, "rb") as f:
        original = f.read()
    server = Server()
    try:
        # ---------- Phase A: starttls_required: true ----------
        text = original.decode().replace("starttls_required: false", "starttls_required: true")
        assert "starttls_required: true" in text
        with open(YML, "w") as f:
            f.write(text)
        assert server.start(), "server did not start (starttls_required)"
        rpc = subprocess.run(
            ["elixir", "--sname", "probe11b", "-e",
             ':rpc.call(:"exjabberd@' + socket.gethostname() + '", Exjabberd.Auth, '
             ':create_user, ["localhost", "andi", "secret"]) |> IO.inspect()'],
            capture_output=True, text=True, timeout=60, env=tool_env({"ELIXIR_ERL_OPTIONS": "+fnu"}))
        print("[SETUP] andi create:", (rpc.stdout + rpc.stderr).strip()[:80], flush=True)

        c = Conn()
        c.send(STREAM_OPEN)
        feats = c.recv_until("stream:features")
        log("starttls_required: <required/> advertised",
            "<required" in feats, feats[:400])
        log("starttls_required: mechanisms withheld on plaintext",
            "<mechanism>" not in feats, feats[:260])

        plain_auth(c, "andi", "secret")
        r = c.recv_until("policy-violation", timeout=8)
        log("starttls_required: plaintext PLAIN auth rejected (policy-violation)",
            "policy-violation" in r, r[:260])
        c.close()

        # STARTTLS upgrade, then auth works.
        c = Conn()
        c.send(STREAM_OPEN)
        c.recv_until("stream:features")
        c.send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        r = c.recv_until("proceed", timeout=8)
        log("starttls_required: <proceed/>", "proceed" in r, r[:160])
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        c.s = ctx.wrap_socket(c.s, server_hostname="localhost")
        c.buf = b""
        c.send(STREAM_OPEN)
        feats = c.recv_until("stream:features")
        log("starttls_required: mechanisms offered after TLS",
            "<mechanism>PLAIN</mechanism>" in feats, feats[:260])
        plain_auth(c, "andi", "secret")
        r = c.recv_until("success", timeout=8)
        log("starttls_required: PLAIN auth succeeds over TLS", "<success" in r, r[:160])
        r = bind(c, "tls1")
        log("starttls_required: bind over TLS", "<jid>" in r, r[:200])
        c.close()
        server.stop()

        # ---------- Phase B: auth_method: anonymous ----------
        text = original.decode().replace("auth_method: mnesia", "auth_method: anonymous")
        assert "auth_method: anonymous" in text
        with open(YML, "w") as f:
            f.write(text)
        assert server.start(), "server did not start (anonymous)"

        c = Conn()
        c.send(STREAM_OPEN)
        c.recv_until("stream:features")
        plain_auth(c, "tamuacak123", "passwordbebas")
        r = c.recv_until("success", timeout=8)
        log("anonymous: never-registered user logs in with any password",
            "<success" in r, r[:200])
        r = bind(c, "anon1")
        log("anonymous: bind works for guest", "tamuacak123@localhost" in r, r[:220])
        c.send("<iq type='get' id='p1' to='localhost'><ping xmlns='urn:xmpp:ping'/></iq>")
        r = c.recv_until("p1", timeout=8)
        log("anonymous: guest session is fully usable (ping answered)",
            "type='result'" in r, r[:200])
        c.close()
        server.stop()
    finally:
        server.stop()
        with open(YML, "wb") as f:
            f.write(original)

    passed = sum(1 for _, ok in results if ok)
    print(f"SUMMARY: {passed}/{len(results)} passed")
    return 0 if passed == len(results) and results else 1

if __name__ == "__main__":
    sys.exit(main())
