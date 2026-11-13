#!/usr/bin/env python3
"""Phase 16 live probe: the stateless / external auth backends
(`auth_method: jwt`, `oauth`, `external`).

Boots the real server three times, once per backend, and proves
each with real SASL PLAIN logins over raw sockets:

  JWT    — tokens minted in this probe (HS256): a valid token
           logs in; a token signed with the wrong secret, an
           expired token, a token whose `sub` is another user,
           an alg=none token and a malformed token all fail.
  OAuth  — a fixture RFC 7662 introspection endpoint (this
           probe's own HTTP server): the good token logs its user
           in; an inactive token and a token issued for another
           username fail; with the endpoint down, login fails
           closed.
  External — a fixture extauth script (ejabberd protocol,
           length-prefixed stdio): login OK / wrong password
           fails; user_exists, set_password, create_user
           (tryregister) and remove_user all take effect on the
           wire.

LDAP and PAM are NOT covered: no LDAP server exists in this
sandbox and PAM cannot be exercised meaningfully here — both
stay honest stubs (see docs/PARITY.md item 55).

Usage: /home/hatch/workspace/.venv-xmpp/bin/python test_auth_backends_phase16.py
Run from the repo directory. Requires epmd and a free port 5222.
"""
import base64
import hashlib
import hmac as hmac_mod
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.dirname(os.path.abspath(__file__))
YML = os.path.join(REPO, "exjabberd.yml")
HOST = "127.0.0.1"
PORT = 5222
OAUTH_PORT = 18099
RUN = os.urandom(4).hex()
NODE = f"exjabberd@{socket.gethostname()}"
JWT_SECRET = f"jwt-secret-{RUN}"

results = []


def log(name, ok, detail=""):
    results.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail}", flush=True)


def tool_env(extra=None):
    env = dict(os.environ)
    env["PATH"] = ("/home/hatch/workspace/.toolchain/otp-28.1/bin:"
                   "/home/hatch/workspace/.toolchain/elixir-1.19.7/bin:"
                   + env.get("PATH", ""))
    env["ELIXIR_ERL_OPTIONS"] = "+fnu"
    if extra:
        env.update(extra)
    return env


def port_open(port):
    try:
        with socket.create_connection((HOST, port), timeout=1):
            return True
    except OSError:
        return False


def rpc(code, timeout=60):
    expr = f':rpc.call(:"{NODE}", {code}) |> IO.inspect()'
    r = subprocess.run(["elixir", "--sname", f"probe-{RUN}", "-e", expr],
                       capture_output=True, text=True, timeout=timeout,
                       env=tool_env(), cwd=REPO)
    return r.stdout + r.stderr


class Server:
    def __init__(self):
        self.proc = None

    def start(self, env_extra, timeout=90):
        assert not port_open(PORT), "port 5222 is already in use -- stop the dev server first"
        env = tool_env(dict(env_extra, ELIXIR_ERL_OPTIONS="+fnu -sname exjabberd"))
        self.proc = subprocess.Popen(
            ["mix", "run", "--no-halt"], cwd=REPO, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if port_open(PORT):
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


# ---------------------------------------------------------------- XMPP wire
STREAM_OPEN = ("<?xml version='1.0'?><stream:stream to='localhost' "
               "xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")


class Conn:
    def __init__(self):
        self.s = socket.create_connection((HOST, PORT), timeout=10)
        self.s.settimeout(8)
        self.buf = b""

    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.s.sendall(data)

    def recv_until(self, needle, timeout=8):
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
        try:
            self.s.close()
        except OSError:
            pass


def login_plain(user, password):
    """SASL PLAIN over a raw socket. Returns True on <success/>."""
    c = Conn()
    try:
        c.send(STREAM_OPEN)
        c.recv_until("stream:features")
        b64 = base64.b64encode(f"\0{user}\0{password}".encode()).decode()
        c.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{b64}</auth>")
        r = c.recv_until("success", timeout=8)
        return "<success" in r
    except (OSError, socket.timeout):
        return False
    finally:
        c.close()


# ---------------------------------------------------------------- JWT mint
def b64url(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def mint_jwt(secret, claims, alg="HS256"):
    header = {"alg": alg, "typ": "JWT"}
    signing = f"{b64url(json.dumps(header))}.{b64url(json.dumps(claims))}"
    if alg == "none":
        return signing + "."
    sig = hmac_mod.new(secret.encode(), signing.encode(), hashlib.sha256).digest()
    return f"{signing}.{b64url(sig)}"


# ---------------------------------------------------------------- OAuth fixture
class IntrospectHandler(BaseHTTPRequestHandler):
    tokens = {}

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        token = body.split("token=", 1)[-1]
        answer = self.tokens.get(token, {"active": False})
        payload = json.dumps(answer).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


# ---------------------------------------------------------------- external fixture
EXTAUTH_SCRIPT = '''#!/usr/bin/env python3
import struct
import sys

users = {"extuser": "extpw"}


def read_exact(n):
    data = b""
    while len(data) < n:
        chunk = sys.stdin.buffer.read(n - len(data))
        if not chunk:
            sys.exit(0)
        data += chunk
    return data


while True:
    header = read_exact(2)
    (length,) = struct.unpack(">H", header)
    payload = read_exact(length).decode()
    parts = payload.split(":", 3)
    op = parts[0]
    ok = False
    if op == "auth" and len(parts) == 4:
        ok = users.get(parts[1]) == parts[3]
    elif op == "isuser" and len(parts) >= 2:
        ok = parts[1] in users
    elif op == "tryregister" and len(parts) == 4:
        if parts[1] not in users:
            users[parts[1]] = parts[3]
            ok = True
    elif op == "setpass" and len(parts) == 4:
        if parts[1] in users:
            users[parts[1]] = parts[3]
            ok = True
    elif op == "removeuser" and len(parts) >= 2:
        if parts[1] in users:
            del users[parts[1]]
            ok = True
    reply = b"1" if ok else b"0"
    sys.stdout.buffer.write(struct.pack(">H", len(reply)) + reply)
    sys.stdout.buffer.flush()
'''


# ---------------------------------------------------------------- main
def main():
    tmpdir = tempfile.mkdtemp(prefix="exjabberd-phase16-backends-")
    with open(YML, "rb") as f:
        original_yml = f.read()

    def write_yml(auth_method):
        text = original_yml.decode()
        text = re.sub(r"^auth_method:.*$", f"auth_method: {auth_method}",
                      text, count=1, flags=re.M)
        with open(YML, "w") as f:
            f.write(text)

    server = Server()
    oauth_server = None
    try:
        now = int(time.time())

        # --- JWT ------------------------------------------------------------
        write_yml("jwt")
        assert server.start({"EXJABBERD_AUTH_JWT_SECRET": JWT_SECRET}), \
            "server did not start on jwt config"
        log("server boots with auth_method: jwt", True)
        user = f"jwtuser-{RUN}"
        good = mint_jwt(JWT_SECRET, {"sub": user, "exp": now + 3600})
        log("PLAIN login with valid JWT", login_plain(user, good))
        wrong_secret = mint_jwt("wrong-secret", {"sub": user, "exp": now + 3600})
        log("JWT signed with wrong secret fails", not login_plain(user, wrong_secret))
        expired = mint_jwt(JWT_SECRET, {"sub": user, "exp": now - 60})
        log("expired JWT fails", not login_plain(user, expired))
        other_sub = mint_jwt(JWT_SECRET, {"sub": "someone-else", "exp": now + 3600})
        log("JWT with another user's sub fails", not login_plain(user, other_sub))
        none_alg = mint_jwt(JWT_SECRET, {"sub": user, "exp": now + 3600}, alg="none")
        log("alg=none JWT fails", not login_plain(user, none_alg))
        log("malformed JWT fails", not login_plain(user, "not-a-jwt"))
        server.stop()

        # --- OAuth ----------------------------------------------------------
        IntrospectHandler.tokens = {
            "good-token": {"active": True, "username": "oauser",
                           "exp": now + 3600},
            "stale-token": {"active": True, "username": "oauser",
                            "exp": now - 60},
        }
        oauth_server = ThreadingHTTPServer((HOST, OAUTH_PORT), IntrospectHandler)
        threading.Thread(target=oauth_server.serve_forever, daemon=True).start()

        write_yml("oauth")
        assert server.start(
            {"EXJABBERD_AUTH_OAUTH_URL": f"http://{HOST}:{OAUTH_PORT}/introspect"}), \
            "server did not start on oauth config"
        log("server boots with auth_method: oauth", True)
        log("PLAIN login with active token", login_plain("oauser", "good-token"))
        log("inactive token fails", not login_plain("oauser", "bad-token"))
        log("token of another username fails", not login_plain("mallory", "good-token"))
        log("expired token fails", not login_plain("oauser", "stale-token"))
        oauth_server.shutdown()
        oauth_server.server_close()
        oauth_server = None
        log("login fails closed when introspection endpoint is down",
            not login_plain("oauser", "good-token"))
        server.stop()

        # --- External ---------------------------------------------------------
        script_path = os.path.join(tmpdir, "extauth_fixture.py")
        with open(script_path, "w") as f:
            f.write(EXTAUTH_SCRIPT)
        os.chmod(script_path, 0o755)

        write_yml("external")
        assert server.start({"EXJABBERD_AUTH_EXTERNAL_SCRIPT": script_path}), \
            "server did not start on external config"
        log("server boots with auth_method: external", True)
        log("PLAIN login via extauth script", login_plain("extuser", "extpw"))
        log("wrong password via extauth fails", not login_plain("extuser", "nope"))
        out = rpc('Exjabberd.Auth, :user_exists, ["localhost", "extuser"]')
        log("RPC user_exists (isuser) true", out.strip().startswith("true"))
        out = rpc('Exjabberd.Auth, :user_exists, ["localhost", "ghost"]')
        log("RPC user_exists (isuser) false", out.strip().startswith("false"))
        out = rpc('Exjabberd.Auth, :set_password, ["localhost", "extuser", "newpw"]')
        log("RPC set_password (setpass)", ":ok" in out)
        log("old password fails after setpass", not login_plain("extuser", "extpw"))
        log("new password works after setpass", login_plain("extuser", "newpw"))
        out = rpc('Exjabberd.Auth, :create_user, ["localhost", "newbie", "pw2"]')
        log("RPC create_user (tryregister)", ":ok" in out)
        log("registered user logs in", login_plain("newbie", "pw2"))
        out = rpc('Exjabberd.Auth, :remove_user, ["localhost", "newbie"]')
        log("RPC remove_user (removeuser)", ":ok" in out)
        log("removed user cannot log in", not login_plain("newbie", "pw2"))
        server.stop()
    finally:
        try:
            server.stop()
        except Exception:
            pass
        if oauth_server is not None:
            oauth_server.shutdown()
            oauth_server.server_close()
        with open(YML, "wb") as f:
            f.write(original_yml)

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed"
          + (f"; FAILED: {failed}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
