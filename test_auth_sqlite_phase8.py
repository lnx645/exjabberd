#!/usr/bin/env python3
"""Phase 8 live probe: SQLite auth backend (`auth_method: sqlite`).

Boots the real server itself (swapping exjabberd.yml to sqlite with a
throwaway database file, restored afterwards), then proves with real
XMPP clients over raw sockets:

  1. create user (RPC) -> SASL PLAIN login OK, SASL SCRAM-SHA-256
     login OK (manual RFC 5802 client), wrong password fails
  2. stop server (SIGTERM) -> start again -> PLAIN login still OK
     (SQLite file persists accounts across restarts)
  3. set_password -> old password fails, new password works
  4. remove_user -> login fails
  5. migration: back on Mnesia, create a user, `mix
     exjabberd.auth.migrate --from mnesia --to sqlite`, back on
     SQLite -> the migrated user logs in with the SAME password
  6. one slixmpp client login (real library client, PLAIN)

Usage: /home/hatch/workspace/.venv-xmpp/bin/python test_auth_sqlite_phase8.py
Run from the repo directory. Requires epmd (started automatically
when needed by `mix run --no-halt` is NOT the case -- start it with
`epmd -daemon` if distribution fails) and a free port 5222.
"""
import asyncio
import base64
import hashlib
import hmac as hmac_mod
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.abspath(__file__))
YML = os.path.join(REPO, "exjabberd.yml")
HOST = "127.0.0.1"
PORT = 5222
RUN = os.urandom(4).hex()
NODE = f"exjabberd@{socket.gethostname()}"

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


def port_open():
    try:
        with socket.create_connection((HOST, PORT), timeout=1):
            return True
    except OSError:
        return False


def rpc(code, timeout=60):
    """Run Elixir code against the running node via :rpc."""
    expr = f':rpc.call(:"{NODE}", {code}) |> IO.inspect()'
    r = subprocess.run(["elixir", "--sname", f"probe-{RUN}", "-e", expr],
                       capture_output=True, text=True, timeout=timeout,
                       env=tool_env(), cwd=REPO)
    return r.stdout + r.stderr


def rpc_create(user, password):
    out = rpc(f'Exjabberd.Auth, :create_user, ["localhost", "{user}", "{password}"]')
    return ":ok" in out


class Server:
    def __init__(self):
        self.proc = None

    def start(self, timeout=90):
        assert not port_open(), "port 5222 is already in use -- stop the dev server first"
        self.proc = subprocess.Popen(
            ["mix", "run", "--no-halt"],
            cwd=REPO, env=tool_env({"ELIXIR_ERL_OPTIONS": "+fnu -sname exjabberd"}),
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
            # SIGTERM: the VM stops the applications (Mnesia dumps its
            # log), so accounts created over RPC survive. SIGKILL
            # would lose the not-yet-flushed Mnesia transaction log.
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


def scram_client_final(password, server_first, client_first_bare, client_nonce, server_nonce):
    # server_first: "r=<nonce>,s=<salt-b64>,i=<iters>"
    attrs = dict(p.split("=", 1) for p in server_first.split(","))
    salt = base64.b64decode(attrs["s"])
    iters = int(attrs["i"])
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters, 32)
    client_key = hmac_mod.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    channel = base64.b64encode(b"n,,").decode()
    final_wo = f"c={channel},r={server_nonce}"
    auth_message = f"{client_first_bare},{server_first},{final_wo}"
    signature = hmac_mod.new(stored_key, auth_message.encode(), hashlib.sha256).digest()
    proof = bytes(a ^ b for a, b in zip(client_key, signature))
    return f"{final_wo},p={base64.b64encode(proof).decode()}"


def login_scram(user, password):
    """SASL SCRAM-SHA-256 over a raw socket (manual RFC 5802 client)."""
    c = Conn()
    try:
        c.send(STREAM_OPEN)
        c.recv_until("stream:features")
        nonce = base64.b64encode(os.urandom(12)).decode()
        bare = f"n={user},r={nonce}"
        first = base64.b64encode(f"n,,{bare}".encode()).decode()
        c.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-256'>{first}</auth>")
        r = c.recv_until("challenge")
        m = re.search(r"<challenge[^>]*>([^<]+)</challenge>", r)
        if not m:
            return False
        server_first = base64.b64decode(m.group(1)).decode()
        attrs = dict(p.split("=", 1) for p in server_first.split(","))
        final = scram_client_final(password, server_first, bare, nonce, attrs["r"])
        c.send(f"<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{base64.b64encode(final.encode()).decode()}</response>")
        r2 = c.recv_until("success")
        return "<success" in r2
    except (OSError, socket.timeout):
        return False
    finally:
        c.close()


def slix_login(user, password):
    """One real library client (slixmpp) logging in with PLAIN."""
    import ssl

    import slixmpp

    # The server uses a self-signed dev certificate (priv/ssl); a
    # test client must not verify it against the system CA store.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    class Client(slixmpp.ClientXMPP):
        def __init__(self, jid, pw):
            super().__init__(jid, pw)
            self.ok = asyncio.Event()
            self.add_event_handler("session_start", self.on_start)

        async def on_start(self, _event):
            self.ok.set()

    async def run():
        xmpp = Client(f"{user}@localhost", password)
        xmpp.ssl_context = ctx
        xmpp.use_tls = False
        xmpp.force_starttls = False
        try:
            await asyncio.wait_for(xmpp.connect(HOST, PORT), timeout=10)
        except Exception:
            return False
        try:
            await asyncio.wait_for(xmpp.ok.wait(), timeout=10)
            return True
        except asyncio.TimeoutError:
            return False
        finally:
            xmpp.expect_disconnect = True
            try:
                xmpp.disconnect()
            except Exception:
                pass
            await asyncio.sleep(0.5)

    return asyncio.run(run())


# ---------------------------------------------------------------- main
def main():
    tmpdir = tempfile.mkdtemp(prefix="exjabberd-phase8-")
    db_path = os.path.join(tmpdir, "auth.sqlite3")
    with open(YML, "rb") as f:
        original_yml = f.read()

    def write_yml(auth_method):
        text = original_yml.decode()
        text = re.sub(r"^auth_method:.*$", f"auth_method: {auth_method}",
                      text, count=1, flags=re.M)
        text = re.sub(r'path: "priv/auth\.sqlite3"',
                      f'path: "{db_path}"', text, count=1)
        with open(YML, "w") as f:
            f.write(text)

    server = Server()
    try:
        # --- phase A: SQLite backend ----------------------------------
        write_yml("sqlite")
        assert server.start(), "server did not start on sqlite config"
        log("server boots with auth_method: sqlite", True)

        user = f"p8user-{RUN}"
        assert rpc_create(user, "secret"), "RPC create_user failed"
        log("RPC create_user on sqlite backend", True)
        log("PLAIN login (sqlite)", login_plain(user, "secret"))
        log("SCRAM-SHA-256 login (sqlite)", login_scram(user, "secret"))
        log("PLAIN login with wrong password fails", not login_plain(user, "wrong"))
        log("slixmpp client login (sqlite)", slix_login(user, "secret"))

        # SQLite file really holds the account (same verifier format).
        out = subprocess.run(["sqlite3", db_path,
                              "SELECT user, iterations, length(salt), length(stored_key), "
                              "length(server_key), typeof(stored_key) FROM passwd;"],
                             capture_output=True, text=True, timeout=10)
        row_ok = (f"{user}|4096|16|32|32|blob" in out.stdout)
        log("sqlite file holds SCRAM verifier (4096 iters, 16/32/32 blob)",
            row_ok, out.stdout.strip())

        # --- restart: accounts must survive ---------------------------
        server.stop()
        assert server.start(), "server did not restart"
        log("PLAIN login after server restart", login_plain(user, "secret"))
        log("SCRAM login after server restart", login_scram(user, "secret"))

        # --- password rotation + delete -------------------------------
        out = rpc(f'Exjabberd.Auth, :set_password, ["localhost", "{user}", "newsecret"]')
        log("RPC set_password", ":ok" in out)
        log("old password fails after rotation", not login_plain(user, "secret"))
        log("new password works after rotation", login_plain(user, "newsecret"))
        out = rpc(f'Exjabberd.Auth, :remove_user, ["localhost", "{user}"]')
        log("RPC remove_user", ":ok" in out)
        log("login fails after remove_user", not login_plain(user, "newsecret"))

        # --- phase B: migration Mnesia -> SQLite ----------------------
        server.stop()
        with open(YML, "wb") as f:
            f.write(original_yml)
        assert server.start(), "server did not start on mnesia config"
        mig = f"p8mig-{RUN}"
        assert rpc_create(mig, "secret"), "RPC create_user on mnesia failed"
        # Mnesia quirk: an abruptly-halted VM can lose the not yet
        # flushed transaction log -- dump it so the account is really
        # on disk before the server stops.
        rpc(":mnesia, :dump_log, []")
        server.stop()

        r = subprocess.run(["mix", "exjabberd.auth.migrate",
                            "--from", "mnesia", "--to", "sqlite",
                            "--path", db_path],
                           capture_output=True, text=True, timeout=120,
                           env=tool_env(), cwd=REPO)
        out = r.stdout + r.stderr
        # Count-agnostic: the dev Mnesia schema may hold other users
        # too; what matters is that the migration ran and the mig
        # user landed in the SQLite file.
        migrated = "migrated" in out and "user(s) mnesia -> sqlite" in out
        log("mix exjabberd.auth.migrate mnesia -> sqlite", migrated,
            out.strip().splitlines()[-1] if out.strip() else "")
        row = subprocess.run(["sqlite3", db_path,
                              f"SELECT user FROM passwd WHERE user='{mig}';"],
                             capture_output=True, text=True, timeout=10)
        log("migrated user row exists in sqlite file", mig in row.stdout, row.stdout.strip())

        write_yml("sqlite")
        assert server.start(), "server did not restart on sqlite config"
        log("migrated user logs in on sqlite, same password",
            login_plain(mig, "secret"))
        log("migrated user SCRAM login on sqlite",
            login_scram(mig, "secret"))

        # Cleanup: the migrated user lives in the throwaway DB only;
        # remove the Mnesia original so the dev schema stays clean.
        server.stop()
        with open(YML, "wb") as f:
            f.write(original_yml)
        assert server.start(), "server did not restart for cleanup"
        rpc(f'Exjabberd.Auth, :remove_user, ["localhost", "{mig}"]')
        rpc(":mnesia, :dump_log, []")
        server.stop()
        log("cleanup: migrated user removed from Mnesia", True)
    finally:
        try:
            server.stop()
        except Exception:
            pass
        with open(YML, "wb") as f:
            f.write(original_yml)

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed"
          + (f"; FAILED: {failed}" if failed else ""))
    print(f"probe sqlite file (kept for inspection): {db_path}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
