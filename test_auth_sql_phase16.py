#!/usr/bin/env python3
"""Phase 16 live probe: SQL auth backend (`auth_method: sql`,
PostgreSQL).

Boots a REAL PostgreSQL 16 (the embedded binaries staged from
~/.embedded-postgres-go, run as user `nobody`, SCRAM-SHA-256
password auth) and the real server with `auth_method: sql`, then
proves with real XMPP clients over raw sockets:

  1. create user (RPC) -> SASL PLAIN login OK, SASL SCRAM-SHA-256
     login OK (manual RFC 5802 client), wrong password fails,
     one slixmpp client login
  2. the PostgreSQL `passwd` row holds SCRAM verifier data only
     (16-byte salt, 4096 iterations, 32-byte keys, never the
     password) — checked through the backend itself
  3. stop server (SIGTERM) -> start again -> login still OK
     (PostgreSQL persists accounts across restarts)
  4. set_password -> old password fails, new password works
  5. remove_user -> login fails
  6. migration: back on Mnesia, create a user,
     `mix exjabberd.auth.migrate --from mnesia --to sql`, back on
     SQL -> the migrated user logs in with the SAME password

Usage: /home/hatch/workspace/.venv-xmpp/bin/python test_auth_sql_phase16.py
Run from the repo directory. Requires the embedded PostgreSQL
binaries, `su` (PostgreSQL refuses to run as root), epmd and a
free port 5222.
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
PG_PORT = 55434
RUN = os.urandom(4).hex()
NODE = f"exjabberd@{socket.gethostname()}"
PG_SRC = os.path.expanduser("~/.embedded-postgres-go/extracted")
PG_PASSWORD = f"pgpass-{RUN}"

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


def sql_env():
    return {
        "EXJABBERD_AUTH_SQL_SERVER": "postgres",
        "EXJABBERD_AUTH_SQL_HOST": "127.0.0.1",
        "EXJABBERD_AUTH_SQL_PORT": str(PG_PORT),
        "EXJABBERD_AUTH_SQL_DATABASE": "postgres",
        "EXJABBERD_AUTH_SQL_USERNAME": "exjabberd",
        "EXJABBERD_AUTH_SQL_PASSWORD": PG_PASSWORD,
    }


def port_open(port):
    try:
        with socket.create_connection((HOST, port), timeout=1):
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


class PgServer:
    """Embedded PostgreSQL 16 run as `nobody` (it refuses root).

    The binaries run from their canonical location (made
    world-executable by the probe); only the data dir, socket dir
    and password file are staged in a small /tmp scratch dir owned
    by `nobody` — the workspace mount forbids chown, and /tmp is a
    small tmpfs, so nothing large may be copied anywhere.
    """

    def __init__(self, tmpdir):
        self.tmpdir = tmpdir
        self.dist = PG_SRC
        self.data = os.path.join(tmpdir, "pgdata")
        self.sockdir = os.path.join(tmpdir, "pgsock")
        self.started = False

    def _su(self, cmd, timeout=120):
        return subprocess.run(["su", "-s", "/bin/bash", "nobody", "-c", cmd],
                              capture_output=True, text=True, timeout=timeout)

    def start(self):
        if not os.path.isdir(PG_SRC):
            print(f"SETUP FAILED: embedded PostgreSQL not found at {PG_SRC}",
                  file=sys.stderr)
            return False
        # nobody must be able to traverse + execute the binaries.
        subprocess.run(["chmod", "755", os.path.expanduser("~")],
                       capture_output=True)
        subprocess.run(["chmod", "-R", "a+rX",
                        os.path.expanduser("~/.embedded-postgres-go")],
                       capture_output=True)
        os.makedirs(self.sockdir, exist_ok=True)
        pwfile = os.path.join(self.tmpdir, "pwfile")
        with open(pwfile, "w") as f:
            f.write(PG_PASSWORD + "\n")
        for path in (self.tmpdir, self.sockdir, pwfile):
            subprocess.run(["chown", "-R", "nobody:nogroup", path],
                           check=True, timeout=60)
        bin_dir = os.path.join(self.dist, "bin")
        r = self._su(f"{bin_dir}/initdb -D {self.data} -U exjabberd "
                     f"--auth=scram-sha-256 --pwfile={pwfile} "
                     f"--locale=C --encoding=UTF8")
        if r.returncode != 0:
            print("initdb failed:", r.stdout, r.stderr, file=sys.stderr)
            return False
        r = self._su(f"{bin_dir}/pg_ctl -D {self.data} "
                     f"-l {self.tmpdir}/pg.log "
                     f"-o '-p {PG_PORT} -k {self.sockdir} -h 127.0.0.1' -w start")
        if r.returncode != 0:
            print("pg_ctl start failed:", r.stdout, r.stderr, file=sys.stderr)
            return False
        self.started = True
        deadline = time.time() + 30
        while time.time() < deadline:
            if port_open(PG_PORT):
                return True
            time.sleep(0.5)
        return False

    def stop(self):
        if self.started:
            bin_dir = os.path.join(self.dist, "bin")
            self._su(f"{bin_dir}/pg_ctl -D {self.data} -m fast -w stop",
                     timeout=60)
            self.started = False


class Server:
    def __init__(self):
        self.proc = None

    def start(self, timeout=90):
        assert not port_open(PORT), "port 5222 is already in use -- stop the dev server first"
        self.proc = subprocess.Popen(
            ["mix", "run", "--no-halt"],
            cwd=REPO,
            env=tool_env(dict(sql_env(), ELIXIR_ERL_OPTIONS="+fnu -sname exjabberd")),
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


def scram_client_final(password, server_first, client_first_bare, client_nonce, server_nonce):
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


AUDIT_EXS = """
[node, user] = System.argv()

code = \"\"\"
{:ok, c} = Exjabberd.Auth.Sql.get_scram("localhost", #{user})
{byte_size(c.salt), c.iterations, byte_size(c.stored_key),
 byte_size(c.server_key), c.stored_key == "secret"}
\"\"\"

result = :rpc.call(String.to_atom(node), Code, :eval_string, [code])
IO.inspect(result)
"""


def audit_verifier(user, tmpdir):
    """Ask the running server's SQL backend what it stored."""
    path = os.path.join(tmpdir, "audit.exs")
    with open(path, "w") as f:
        f.write(AUDIT_EXS.replace("#{user}", f'"{user}"'))
    r = subprocess.run(["elixir", "--sname", f"audit-{RUN}", path, NODE, user],
                       capture_output=True, text=True, timeout=60,
                       env=tool_env(), cwd=REPO)
    out = r.stdout + r.stderr
    m = re.search(r"\{(\d+), (\d+), (\d+), (\d+), (true|false)\}", out)
    if not m:
        return None
    return tuple(int(m.group(i)) for i in range(1, 5)) + (m.group(5) == "true",)


# ---------------------------------------------------------------- main
def main():
    # Small scratch only (PG data dir); the binaries run in place.
    tmpdir = tempfile.mkdtemp(prefix="exjabberd-phase16-")
    with open(YML, "rb") as f:
        original_yml = f.read()

    def write_yml(auth_method):
        text = original_yml.decode()
        text = re.sub(r"^auth_method:.*$", f"auth_method: {auth_method}",
                      text, count=1, flags=re.M)
        with open(YML, "w") as f:
            f.write(text)

    pg = PgServer(tmpdir)
    server = Server()
    try:
        assert pg.start(), "PostgreSQL did not start"
        log("embedded PostgreSQL 16 up (SCRAM auth)", True)

        # --- phase A: SQL backend --------------------------------------
        write_yml("sql")
        assert server.start(), "server did not start on sql config"
        log("server boots with auth_method: sql", True)

        user = f"p16user-{RUN}"
        assert rpc_create(user, "secret"), "RPC create_user failed"
        log("RPC create_user on sql backend", True)
        log("PLAIN login (sql)", login_plain(user, "secret"))
        log("SCRAM-SHA-256 login (sql)", login_scram(user, "secret"))
        log("PLAIN login with wrong password fails", not login_plain(user, "wrong"))
        log("slixmpp client login (sql)", slix_login(user, "secret"))

        audit = audit_verifier(user, tmpdir)
        log("PG row holds SCRAM verifier (16B salt, 4096 iters, 32B keys, not the password)",
            audit == (16, 4096, 32, 32, False), f"audit={audit}")

        # --- restart: accounts must survive -----------------------------
        server.stop()
        assert server.start(), "server did not restart"
        log("PLAIN login after server restart", login_plain(user, "secret"))
        log("SCRAM login after server restart", login_scram(user, "secret"))

        # --- password rotation + delete ---------------------------------
        out = rpc(f'Exjabberd.Auth, :set_password, ["localhost", "{user}", "newsecret"]')
        log("RPC set_password", ":ok" in out)
        log("old password fails after rotation", not login_plain(user, "secret"))
        log("new password works after rotation", login_plain(user, "newsecret"))
        out = rpc(f'Exjabberd.Auth, :remove_user, ["localhost", "{user}"]')
        log("RPC remove_user", ":ok" in out)
        log("login fails after remove_user", not login_plain(user, "newsecret"))

        # --- phase B: migration Mnesia -> SQL ----------------------------
        server.stop()
        with open(YML, "wb") as f:
            f.write(original_yml)
        assert server.start(), "server did not start on mnesia config"
        mig = f"p16mig-{RUN}"
        assert rpc_create(mig, "secret"), "RPC create_user on mnesia failed"
        rpc(":mnesia, :dump_log, []")
        server.stop()

        r = subprocess.run(["mix", "exjabberd.auth.migrate",
                            "--from", "mnesia", "--to", "sql"],
                           capture_output=True, text=True, timeout=120,
                           env=tool_env(sql_env()), cwd=REPO)
        out = r.stdout + r.stderr
        migrated = "migrated" in out and "user(s) mnesia -> sql" in out
        log("mix exjabberd.auth.migrate mnesia -> sql", migrated,
            out.strip().splitlines()[-1] if out.strip() else "")

        write_yml("sql")
        assert server.start(), "server did not restart on sql config"
        log("migrated user logs in on sql, same password",
            login_plain(mig, "secret"))
        log("migrated user SCRAM login on sql",
            login_scram(mig, "secret"))

        # Cleanup: remove the Mnesia original so the dev schema stays clean.
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
        try:
            pg.stop()
        except Exception:
            pass
        with open(YML, "wb") as f:
            f.write(original_yml)

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed"
          + (f"; FAILED: {failed}" if failed else ""))
    print(f"probe tmpdir (kept for inspection): {tmpdir}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
