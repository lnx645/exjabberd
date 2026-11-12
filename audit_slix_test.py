#!/usr/bin/env python3
"""Independent slixmpp client test against exjabberd on 127.0.0.1:5222.
Two real XMPP clients: login (PLAIN), roster, presence, 1-1 message.
Usage: <venv>/bin/python audit_slix_test.py
Test users (andi/budi/carol, password "secret") are created via RPC
when missing, so the probe works on a fresh clone too.
"""
import asyncio, ssl, sys, os, socket, subprocess
import slixmpp

# The server uses a self-signed dev certificate (priv/ssl, generated on
# first use). A test client must not verify it against the system CA
# store — production deployments use a real certificate instead.
NO_VERIFY_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
NO_VERIFY_CTX.check_hostname = False
NO_VERIFY_CTX.verify_mode = ssl.CERT_NONE

RESULTS = []
def log(name, ok, detail=""):
    RESULTS.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail}", flush=True)

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

class Client(slixmpp.ClientXMPP):
    def __init__(self, jid, pw, peer_box):
        super().__init__(jid, pw)
        self.peer_box = peer_box
        self.got_presence = asyncio.Event()
        self.got_message = asyncio.Event()
        self.roster_items = None
        self.add_event_handler("session_start", self.on_start)
        self.add_event_handler("presence_available", self.on_presence)
        self.add_event_handler("message", self.on_message)
        self.expect_disconnect = False
        self.add_event_handler("failed_auth", lambda e: log(f"{jid}: auth failed event", False, str(e)))
        self.add_event_handler("disconnected", lambda e: None if self.expect_disconnect else log(f"{jid}: disconnected", False, str(e)))

    async def on_start(self, event):
        try:
            self.send_presence()
            try:
                await asyncio.wait_for(self.get_roster(), timeout=6)
                items = list(self.client_roster.keys())
                self.roster_items = items
                log(f"{self.boundjid}: roster get", True, f"items={items}")
            except Exception as e:
                log(f"{self.boundjid}: roster get", False, f"timeout/error: {e}")
            # disco info on server
            try:
                iq = await asyncio.wait_for(
                    self.plugin["xep_0030"].get_info(jid="localhost"), timeout=6)
                log(f"{self.boundjid}: disco#info localhost", True, str(iq)[:200])
            except Exception as e:
                log(f"{self.boundjid}: disco#info localhost", False, f"timeout/error: {e}")
            # ping server
            try:
                await asyncio.wait_for(self.plugin["xep_0199"].ping("localhost"), timeout=6)
                log(f"{self.boundjid}: XEP-0199 ping", True, "")
            except Exception as e:
                log(f"{self.boundjid}: XEP-0199 ping", False, f"timeout/error: {e}")
        except Exception as e:
            log(f"{self.boundjid}: session_start error", False, str(e))

    def on_presence(self, pres):
        if pres["from"].bare != self.boundjid.bare:
            self.got_presence.set()

    def on_message(self, msg):
        if msg["type"] in ("chat", "normal"):
            self.peer_box.append(msg["body"])
            self.got_message.set()

async def main():
    andi_box, budi_box = [], []
    andi = Client("andi@localhost/raw-slix", "secret", andi_box)
    budi = Client("budi@localhost/raw-slix", "secret", budi_box)
    andi.ssl_context = NO_VERIFY_CTX
    budi.ssl_context = NO_VERIFY_CTX
    andi.register_plugin("xep_0030")
    andi.register_plugin("xep_0199")
    budi.register_plugin("xep_0030")
    budi.register_plugin("xep_0199")
    # plain TCP, no TLS (server advertises none on the wire)
    andi.use_tls = False
    budi.use_tls = False
    andi.force_starttls = False
    budi.force_starttls = False
    try:
        await asyncio.wait_for(andi.connect("127.0.0.1", 5222), timeout=10)
        log("andi: TCP connect + stream", True, "")
    except Exception as e:
        log("andi: TCP connect + stream", False, str(e))
        return
    try:
        await asyncio.wait_for(budi.connect("127.0.0.1", 5222), timeout=10)
        log("budi: TCP connect + stream", True, "")
    except Exception as e:
        log("budi: TCP connect + stream", False, str(e))
        return
    # slixmpp >= 1.8 has no ClientXMPP.process(): connect() already runs
    # the stream as a background asyncio task.
    await asyncio.sleep(12)  # let session_start handlers run (roster/disco/ping)
    # presence delivery — 10 s, not 3: under load the peer's
    # session_start (roster/disco/ping) can still be running when this
    # wait starts, and 3 s flaked. A longer wait only delays a real
    # failure; the event is already set when presence arrived early.
    try:
        await asyncio.wait_for(budi.got_presence.wait(), timeout=10)
        log("presence andi -> budi (slixmpp)", True, "")
    except asyncio.TimeoutError:
        log("presence andi -> budi (slixmpp)", False, "no presence received in 10s")
    # 1-1 message
    andi.send_message(mto="budi@localhost", mbody="halo dari slixmpp", mtype="chat")
    try:
        await asyncio.wait_for(budi.got_message.wait(), timeout=10)
        log("message andi -> budi (slixmpp)", "halo dari slixmpp" in budi_box, f"box={budi_box}")
    except asyncio.TimeoutError:
        log("message andi -> budi (slixmpp)", False, "no message received in 10s")
    andi.expect_disconnect = True
    budi.expect_disconnect = True
    andi.disconnect()
    budi.disconnect()
    await asyncio.sleep(1)
    n = sum(1 for _, ok in RESULTS if ok)
    print(f"\nSUMMARY: {n}/{len(RESULTS)} passed")

ensure_users(["andi", "budi", "carol"])
asyncio.run(main())
