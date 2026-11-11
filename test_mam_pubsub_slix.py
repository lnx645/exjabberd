#!/usr/bin/env python3
"""slixmpp interop probe for XEP-0313 (MAM) and XEP-0060 (PubSub)
against exjabberd on 127.0.0.1:5222.

Proves a real XMPP client library (slixmpp 1.17, plugins xep_0313
and xep_0060) can use both features end to end — not just raw
sockets. Usage: <venv>/bin/python test_mam_pubsub_slix.py
"""
import asyncio, ssl, sys, subprocess, os, uuid, re

import slixmpp
from slixmpp.xmlstream import ET

NO_VERIFY_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
NO_VERIFY_CTX.check_hostname = False
NO_VERIFY_CTX.verify_mode = ssl.CERT_NONE

RUN = uuid.uuid4().hex[:8]
RESULTS = []

def log(name, ok, detail=""):
    RESULTS.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail}", flush=True)

def rpc_create(user):
    env = dict(os.environ)
    env["PATH"] = ("/home/hatch/workspace/.toolchain/otp-28.1/bin:"
                   "/home/hatch/workspace/.toolchain/elixir-1.19.7/bin:"
                   + env.get("PATH", ""))
    env["ELIXIR_ERL_OPTIONS"] = "+fnu"
    code = (f':rpc.call(:"exjabberd@htch-runtime", Exjabberd.Auth, '
            f':create_user, ["localhost", "{user}", "secret"]) |> IO.inspect()')
    r = subprocess.run(["elixir", "--sname", "probe", "-e", code],
                       capture_output=True, text=True, timeout=60, env=env)
    return ":ok" in (r.stdout + r.stderr)

class Client(slixmpp.ClientXMPP):
    def __init__(self, jid, pw):
        super().__init__(jid, pw)
        self.ready = asyncio.Event()
        self.events = []
        self.event_seen = asyncio.Event()
        self.add_event_handler("session_start", self.on_start)
        self.add_event_handler("pubsub_publish", self.on_pubsub_event)
        self.add_event_handler("message", self.on_message)
        self.expect_disconnect = False
        self.add_event_handler(
            "disconnected",
            lambda e: None if self.expect_disconnect
            else log(f"{jid}: disconnected", False, str(e)))

    async def on_start(self, event):
        self.send_presence()
        self.ready.set()

    def on_pubsub_event(self, msg):
        self.events.append(str(msg))
        self.event_seen.set()

    def on_message(self, msg):
        # PubSub event notifications also arrive as messages; record
        # any stanza carrying a pubsub event.
        if "pubsub#event" in str(msg):
            self.events.append(str(msg))
            self.event_seen.set()

async def main():
    andi_u, budi_u = f"slixandi{RUN}", f"slixbudi{RUN}"
    for u in (andi_u, budi_u):
        log(f"create user {u}", rpc_create(u))

    andi = Client(f"{andi_u}@localhost/slix", "secret")
    budi = Client(f"{budi_u}@localhost/slix", "secret")
    for c in (andi, budi):
        c.ssl_context = NO_VERIFY_CTX
        c.use_tls = False
        c.force_starttls = False
        c.register_plugin("xep_0030")
        c.register_plugin("xep_0313")
        c.register_plugin("xep_0060")

    await asyncio.wait_for(andi.connect("127.0.0.1", 5222), timeout=10)
    await asyncio.wait_for(budi.connect("127.0.0.1", 5222), timeout=10)
    await asyncio.wait_for(andi.ready.wait(), timeout=10)
    await asyncio.wait_for(budi.ready.wait(), timeout=10)
    await asyncio.sleep(1)
    tag = f"SLIX-{RUN}"
    service = "pubsub.localhost"

    # ---------- MAM via xep_0313 ----------
    andi.send_message(mto=f"{budi_u}@localhost", mbody=f"{tag} satu",
                      mtype="chat")
    await asyncio.sleep(0.5)
    andi.send_message(mto=f"{budi_u}@localhost", mbody=f"{tag} dua",
                      mtype="chat")
    await asyncio.sleep(1)
    try:
        iq = await asyncio.wait_for(
            budi.plugin["xep_0313"].retrieve(with_jid=f"{andi_u}@localhost"),
            timeout=8)
        results = iq["mam"]["results"]
        bodies = []
        for r in results:
            # The forwarded message body is easiest read from the
            # stanza XML itself.
            m = re.search(r"<body>([^<]*)</body>", str(r))
            bodies.append(m.group(1) if m else "?")
        log("slix mam retrieve returns both messages in order",
            bodies == [f"{tag} satu", f"{tag} dua"], f"bodies={bodies}")
        fin_ok = iq["type"] == "result"
        log("slix mam retrieve fin is iq result", fin_ok, str(iq)[:200])
    except Exception as e:
        log("slix mam retrieve", False, f"error: {e}")

    # ---------- PubSub via xep_0060 ----------
    node = f"slix-news-{RUN}"
    try:
        await asyncio.wait_for(
            andi.plugin["xep_0060"].create_node(service, node), timeout=6)
        log("slix pubsub create_node", True, "")
    except Exception as e:
        log("slix pubsub create_node", False, str(e))

    try:
        sub = await asyncio.wait_for(
            budi.plugin["xep_0060"].subscribe(service, node), timeout=6)
        log("slix pubsub subscribe",
            sub["pubsub"]["subscription"]["subscription"] == "subscribed",
            str(sub)[:250])
    except Exception as e:
        log("slix pubsub subscribe", False, str(e))

    budi.events.clear()
    budi.event_seen.clear()
    try:
        await asyncio.wait_for(
            andi.plugin["xep_0060"].publish(
                service, node, id="it1",
                payload=ET.fromstring(f"<entry>{tag} berita</entry>")),
            timeout=6)
        log("slix pubsub publish", True, "")
    except Exception as e:
        log("slix pubsub publish", False, str(e))
    try:
        await asyncio.wait_for(budi.event_seen.wait(), timeout=6)
        log("slix pubsub subscriber receives event",
            any(f"{tag} berita" in e for e in budi.events),
            budi.events[0][:300] if budi.events else "(none)")
    except Exception:
        log("slix pubsub subscriber receives event", False,
            f"events={budi.events}")

    try:
        items = await asyncio.wait_for(
            budi.plugin["xep_0060"].get_items(service, node), timeout=6)
        payloads = str(items["pubsub"]["items"])
        log("slix pubsub get_items returns the item",
            "it1" in payloads and f"{tag} berita" in payloads,
            payloads[:300])
    except Exception as e:
        log("slix pubsub get_items", False, str(e))

    try:
        await asyncio.wait_for(
            andi.plugin["xep_0060"].retract(service, node, "it1"),
            timeout=6)
        log("slix pubsub retract", True, "")
    except Exception as e:
        log("slix pubsub retract", False, str(e))

    try:
        await asyncio.wait_for(
            budi.plugin["xep_0060"].unsubscribe(service, node), timeout=6)
        log("slix pubsub unsubscribe", True, "")
    except Exception as e:
        log("slix pubsub unsubscribe", False, str(e))

    try:
        await asyncio.wait_for(
            andi.plugin["xep_0060"].delete_node(service, node), timeout=6)
        log("slix pubsub delete_node", True, "")
    except Exception as e:
        log("slix pubsub delete_node", False, str(e))

    andi.expect_disconnect = True
    budi.expect_disconnect = True
    andi.disconnect()
    budi.disconnect()
    await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
    failed = [n for n, ok in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} passed")
    sys.exit(1 if failed else 0)
