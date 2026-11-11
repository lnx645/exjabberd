#!/usr/bin/env python3
"""slixmpp end-to-end leg for Fase 3 S2S: two real slixmpp clients on
two real nodes (andi@a.localhost via 127.0.0.1:5222, budi@b.localhost
via 127.0.0.1:5223) exchange a message and a reply across the
federated link, plus directed presence.

Usage: <venv>/bin/python test_s2s_slix.py   (nodes must be running)
"""
import asyncio, ssl, sys
import slixmpp

# Self-signed dev certificates (priv/ssl); never verify them in tests.
NO_VERIFY_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
NO_VERIFY_CTX.check_hostname = False
NO_VERIFY_CTX.verify_mode = ssl.CERT_NONE

RESULTS = []
def log(name, ok, detail=""):
    RESULTS.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail}", flush=True)

class Client(slixmpp.ClientXMPP):
    def __init__(self, jid, pw, box, presence_box):
        super().__init__(jid, pw)
        self.box = box
        self.presence_box = presence_box
        self.got_message = asyncio.Event()
        self.got_presence = asyncio.Event()
        self.add_event_handler("session_start", self.on_start)
        self.add_event_handler("presence_available", self.on_presence)
        self.add_event_handler("message", self.on_message)

    async def on_start(self, event):
        self.send_presence()

    def on_presence(self, pres):
        if pres["from"].bare != self.boundjid.bare:
            self.presence_box.append(str(pres["from"]))
            self.got_presence.set()

    def on_message(self, msg):
        if msg["type"] in ("chat", "normal"):
            self.box.append(msg["body"])
            self.got_message.set()

async def main():
    andi_box, budi_box, andi_pres, budi_pres = [], [], [], []
    andi = Client("andi@a.localhost/slix", "secret", andi_box, andi_pres)
    budi = Client("budi@b.localhost/slix", "secret", budi_box, budi_pres)
    andi.ssl_context = NO_VERIFY_CTX
    budi.ssl_context = NO_VERIFY_CTX
    # Plain TCP for this leg (STARTTLS over S2S is proven by the raw
    # probe); mirrors audit_slix_test.py.
    andi.use_tls = False
    budi.use_tls = False
    andi.force_starttls = False
    budi.force_starttls = False
    # slixmpp >= 1.8 has no ClientXMPP.process(): connect() already
    # runs the stream as a background asyncio task.
    await asyncio.wait_for(andi.connect("127.0.0.1", 5222), timeout=10)
    await asyncio.wait_for(budi.connect("127.0.0.1", 5223), timeout=10)
    await asyncio.sleep(2)
    if not andi.is_connected() or not budi.is_connected():
        log("slix: both clients connected", False,
            f"andi={andi.is_connected()} budi={budi.is_connected()}")
        return
    log("slix: both clients connected", True)

    andi.send_message(mto="budi@b.localhost", mbody="hello-slix-s2s", mtype="chat")
    try:
        await asyncio.wait_for(budi.got_message.wait(), timeout=12)
        log("slix: andi@a -> budi@b message delivered",
            budi_box == ["hello-slix-s2s"], str(budi_box))
    except asyncio.TimeoutError:
        log("slix: andi@a -> budi@b message delivered", False, "timeout")

    budi.got_message.clear()
    budi.send_message(mto="andi@a.localhost", mbody="reply-slix-s2s", mtype="chat")
    try:
        await asyncio.wait_for(andi.got_message.wait(), timeout=12)
        log("slix: budi@b -> andi@a reply delivered",
            andi_box == ["reply-slix-s2s"], str(andi_box))
    except asyncio.TimeoutError:
        log("slix: budi@b -> andi@a reply delivered", False, "timeout")

    # Directed presence andi -> budi (budi already got andi's initial
    # broadcast presence; clear and re-send directed).
    budi.got_presence.clear()
    andi.send_presence(pto="budi@b.localhost")
    try:
        await asyncio.wait_for(budi.got_presence.wait(), timeout=10)
        log("slix: directed presence andi@a -> budi@b", True, str(budi_pres))
    except asyncio.TimeoutError:
        log("slix: directed presence andi@a -> budi@b", False, "timeout")

    andi.disconnect()
    budi.disconnect()
    await asyncio.sleep(1)

asyncio.run(main())
passed = sum(1 for _, ok in RESULTS if ok)
print(f"\n{passed}/{len(RESULTS)} checks passed")
sys.exit(0 if passed == len(RESULTS) else 1)
