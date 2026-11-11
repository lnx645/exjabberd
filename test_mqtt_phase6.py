#!/usr/bin/env python3
"""Phase 6 live probe: MQTT v3.1.1 broker on 1883 + MQTT <-> XMPP
PubSub bridge, against a running dev server (127.0.0.1:5222 + 1883).

Usage: start the server first
(ELIXIR_ERL_OPTIONS="+fnu -sname exjabberd" mix run --no-halt),
then: <venv>/bin/python test_mqtt_phase6.py

Real clients: paho-mqtt 2.x for the broker behaviour, raw TCP frames
for PINGREQ / bad protocol version / oversize payload / keep-alive
timeout, and slixmpp (xep_0060) for the bridge's XMPP side.
"""
import asyncio
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid

import paho.mqtt.client as mqtt
import slixmpp
from slixmpp.xmlstream import ET

HOST = "127.0.0.1"
XMPP_PORT = 5222
MQTT_PORT = 1883
RUN = uuid.uuid4().hex[:8]
results = []

NO_VERIFY_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
NO_VERIFY_CTX.check_hostname = False
NO_VERIFY_CTX.verify_mode = ssl.CERT_NONE


def log(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail}", flush=True)


def rpc_create(user, password="secret"):
    code = (
        f':rpc.call(:"exjabberd@htch-runtime", Exjabberd.Auth, '
        f':create_user, ["localhost", "{user}", "{password}"]) |> IO.inspect()'
    )
    env = dict(os.environ)
    env["PATH"] = ("/home/hatch/workspace/.toolchain/otp-28.1/bin:"
                   "/home/hatch/workspace/.toolchain/elixir-1.19.7/bin:"
                   + env.get("PATH", ""))
    env["ELIXIR_ERL_OPTIONS"] = "+fnu"
    r = subprocess.run(["elixir", "--sname", "probe", "-e", code],
                       capture_output=True, text=True, timeout=60, env=env)
    return ":ok" in (r.stdout + r.stderr)


# ---------------------------------------------------------------- paho helpers
class Collector:
    """Collects (topic, payload, qos, retain) from a paho client."""

    def __init__(self, client_id, username=None, password=None, clean_session=True,
                 keepalive=60, will=None):
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1,
                                  client_id=client_id, clean_session=clean_session)
        if username is not None:
            self.client.username_pw_set(username, password)
        if will is not None:
            self.client.will_set(*will)
        self.msgs = []
        self.connected = threading.Event()
        self.disconnected = threading.Event()
        self.rc = None
        self.session_present = None
        self.sub_acked = threading.Event()
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message
        self.client.on_subscribe = lambda *a: self.sub_acked.set()
        self.keepalive = keepalive

    def _on_connect(self, client, userdata, flags, rc):
        self.rc = rc
        self.session_present = flags.get("session present", False)
        self.connected.set()

    def _on_disconnect(self, client, userdata, rc):
        self.disconnected.set()

    def _on_message(self, client, userdata, msg):
        self.msgs.append((msg.topic, msg.payload.decode(errors="replace"),
                          msg.qos, msg.retain))

    def connect(self, timeout=6):
        self.client.connect(HOST, MQTT_PORT, self.keepalive)
        self.client.loop_start()
        return self.connected.wait(timeout)

    def wait_msg(self, topic=None, payload=None, timeout=6):
        end = time.time() + timeout
        while time.time() < end:
            for m in list(self.msgs):
                if (topic is None or m[0] == topic) and (payload is None or m[1] == payload):
                    return m
            time.sleep(0.05)
        return None

    def close(self):
        try:
            self.client.disconnect()
        except Exception:
            pass
        try:
            self.client.loop_stop()
        except Exception:
            pass


def new_client(cid, **kw):
    return Collector(f"{cid}-{RUN}", **kw)


# ---------------------------------------------------------------- raw MQTT frames
def encode_remaining(n):
    out = b""
    while True:
        b = n % 128
        n //= 128
        if n > 0:
            b |= 128
        out += bytes([b])
        if n == 0:
            return out


def frame(type_flags, body):
    return bytes([type_flags]) + encode_remaining(len(body)) + body


def enc_str(s):
    b = s.encode() if isinstance(s, str) else s
    return len(b).to_bytes(2, "big") + b


def connect_frame(client_id, keepalive=60, username=None, password=None,
                  will_topic=None, will_msg=None, clean_session=True,
                  proto_level=4):
    flags = 0x02 if clean_session else 0x00
    if username is not None:
        flags |= 0x80
    if password is not None:
        flags |= 0x40
    if will_topic is not None:
        flags |= 0x04
    body = enc_str("MQTT") + bytes([proto_level, flags]) + keepalive.to_bytes(2, "big")
    body += enc_str(client_id)
    if will_topic is not None:
        body += enc_str(will_topic) + enc_str(will_msg or "")
    if username is not None:
        body += enc_str(username)
    if password is not None:
        body += enc_str(password)
    return frame(0x10, body)


def recv_exact(sock, n, timeout=6):
    sock.settimeout(timeout)
    data = b""
    try:
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


# ---------------------------------------------------------------- broker tests
def broker_tests():
    alice = f"mqttalice{RUN}"
    log(f"create user {alice}", rpc_create(alice))

    # 1. Anonymous CONNECT -> CONNACK rc 0.
    anon = new_client("anon")
    ok = anon.connect()
    log("anon CONNECT -> CONNACK rc 0", ok and anon.rc == 0, f"rc={anon.rc}")
    anon.close()

    # 2. Good auth (bare user, and user@host) -> rc 0.
    good = new_client("good", username=alice, password="secret")
    ok = good.connect()
    log("auth CONNECT (bare user) -> rc 0", ok and good.rc == 0, f"rc={good.rc}")
    good.close()

    good2 = new_client("good2", username=f"{alice}@localhost", password="secret")
    ok = good2.connect()
    log("auth CONNECT (user@host) -> rc 0", ok and good2.rc == 0, f"rc={good2.rc}")
    good2.close()

    # 3. Wrong password / unknown user -> CONNACK refused (rc 5).
    bad = new_client("bad", username=alice, password="wrong-password")
    ok = bad.connect()
    log("wrong password -> CONNACK rc 5", ok and bad.rc == 5, f"rc={bad.rc}")
    bad.close()

    ghost = new_client("ghost", username=f"nosuch{RUN}", password="secret")
    ok = ghost.connect()
    log("unknown user -> CONNACK rc 5", ok and ghost.rc == 5, f"rc={ghost.rc}")
    ghost.close()

    # 4. QoS 0, 1, 2 publish/subscribe, each with the right handshake.
    for qos in (0, 1, 2):
        sub = new_client(f"sub-q{qos}")
        pub = new_client(f"pub-q{qos}")
        assert sub.connect() and sub.rc == 0
        assert pub.connect() and pub.rc == 0
        sub.client.subscribe(f"q{qos}/t", qos)
        assert sub.sub_acked.wait(5)
        info = pub.client.publish(f"q{qos}/t", f"payload-q{qos}", qos=qos)
        if qos > 0:
            info.wait_for_publish(timeout=5)
        m = sub.wait_msg(topic=f"q{qos}/t", payload=f"payload-q{qos}")
        log(f"QoS {qos} publish -> subscriber receives",
            m is not None and m[2] == qos, f"got={m}")
        sub.close()
        pub.close()

    # 5. Retained: late subscriber receives the retained message.
    pub = new_client("pub-ret")
    assert pub.connect()
    pub.client.publish("ret/t", "retained-value", qos=1, retain=True).wait_for_publish(timeout=5)
    pub.close()
    time.sleep(0.3)
    late = new_client("late-ret")
    assert late.connect()
    late.client.subscribe("ret/t", 0)
    assert late.sub_acked.wait(5)
    m = late.wait_msg(topic="ret/t", payload="retained-value")
    log("retained message to late subscriber", m is not None and m[3] is True, f"got={m}")
    late.close()

    # Clearing retained with an empty payload: next subscriber gets nothing.
    pub = new_client("pub-ret-clear")
    assert pub.connect()
    pub.client.publish("ret/t", "", qos=0, retain=True)
    time.sleep(0.3)
    pub.close()
    late2 = new_client("late-ret2")
    assert late2.connect()
    late2.client.subscribe("ret/t", 0)
    assert late2.sub_acked.wait(5)
    m = late2.wait_msg(topic="ret/t", timeout=2)
    log("empty retained payload clears retained", m is None, f"got={m}")
    late2.close()

    # 6. Wildcards + and #.
    sub = new_client("sub-wild")
    assert sub.connect()
    sub.client.subscribe("wild/+/temp", 1)
    sub.client.subscribe("wild/#", 0)
    assert sub.sub_acked.wait(5)
    pub = new_client("pub-wild")
    assert pub.connect()
    pub.client.publish("wild/room1/temp", "22", qos=1).wait_for_publish(timeout=5)
    pub.client.publish("wild/room1/temp/deep", "deep", qos=0)
    pub.client.publish("other/temp", "nope", qos=0)
    time.sleep(0.5)
    topics = {m[0] for m in sub.msgs}
    log("wildcard + and # match correctly",
        "wild/room1/temp" in topics and "wild/room1/temp/deep" in topics
        and "other/temp" not in topics, f"topics={sorted(topics)}")
    sub.close()
    pub.close()

    # 7. Will: abrupt socket close publishes the Will message.
    watcher = new_client("will-watcher")
    assert watcher.connect()
    watcher.client.subscribe("will/topic", 1)
    assert watcher.sub_acked.wait(5)
    doomed = new_client("doomed", will=("will/topic", "doomed is gone", 1, False))
    assert doomed.connect()
    time.sleep(0.3)
    # Abrupt close: kill the socket without a DISCONNECT packet.
    sock = doomed.client.socket()
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()
    doomed.client.loop_stop()
    m = watcher.wait_msg(topic="will/topic", payload="doomed is gone")
    log("will message on abrupt disconnect", m is not None, f"got={m}")
    watcher.close()

    # Clean disconnect does NOT publish the will.
    watcher2 = new_client("will-watcher2")
    assert watcher2.connect()
    watcher2.client.subscribe("will/topic2", 1)
    assert watcher2.sub_acked.wait(5)
    polite = new_client("polite", will=("will/topic2", "should not appear", 1, False))
    assert polite.connect()
    time.sleep(0.2)
    polite.close()
    time.sleep(0.5)
    m = watcher2.wait_msg(topic="will/topic2", timeout=2)
    log("no will on clean DISCONNECT", m is None, f"got={m}")
    watcher2.close()

    # 8. Session takeover: second connection with the same id kills the first.
    first = new_client("takeover-id")
    assert first.connect() and first.rc == 0
    time.sleep(0.2)
    second = new_client("takeover-id")
    assert second.connect() and second.rc == 0
    gone = first.disconnected.wait(5)
    log("same client id takes over (first disconnected)", gone,
        f"first disconnected={gone}")
    second.close()
    first.close()

    # 9. Persistent session: QoS 1 queued while offline, replayed on reconnect.
    persist_id = f"persist-{RUN}"
    p1 = Collector(persist_id, clean_session=False)
    assert p1.connect() and p1.rc == 0
    p1.client.subscribe("persist/t", 1)
    assert p1.sub_acked.wait(5)
    p1.close()
    time.sleep(0.3)
    pub = new_client("pub-persist")
    assert pub.connect()
    pub.client.publish("persist/t", "queued-while-offline", qos=1).wait_for_publish(timeout=5)
    pub.close()
    p2 = Collector(persist_id, clean_session=False)
    assert p2.connect() and p2.rc == 0
    m = p2.wait_msg(topic="persist/t", payload="queued-while-offline")
    log("persistent session replays queued QoS 1",
        m is not None, f"got={m} session_present={p2.session_present}")
    p2.close()


def raw_tests():
    # 10. PINGREQ -> PINGRESP over a raw socket.
    s = socket.create_connection((HOST, MQTT_PORT), timeout=6)
    s.sendall(connect_frame(f"raw-ping-{RUN}"))
    connack = recv_exact(s, 4)
    ok = connack == b"\x20\x02\x00\x00"
    s.sendall(b"\xc0\x00")
    resp = recv_exact(s, 2)
    log("raw PINGREQ -> PINGRESP", ok and resp == b"\xd0\x00",
        f"connack={connack.hex()} resp={resp.hex()}")
    s.close()

    # 11. Bad protocol version -> CONNACK rc 1, then close.
    s = socket.create_connection((HOST, MQTT_PORT), timeout=6)
    s.sendall(connect_frame(f"raw-badproto-{RUN}", proto_level=3))
    data = recv_exact(s, 4)
    log("bad protocol version -> CONNACK rc 1",
        data == b"\x20\x02\x00\x01", f"got={data.hex()}")
    s.settimeout(3)
    try:
        more = s.recv(1)
    except socket.timeout:
        more = b"timeout"
    log("bad protocol version -> connection closed", more == b"",
        f"recv={more!r}")
    s.close()

    # 12. Keep-alive timeout: connect with keepalive=2, stay silent.
    s = socket.create_connection((HOST, MQTT_PORT), timeout=6)
    s.sendall(connect_frame(f"raw-keepalive-{RUN}", keepalive=2))
    connack = recv_exact(s, 4)
    s.settimeout(8)
    start = time.time()
    try:
        more = s.recv(1)
        elapsed = time.time() - start
    except socket.timeout:
        more, elapsed = b"timeout", time.time() - start
    log("keep-alive timeout closes silent client",
        connack == b"\x20\x02\x00\x00" and more == b"" and 2.5 < elapsed < 8,
        f"connack={connack.hex()} closed_after={elapsed:.1f}s recv={more!r}")
    s.close()

    # 13. Oversize payload (max_payload 262144) -> connection closed.
    s = socket.create_connection((HOST, MQTT_PORT), timeout=6)
    s.sendall(connect_frame(f"raw-big-{RUN}"))
    connack = recv_exact(s, 4)
    big = b"x" * 300_000
    pub = frame(0x30, enc_str("big/t") + big)
    try:
        s.sendall(pub)
    except OSError:
        pass
    s.settimeout(5)
    try:
        more = s.recv(1)
    except socket.timeout:
        more = b"timeout"
    log("oversize PUBLISH payload closes connection",
        connack == b"\x20\x02\x00\x00" and more == b"",
        f"connack={connack.hex()} recv={more!r}")
    s.close()


# ---------------------------------------------------------------- bridge tests (slixmpp)
class BridgeClient(slixmpp.ClientXMPP):
    def __init__(self, jid, pw):
        super().__init__(jid, pw)
        self.ready = asyncio.Event()
        self.events = []
        self.event_seen = asyncio.Event()
        self.add_event_handler("session_start", self.on_start)
        self.add_event_handler("pubsub_publish", self.on_pubsub_event)
        self.add_event_handler("message", self.on_message)

    async def on_start(self, event):
        self.send_presence()
        self.ready.set()

    def on_pubsub_event(self, msg):
        self.events.append(str(msg))
        self.event_seen.set()

    def on_message(self, msg):
        if "pubsub#event" in str(msg):
            self.events.append(str(msg))
            self.event_seen.set()


async def bridge_tests():
    andi_u, budi_u = f"bridgedandi{RUN}", f"bridgedbudi{RUN}"
    for u in (andi_u, budi_u):
        log(f"create user {u}", rpc_create(u))

    andi = BridgeClient(f"{andi_u}@localhost/bridge", "secret")
    budi = BridgeClient(f"{budi_u}@localhost/bridge", "secret")
    for c in (andi, budi):
        c.ssl_context = NO_VERIFY_CTX
        c.use_tls = False
        c.force_starttls = False
        c.register_plugin("xep_0060")
    await asyncio.wait_for(andi.connect(HOST, XMPP_PORT), timeout=10)
    await asyncio.wait_for(budi.connect(HOST, XMPP_PORT), timeout=10)
    await asyncio.wait_for(andi.ready.wait(), timeout=10)
    await asyncio.wait_for(budi.ready.wait(), timeout=10)
    log("bridge XMPP clients connected", True)

    node = f"bridge/{RUN}/news"
    service = "pubsub.localhost"

    # MQTT -> XMPP: first publish auto-creates the node; XMPP subscribes;
    # second publish must arrive as a PubSub event.
    pub = new_client("bridge-pub")
    assert pub.connect() and pub.rc == 0
    pub.client.publish(node, "first (creates node)", qos=1).wait_for_publish(timeout=5)
    await asyncio.sleep(0.5)
    try:
        sub = await asyncio.wait_for(
            budi.plugin["xep_0060"].subscribe(service, node), timeout=6)
        log("bridge XMPP subscribe to auto-created node",
            sub["pubsub"]["subscription"]["subscription"] == "subscribed", "")
    except Exception as e:
        log("bridge XMPP subscribe to auto-created node", False, str(e))
        andi.disconnect()
        budi.disconnect()
        pub.close()
        return
    budi.events.clear()
    budi.event_seen.clear()
    pub.client.publish(node, "hello from mqtt", qos=1).wait_for_publish(timeout=5)
    try:
        await asyncio.wait_for(budi.event_seen.wait(), timeout=6)
        log("bridge MQTT publish -> XMPP PubSub subscriber",
            any("hello from mqtt" in e for e in budi.events),
            budi.events[0][:300] if budi.events else "(none)")
    except asyncio.TimeoutError:
        log("bridge MQTT publish -> XMPP PubSub subscriber", False, "no event in 6s")
    pub.close()

    # XMPP -> MQTT: XMPP publish arrives at the MQTT subscriber.
    sub = new_client("bridge-sub")
    assert sub.connect() and sub.rc == 0
    sub.client.subscribe(node, 0)
    assert sub.sub_acked.wait(5)
    try:
        await asyncio.wait_for(
            andi.plugin["xep_0060"].publish(
                service, node, id="xmpp1",
                payload=ET.fromstring("<entry>hello from xmpp</entry>")),
            timeout=6)
        log("bridge XMPP publish ok", True)
    except Exception as e:
        log("bridge XMPP publish ok", False, str(e))
    m = sub.wait_msg(topic=node, payload="hello from xmpp")
    log("bridge XMPP publish -> MQTT subscriber", m is not None, f"got={m}")
    sub.close()

    andi.disconnect()
    budi.disconnect()


def main():
    broker_tests()
    raw_tests()
    asyncio.run(bridge_tests())
    failed = [r for r in results if not r[1]]
    print(f"\n==== {len(results) - len(failed)}/{len(results)} passed ====")
    if failed:
        print("FAILED:", [r[0] for r in failed])
        sys.exit(1)


if __name__ == "__main__":
    main()
