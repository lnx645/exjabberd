#!/usr/bin/env python3
"""Phase 17 live probe: MQTT v5.0 broker behaviour on 1883, against a
running dev server (verify.sh step 03 boots it).

Real clients: paho-mqtt 2.x speaking MQTTv5 for the mainstream flows,
plus a small hand-rolled raw-socket v5 client for the corners paho
cannot express (topic aliases, abrupt socket death with a Will Delay,
DISCONNECT reason 0x04, Authentication Method refusal, Receive
Maximum windowing).

Covers: CONNACK properties, property pass-through (content type /
response topic / correlation data / user properties), subscription
identifiers, QoS 2 exactly-once, topic aliases (+ 0x94 on unknown),
session expiry (persist + DISCONNECT narrowing to 0), will delay
(elapse / session-continuation cancel), DISCONNECT-with-Will (0x04),
message expiry on retained messages, shared subscriptions, No Local,
Retain As Published, Retain Handling, bad-auth reason 0x86,
auth-method refusal 0x8C, assigned client identifiers, Maximum
Packet Size drop, Receive Maximum windowing.
"""
import socket
import sys
import threading
import time
import uuid

import paho.mqtt.client as mqtt
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties
from paho.mqtt.subscribeoptions import SubscribeOptions

HOST = "127.0.0.1"
MQTT_PORT = 1883
RUN = uuid.uuid4().hex[:8]
results = []


def log(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail}", flush=True)


# ---------------------------------------------------------------- paho v5
class V5Collector:
    def __init__(self, client_id, clean_start=True, session_expiry=None,
                 max_packet_size=None, receive_maximum=None):
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                                  client_id=client_id, protocol=mqtt.MQTTv5)
        self.clean_start = clean_start
        props = Properties(PacketTypes.CONNECT)
        if session_expiry is not None:
            props.SessionExpiryInterval = session_expiry
        if max_packet_size is not None:
            props.MaximumPacketSize = max_packet_size
        if receive_maximum is not None:
            props.ReceiveMaximum = receive_maximum
        self.connect_props = props
        self.msgs = []
        self.connected = threading.Event()
        self.disconnected = threading.Event()
        self.reason = None
        self.conn_props = None
        self.session_present = None
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = lambda *a: self.disconnected.set()
        self.client.on_message = self._on_message

    def _on_connect(self, client, userdata, flags, reason_code, properties):
        self.reason = reason_code
        self.conn_props = properties
        self.session_present = bool(flags.session_present) if flags else False
        self.connected.set()

    def _on_message(self, client, userdata, msg):
        self.msgs.append(msg)

    def connect(self, timeout=6):
        self.client.connect(HOST, MQTT_PORT, 60,
                            clean_start=self.clean_start,
                            properties=self.connect_props)
        self.client.loop_start()
        return self.connected.wait(timeout)

    def wait_msg(self, topic=None, payload=None, timeout=6):
        end = time.time() + timeout
        while time.time() < end:
            for m in list(self.msgs):
                if (topic is None or m.topic == topic) and \
                        (payload is None or m.payload == payload):
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


def new_v5(cid, **kw):
    return V5Collector(f"{cid}-{RUN}", **kw)


def props(**kw):
    p = Properties(PacketTypes.PUBLISH)
    for k, v in kw.items():
        setattr(p, k, v)
    return p


# ---------------------------------------------------------------- raw v5
def enc_str(s):
    b = s.encode() if isinstance(s, str) else s
    return len(b).to_bytes(2, "big") + b


def varint(n):
    out = bytearray()
    while True:
        d = n % 128
        n //= 128
        if n > 0:
            d |= 0x80
        out.append(d)
        if n == 0:
            return bytes(out)


def prop_bytes(pairs):
    """pairs: list of (id, kind, value); kind in byte/u16/u32/varint/str/bin/pair."""
    body = bytearray()
    for pid, kind, value in pairs:
        body.append(pid)
        if kind == "byte":
            body.append(value)
        elif kind == "u16":
            body += value.to_bytes(2, "big")
        elif kind == "u32":
            body += value.to_bytes(4, "big")
        elif kind == "varint":
            body += varint(value)
        elif kind in ("str", "bin"):
            body += enc_str(value)
        elif kind == "pair":
            body += enc_str(value[0]) + enc_str(value[1])
    return varint(len(body)) + bytes(body)


PROP_KINDS = {
    0x01: "byte", 0x02: "u32", 0x03: "str", 0x08: "str", 0x09: "bin",
    0x0B: "varint", 0x11: "u32", 0x12: "str", 0x13: "u16", 0x15: "str",
    0x16: "bin", 0x17: "byte", 0x18: "u32", 0x19: "byte", 0x1A: "str",
    0x1C: "str", 0x1F: "str", 0x21: "u16", 0x22: "u16", 0x23: "u16",
    0x24: "byte", 0x25: "byte", 0x26: "pair", 0x27: "u32", 0x28: "byte",
    0x29: "byte", 0x2A: "byte",
}


def parse_props(buf, off):
    """Parse a property block starting at buf[off] (varint length).
    Returns (dict id -> list of values, new offset)."""
    length, off = read_varint(buf, off)
    end = off + length
    out = {}
    while off < end:
        pid = buf[off]
        off += 1
        kind = PROP_KINDS[pid]
        if kind == "byte":
            v = buf[off]; off += 1
        elif kind == "u16":
            v = int.from_bytes(buf[off:off + 2], "big"); off += 2
        elif kind == "u32":
            v = int.from_bytes(buf[off:off + 4], "big"); off += 4
        elif kind == "varint":
            v, off = read_varint(buf, off)
        elif kind in ("str", "bin"):
            ln = int.from_bytes(buf[off:off + 2], "big"); off += 2
            v = buf[off:off + ln]; off += ln
            if kind == "str":
                v = v.decode()
        elif kind == "pair":
            ln = int.from_bytes(buf[off:off + 2], "big"); off += 2
            a = buf[off:off + ln].decode(); off += ln
            ln = int.from_bytes(buf[off:off + 2], "big"); off += 2
            b = buf[off:off + ln].decode(); off += ln
            v = (a, b)
        out.setdefault(pid, []).append(v)
    return out, off


def read_varint(buf, off):
    mult = 1
    value = 0
    while True:
        b = buf[off]
        off += 1
        value += (b & 0x7F) * mult
        if not (b & 0x80):
            return value, off
        mult *= 128


def packet(ptype_flags, body):
    return bytes([ptype_flags]) + varint(len(body)) + body


def build_connect(client_id, clean=True, keepalive=60, conn_props=(),
                  will=None, username=None, password=None):
    flags = 0x02 if clean else 0x00
    payload = enc_str(client_id)
    if will is not None:
        wtopic, wpayload, wqos, wretain, wprops = will
        flags |= 0x04 | (wqos << 3) | ((0x20 if wretain else 0))
        payload += prop_bytes(wprops) + enc_str(wtopic) + enc_str(wpayload)
    if username is not None:
        flags |= 0x80
        payload += enc_str(username)
    if password is not None:
        flags |= 0x40
        payload += enc_str(password)
    vh = enc_str("MQTT") + bytes([5, flags]) + keepalive.to_bytes(2, "big") \
        + prop_bytes(conn_props)
    return packet(0x10, vh + payload)


class RawV5:
    def __init__(self):
        self.sock = socket.create_connection((HOST, MQTT_PORT), timeout=8)
        self.buf = b""

    def send(self, data):
        self.sock.sendall(data)

    def _fill(self, n, timeout=8):
        self.sock.settimeout(timeout)
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("socket closed by server")
            self.buf += chunk

    def read_packet(self, timeout=8):
        self._fill(2, timeout)
        first = self.buf[0]
        length, off = read_varint(self.buf, 1)
        self._fill(off + length, timeout)
        body = self.buf[off:off + length]
        self.buf = self.buf[off + length:]
        return first >> 4, first & 0x0F, body

    def connect(self, *a, **kw):
        self.send(build_connect(*a, **kw))
        ptype, _flags, body = self.read_packet()
        assert ptype == 2, f"expected CONNACK, got type {ptype}"
        session_present = body[0] == 1
        reason = body[1]
        cprops, _ = parse_props(body, 2)
        return session_present, reason, cprops

    def subscribe(self, packet_id, filters):
        """filters: list of (filter, options_byte). Returns granted codes."""
        body = packet_id.to_bytes(2, "big") + prop_bytes([])
        for flt, opt in filters:
            body += enc_str(flt) + bytes([opt])
        self.send(packet(0x82, body))
        ptype, _f, rbody = self.read_packet()
        assert ptype == 9, f"expected SUBACK, got {ptype}"
        _props, off = parse_props(rbody, 2)
        return list(rbody[off:])

    def publish(self, topic, payload, qos=0, packet_id=None, pprops=(),
                retain=False):
        flags = (qos << 1) | (1 if retain else 0)
        body = enc_str(topic)
        if qos > 0:
            body += packet_id.to_bytes(2, "big")
        body += prop_bytes(pprops) + payload
        self.send(packet(0x30 | flags, body))

    def read_publish(self, timeout=8):
        # Skip ack packets (PUBACK/PUBREC/PUBREL/PUBCOMP) answering
        # this client's own publishes; we want the next delivery.
        for _ in range(5):
            ptype, flags, body = self.read_packet(timeout)
            if ptype == 3:
                break
        assert ptype == 3, f"expected PUBLISH, got {ptype}"
        qos = (flags >> 1) & 0x03
        retain = flags & 0x01
        ln = int.from_bytes(body[0:2], "big")
        topic = body[2:2 + ln].decode()
        off = 2 + ln
        pid = None
        if qos > 0:
            pid = int.from_bytes(body[off:off + 2], "big")
            off += 2
        pprops, off = parse_props(body, off)
        return topic, body[off:], qos, retain, pid, pprops

    def puback(self, packet_id):
        self.send(packet(0x40, packet_id.to_bytes(2, "big")))

    def disconnect(self, reason=0, dprops=()):
        self.send(packet(0xE0, bytes([reason]) + prop_bytes(dprops)))

    def abrupt_close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------- tests
def test_connack_properties():
    c = new_v5("props")
    ok = c.connect()
    p = c.conn_props
    good = (
        ok and c.reason.value == 0 and p is not None
        and p.ReceiveMaximum == 65535
        and p.MaximumPacketSize == 262144 + 4096
        and p.TopicAliasMaximum == 16
        and p.RetainAvailable == 1
        and p.WildcardSubscriptionAvailable == 1
        and p.SubscriptionIdentifierAvailable == 1
        and p.SharedSubscriptionAvailable == 1
    )
    log("connack properties advertise limits and features", bool(good),
        f"rc={c.reason} props={p}")
    c.close()


def test_property_passthrough():
    topic = f"v5/props/{RUN}"
    sub = new_v5("propssub")
    sub.connect()
    sub.client.subscribe(topic, qos=1)
    time.sleep(0.3)
    pub = new_v5("propspub")
    pub.connect()
    pub.client.publish(
        topic, "with-props", qos=1,
        properties=props(ContentType="text/plain",
                         ResponseTopic="v5/reply",
                         CorrelationData=b"\x01\x02",
                         UserProperty=[("trace", "t-1")]))
    m = sub.wait_msg(topic, b"with-props")
    good = False
    if m is not None:
        mp = m.properties
        good = (mp.ContentType == "text/plain"
                and mp.ResponseTopic == "v5/reply"
                and mp.CorrelationData == b"\x01\x02"
                and ("trace", "t-1") in list(mp.UserProperty))
    log("publish properties pass through to subscribers", good,
        f"msg={m.payload if m else None}")
    sub.close()
    pub.close()


def test_subscription_identifier():
    topic = f"v5/subid/{RUN}"
    sub = new_v5("subid")
    sub.connect()
    sp = Properties(PacketTypes.SUBSCRIBE)
    sp.SubscriptionIdentifier = 42
    sub.client.subscribe(topic, qos=1, properties=sp)
    time.sleep(0.3)
    pub = new_v5("subidpub")
    pub.connect()
    pub.client.publish(topic, "tagged", qos=1)
    m = sub.wait_msg(topic, b"tagged")
    ids = []
    if m is not None:
        ids = list(m.properties.SubscriptionIdentifier or [])
    log("subscription identifier attached to deliveries", ids == [42],
        f"ids={ids}")
    sub.close()
    pub.close()


def test_qos2_v5():
    topic = f"v5/qos2/{RUN}"
    sub = new_v5("q2sub")
    sub.connect()
    sub.client.subscribe(topic, qos=2)
    time.sleep(0.3)
    pub = new_v5("q2pub")
    pub.connect()
    pub.client.publish(topic, "exactly-once", qos=2)
    m = sub.wait_msg(topic, b"exactly-once")
    time.sleep(0.5)
    count = sum(1 for x in sub.msgs if x.payload == b"exactly-once")
    log("v5 QoS 2 delivers exactly once", m is not None and count == 1,
        f"count={count}")
    sub.close()
    pub.close()


def test_topic_alias():
    topic = f"v5/alias/{RUN}"
    sub = RawV5()
    sp, rc, _ = sub.connect(f"alias-sub-{RUN}")
    granted = sub.subscribe(1, [(topic, 1)])
    pub = RawV5()
    pub.connect(f"alias-pub-{RUN}")
    pub.publish(topic, b"first", qos=1, packet_id=1,
                pprops=[(0x23, "u16", 1)])
    t1 = sub.read_publish()
    pub.read_packet()  # PUBACK
    pub.publish("", b"second", qos=1, packet_id=2,
                pprops=[(0x23, "u16", 1)])
    t2 = sub.read_publish()
    pub.read_packet()  # PUBACK
    good = (granted == [1] and t1[0] == topic and t1[1] == b"first"
            and t2[0] == topic and t2[1] == b"second")
    log("topic alias resolves to the bound topic", good,
        f"t1={t1[0]}/{t1[1]} t2={t2[0]}/{t2[1]}")
    # Unknown alias -> DISCONNECT with reason 0x94 (Topic Alias invalid).
    bad = RawV5()
    bad.connect(f"alias-bad-{RUN}")
    bad.publish("", b"boom", qos=0, pprops=[(0x23, "u16", 7)])
    try:
        ptype, _f, body = bad.read_packet()
        ok2 = ptype == 14 and body and body[0] == 0x94
        detail = f"type={ptype} body={list(body)}"
    except (ConnectionError, socket.timeout) as e:
        ok2 = False
        detail = f"no DISCONNECT: {e}"
    log("unknown topic alias -> DISCONNECT 0x94", ok2, detail)
    sub.disconnect()
    pub.disconnect()
    bad.close()


def test_session_expiry():
    topic = f"v5/session/{RUN}"
    a = new_v5("sess", clean_start=False, session_expiry=60)
    a.connect()
    a.client.subscribe(topic, qos=1)
    time.sleep(0.3)
    a.close()  # graceful DISCONNECT; session must persist (expiry 60)
    time.sleep(0.3)
    pub = new_v5("sesspub")
    pub.connect()
    pub.client.publish(topic, "while-away", qos=1)
    pub.close()
    time.sleep(0.3)
    b = new_v5("sess", clean_start=False, session_expiry=60)
    b.connect()
    m = b.wait_msg(topic, b"while-away")
    log("session persists across disconnect, queued QoS1 replayed",
        b.session_present is True and m is not None,
        f"present={b.session_present} msg={m is not None}")
    # Narrow the session expiry to 0 at DISCONNECT: session ends.
    dp = Properties(PacketTypes.DISCONNECT)
    dp.SessionExpiryInterval = 0
    b.client.disconnect(properties=dp)
    b.client.loop_stop()
    time.sleep(0.3)
    c = new_v5("sess", clean_start=False, session_expiry=60)
    c.connect()
    log("DISCONNECT session-expiry 0 ends the session",
        c.session_present is False, f"present={c.session_present}")
    c.close()


def test_will_delay():
    topic = f"v5/willdelay/{RUN}"
    watcher = new_v5("willwatch")
    watcher.connect()
    watcher.client.subscribe(topic, qos=1)
    time.sleep(0.3)

    dying = RawV5()
    dying.connect(
        f"willdelay-{RUN}", clean=False,
        conn_props=[(0x11, "u32", 60)],
        will=(topic, "delayed-bye", 1, False, [(0x18, "u32", 2)]))
    dying.abrupt_close()
    early = watcher.wait_msg(topic, b"delayed-bye", timeout=1.2)
    late = watcher.wait_msg(topic, b"delayed-bye", timeout=3.5)
    log("will delay: nothing before the delay, will after it",
        early is None and late is not None,
        f"early={early is not None} late={late is not None}")

    # Reconnect inside the delay and continue the session: the parked
    # will must be discarded.
    dying2 = RawV5()
    dying2.connect(
        f"willdelay2-{RUN}", clean=False,
        conn_props=[(0x11, "u32", 60)],
        will=(topic, "never-sent", 1, False, [(0x18, "u32", 2)]))
    dying2.abrupt_close()
    time.sleep(0.5)
    back = RawV5()
    sp, rc, _ = back.connect(f"willdelay2-{RUN}", clean=False,
                             conn_props=[(0x11, "u32", 60)])
    back.disconnect()
    ghost = watcher.wait_msg(topic, b"never-sent", timeout=3.2)
    log("will delay: session continuation discards the parked will",
        sp is True and ghost is None,
        f"present={sp} ghost={ghost is not None}")
    watcher.close()


def test_disconnect_with_will():
    topic = f"v5/willnow/{RUN}"
    watcher = new_v5("willnowwatch")
    watcher.connect()
    watcher.client.subscribe(topic, qos=1)
    time.sleep(0.3)
    c = RawV5()
    c.connect(
        f"willnow-{RUN}", clean=False,
        conn_props=[(0x11, "u32", 60)],
        will=(topic, "right-now", 1, False, [(0x18, "u32", 30)]))
    c.disconnect(reason=0x04)
    m = watcher.wait_msg(topic, b"right-now", timeout=3)
    log("DISCONNECT reason 0x04 publishes the will immediately",
        m is not None, f"msg={m is not None}")
    watcher.close()
    c.close()


def test_message_expiry_retained():
    topic = f"v5/expiry/{RUN}"
    pub = new_v5("exppub")
    pub.connect()
    pub.client.publish(topic, "short-lived", qos=1, retain=True,
                       properties=props(MessageExpiryInterval=1))
    pub.client.publish(topic + "/long", "long-lived", qos=1, retain=True,
                         properties=props(MessageExpiryInterval=60))
    time.sleep(1.8)
    sub = new_v5("expsub")
    sub.connect()
    sub.client.subscribe(topic, qos=1)
    sub.client.subscribe(topic + "/long", qos=1)
    gone = sub.wait_msg(topic, b"short-lived", timeout=1.5)
    kept = sub.wait_msg(topic + "/long", b"long-lived", timeout=3)
    remaining = None
    if kept is not None:
        remaining = kept.properties.MessageExpiryInterval
    log("retained message expiry: expired dropped, live one carries remaining",
        gone is None and kept is not None and remaining is not None
        and 0 < remaining <= 60,
        f"gone={gone is None} kept={kept is not None} remaining={remaining}")
    sub.close()
    pub.close()


def test_shared_subscription():
    topic = f"v5/shared/{RUN}"
    members = [new_v5(f"share{i}") for i in (1, 2)]
    for m in members:
        m.connect()
        m.client.subscribe(f"$share/grp/{topic}", qos=1)
    plain = new_v5("shareplain")
    plain.connect()
    plain.client.subscribe(topic, qos=1)
    time.sleep(0.3)
    pub = new_v5("sharepub")
    pub.connect()
    for i in range(4):
        pub.client.publish(topic, f"s{i}", qos=1)
    deadline = time.time() + 6
    while time.time() < deadline:
        total = sum(len(m.msgs) for m in members)
        if total >= 4 and len(plain.msgs) >= 4:
            break
        time.sleep(0.05)
    total = sum(len(m.msgs) for m in members)
    each = [len(m.msgs) for m in members]
    log("shared subscription: group gets one copy each, split across members",
        total == 4 and all(n >= 1 for n in each) and len(plain.msgs) == 4,
        f"member_counts={each} plain={len(plain.msgs)}")
    for m in members:
        m.close()
    plain.close()
    pub.close()


def test_no_local_and_rap():
    topic = f"v5/nolocal/{RUN}"
    me = new_v5("nl")
    me.connect()
    me.client.subscribe(topic, options=SubscribeOptions(qos=1, noLocal=True))
    other = new_v5("nlother")
    other.connect()
    other.client.subscribe(topic, qos=1)
    time.sleep(0.3)
    me.client.publish(topic, "from-me", qos=1)
    other.client.publish(topic, "from-other", qos=1)
    own = me.wait_msg(topic, b"from-me", timeout=1.2)
    theirs = me.wait_msg(topic, b"from-other", timeout=3)
    log("no local: own publishes skipped, others delivered",
        own is None and theirs is not None,
        f"own={own is not None} theirs={theirs is not None}")
    me.close()
    other.close()

    # Retain As Published: a retained publish reaches a RAP=1
    # subscriber with RETAIN set, a RAP=0 subscriber with it clear.
    topic2 = f"v5/rap/{RUN}"
    rap = new_v5("rap1")
    rap.connect()
    rap.client.subscribe(topic2,
                         options=SubscribeOptions(qos=1, retainAsPublished=True))
    plain = new_v5("rap0")
    plain.connect()
    plain.client.subscribe(topic2, qos=1)
    time.sleep(0.3)
    pub = new_v5("rappub")
    pub.connect()
    pub.client.publish(topic2, "kept", qos=1, retain=True)
    m1 = rap.wait_msg(topic2, b"kept")
    m0 = plain.wait_msg(topic2, b"kept")
    log("retain as published honored per subscription",
        m1 is not None and m1.retain is True
        and m0 is not None and m0.retain is False,
        f"rap_retain={m1.retain if m1 else None} plain_retain={m0.retain if m0 else None}")
    rap.close()
    plain.close()
    pub.close()


def test_retain_handling():
    topic = f"v5/rh/{RUN}"
    pub = new_v5("rhpub")
    pub.connect()
    pub.client.publish(topic, "stored", qos=1, retain=True)
    time.sleep(0.3)

    never = new_v5("rh2")
    never.connect()
    o2 = SubscribeOptions(qos=1, retainHandling=2)
    never.client.subscribe(topic, options=o2)
    skipped = never.wait_msg(topic, b"stored", timeout=1.2)

    once = new_v5("rh1")
    once.connect()
    o1 = SubscribeOptions(qos=1, retainHandling=1)
    once.client.subscribe(topic, options=o1)
    first = once.wait_msg(topic, b"stored", timeout=3)
    # Re-subscribe the same filter: RH=1 suppresses the replay.
    once.msgs.clear()
    once.client.subscribe(topic, options=o1)
    second = once.wait_msg(topic, b"stored", timeout=1.2)
    log("retain handling: 2 skips, 1 sends only for a new subscription",
        skipped is None and first is not None and second is None,
        f"rh2={skipped is not None} rh1_first={first is not None} rh1_second={second is not None}")
    never.close()
    once.close()
    pub.close()


def test_auth_reasons():
    bad = V5Collector(f"badauth-{RUN}")
    bad.client.username_pw_set("andi", "wrong-password")
    bad.connect()
    log("v5 bad password -> CONNACK reason 0x86 (Bad user name or password)",
        bad.reason is not None and bad.reason.value == 0x86,
        f"reason={bad.reason}")
    bad.close()

    raw = RawV5()
    _sp, rc, _p = raw.connect(
        f"authmethod-{RUN}",
        conn_props=[(0x15, "str", "SCRAM-SHA-256")])
    log("CONNECT with an authentication method -> CONNACK 0x8C",
        rc == 0x8C, f"rc={rc}")
    raw.close()


def test_assigned_client_id():
    raw = RawV5()
    _sp, rc, cprops = raw.connect("", clean=True)
    assigned = cprops.get(0x12, [None])[0]
    good = rc == 0 and assigned and assigned.startswith("exj5-")
    if good:
        granted = raw.subscribe(1, [(f"v5/assigned/{RUN}", 1)])
        raw.publish(f"v5/assigned/{RUN}", b"self", qos=1, packet_id=9)
        t = raw.read_publish()
        good = granted == [1] and t[1] == b"self"
    log("empty client id -> server assigns one and it works",
        bool(good), f"assigned={assigned} rc={rc}")
    raw.disconnect()
    raw.close()


def test_max_packet_size():
    topic = f"v5/maxpkt/{RUN}"
    sub = new_v5("small", max_packet_size=64)
    sub.connect()
    sub.client.subscribe(topic, qos=0)
    time.sleep(0.3)
    pub = new_v5("bigpub")
    pub.connect()
    pub.client.publish(topic, "x" * 200, qos=0)
    big = sub.wait_msg(topic, timeout=1.5)
    pub.client.publish(topic, "tiny", qos=0)
    small = sub.wait_msg(topic, b"tiny", timeout=3)
    log("deliveries over the client's maximum packet size are dropped, connection lives",
        big is None and small is not None,
        f"big={big is not None} small={small is not None}")
    sub.close()
    pub.close()


def test_receive_maximum():
    raw = RawV5()
    raw.connect(f"recvmax-{RUN}",
                conn_props=[(0x21, "u16", 1)])
    topic = f"v5/recvmax/{RUN}"
    raw.subscribe(1, [(topic, 1)])
    pub = new_v5("recvpub")
    pub.connect()
    pub.client.publish(topic, "one", qos=1)
    pub.client.publish(topic, "two", qos=1)
    first = raw.read_publish()
    # Window is 1 and we have not acked: no second PUBLISH may arrive.
    raw.sock.settimeout(1.2)
    try:
        second_early = raw.read_publish()
        early = second_early[1]
    except (socket.timeout, TimeoutError):
        early = None
    raw.puback(first[4])
    second = raw.read_publish()
    log("receive maximum windows outbound QoS 1 deliveries",
        first[1] == b"one" and early is None and second[1] == b"two",
        f"first={first[1]} early={early} second={second[1]}")
    raw.puback(second[4])
    raw.disconnect()
    raw.close()
    pub.close()


def main():
    test_connack_properties()
    test_property_passthrough()
    test_subscription_identifier()
    test_qos2_v5()
    test_topic_alias()
    test_session_expiry()
    test_will_delay()
    test_disconnect_with_will()
    test_message_expiry_retained()
    test_shared_subscription()
    test_no_local_and_rap()
    test_retain_handling()
    test_auth_reasons()
    test_assigned_client_id()
    test_max_packet_size()
    test_receive_maximum()

    passed = sum(1 for _n, ok, _d in results if ok)
    print(f"==== {passed}/{len(results)} passed ====")
    if passed != len(results):
        sys.exit(1)


if __name__ == "__main__":
    main()
