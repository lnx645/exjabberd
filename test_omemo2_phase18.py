#!/usr/bin/env python3
"""Raw-socket live probe for Fase 18 — OMEMO XEP-0384 modern
generations (`urn:xmpp:omemo:1` and `urn:xmpp:omemo:2`) over PEP
(XEP-0163), against exjabberd C2S on 127.0.0.1:5222.

The :1/:2 layout differs from the legacy axolotl generation
(covered by test_jingle_phase5.py): ONE bundles node per account
(`urn:xmpp:omemo:N:bundles`) holding one <bundle/> item per
device (item id = device id, node configured max_items = max),
plus a devices node (`urn:xmpp:omemo:N:devices`) whose single
item has id 'current'. Both nodes MUST have access model open so
contacts without a presence subscription can fetch them.

Usage: start the server first (ELIXIR_ERL_OPTIONS="+fnu -sname
exjabberd" mix run --no-halt), then: python3 test_omemo2_phase18.py

Users are created fresh per run via RPC. Records PASS/FAIL per
check.
"""
import socket, time, sys, base64, subprocess, uuid, os

HOST, PORT = "127.0.0.1", 5222
RUN = uuid.uuid4().hex[:8]
results = []

def log(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail}")

def rpc_create(user):
    code = (
        f':rpc.call(:"exjabberd@{socket.gethostname()}", Exjabberd.Auth, '
        f':create_user, ["localhost", "{user}", "secret"]) |> IO.inspect()'
    )
    env = dict(os.environ)
    env["PATH"] = ("/home/hatch/workspace/.toolchain/otp-28.1/bin:"
                   "/home/hatch/workspace/.toolchain/elixir-1.19.7/bin:"
                   + env.get("PATH", ""))
    env["ELIXIR_ERL_OPTIONS"] = "+fnu"
    r = subprocess.run(
        ["elixir", "--sname", "probe", "-e", code],
        capture_output=True, text=True, timeout=60, env=env,
    )
    return ":ok" in (r.stdout + r.stderr)

STREAM = ("<?xml version='1.0'?><stream:stream to='localhost' "
          "xmlns='jabber:client' "
          "xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")

class Conn:
    def __init__(self, name):
        self.name = name
        self.s = socket.create_connection((HOST, PORT), timeout=10)
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

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass

def login(c, user, resource="m1"):
    c.send(STREAM)
    r = c.recv_until("stream:features")
    assert "stream:features" in r, f"no features for {user}: {r[:200]}"
    b64 = base64.b64encode(f"\0{user}\0secret".encode()).decode()
    c.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{b64}</auth>")
    r = c.recv_until("success")
    assert "<success" in r, f"auth failed for {user}: {r[:200]}"
    c.send(STREAM)
    c.recv_until("stream:features")
    c.send(f"<iq type='set' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>{resource}</resource></bind></iq>")
    r = c.recv_until("bind")
    assert f"<jid>{user}@localhost/{resource}</jid>" in r, f"bind failed: {r[:200]}"

PUBSUB = "http://jabber.org/protocol/pubsub"

def publish(c, iq_id, to_bare, node, item_id, payload, options=""):
    c.send(
        f"<iq type='set' id='{iq_id}' to='{to_bare}'>"
        f"<pubsub xmlns='{PUBSUB}'><publish node='{node}'>"
        f"<item id='{item_id}'>{payload}</item></publish>{options}</pubsub></iq>")

def fetch(c, iq_id, to_bare, node, item_id=None):
    item = f"<item id='{item_id}'/>" if item_id else ""
    c.send(
        f"<iq type='get' id='{iq_id}' to='{to_bare}'>"
        f"<pubsub xmlns='{PUBSUB}'><items node='{node}'>{item}</items></pubsub></iq>")
    return c.recv_until(iq_id)

def opts_form(fields):
    inner = "".join(
        f"<field var='{var}'><value>{val}</value></field>" for var, val in fields)
    return ("<publish-options><x xmlns='jabber:x:data' type='submit'>"
            "<field var='FORM_TYPE' type='hidden'>"
            "<value>http://jabber.org/protocol/pubsub#publish-options</value></field>"
            f"{inner}</x></publish-options>")

def devices_payload(ns, ids):
    return (f"<devices xmlns='{ns}'>" +
            "".join(f"<device id='{i}'/>" for i in ids) + "</devices>")

def bundle_payload(ns, tag):
    return (f"<bundle xmlns='{ns}'><spk id='1'>U1BL{tag}</spk>"
            f"<spks>U0lH{tag}</spks><ik>SUt{tag}</ik><prekeys>"
            f"<pk id='1'>UEs{tag}A</pk><pk id='2'>UEs{tag}B</pk>"
            "</prekeys></bundle>")

def main():
    andi = f"o2andi{RUN}"
    budi = f"o2budi{RUN}"
    carol = f"o2carol{RUN}"
    for u in (andi, budi, carol):
        assert rpc_create(u), f"cannot create {u}"
    a_bare, b_bare, c_bare = f"{andi}@localhost", f"{budi}@localhost", f"{carol}@localhost"
    b_jid = f"{budi}@localhost/m1"

    A = Conn("andi"); B = Conn("budi"); C = Conn("carol")
    login(A, andi); login(B, budi); login(C, carol)
    A.drain(); B.drain(); C.drain()

    ns2 = "urn:xmpp:omemo:2"
    dev2, bun2 = f"{ns2}:devices", f"{ns2}:bundles"

    # --- OMEMO:2 devices node (publish-options sets access open) ---
    publish(A, "d1", a_bare, dev2, "current", devices_payload(ns2, [31415, 4223]),
            opts_form([("pubsub#access_model", "open")]))
    r = A.recv_until("d1")
    log("omemo:2 devices publish (item 'current', access open option)", "type='result'" in r, r[:200])

    r = fetch(B, "d2", a_bare, dev2)
    log("omemo:2 peer without subscription fetches devices",
        "device id='31415'" in r and "device id='4223'" in r, r[:300])

    # --- OMEMO:2 bundles node: first publish WITHOUT publish-options
    # (auto-create must use the spec config: many items, open). ---
    publish(A, "b1", a_bare, bun2, "4223", bundle_payload(ns2, "NDI="))
    r = A.recv_until("b1")
    log("omemo:2 bundle publish without options (auto-create)", "type='result'" in r, r[:200])

    # Second device WITH the XEP-0384 publish-options (max + open).
    publish(A, "b2", a_bare, bun2, "31415", bundle_payload(ns2, "MTE="),
            opts_form([("pubsub#max_items", "max"), ("pubsub#access_model", "open")]))
    r = A.recv_until("b2")
    log("omemo:2 bundle publish with max_items=max option", "type='result'" in r, r[:200])

    r = fetch(B, "b3", a_bare, bun2)
    log("omemo:2 bundles node keeps BOTH device bundles",
        "item id='31415'" in r and "item id='4223'" in r
        and "U1BLMTE=" in r and "U1BLNDI=" in r, r[:400])

    r = fetch(B, "b4", a_bare, bun2, item_id="31415")
    log("omemo:2 single bundle fetch by device id",
        "item id='31415'" in r and "UEsMTE=A" in r and "item id='4223'" not in r, r[:300])

    # Republishing one device replaces only its own item.
    publish(A, "b5", a_bare, bun2, "31415", bundle_payload(ns2, "NEW="))
    A.recv_until("b5")
    r = fetch(B, "b6", a_bare, bun2)
    log("omemo:2 bundle republish replaces own item, keeps the other",
        "U1BLNEW=" in r and "U1BLMTE=" not in r and "item id='4223'" in r
        and r.count("<item ") == 2, r[:400])

    # Devices node still holds exactly one item (max_items 1).
    publish(A, "d3", a_bare, dev2, "current", devices_payload(ns2, [999]))
    A.recv_until("d3")
    r = fetch(B, "d4", a_bare, dev2)
    log("omemo:2 devices republish replaces list (max_items 1)",
        "device id='999'" in r and "device id='31415'" not in r, r[:300])

    # Non-owner cannot publish into someone else's bundles node.
    publish(B, "b7", a_bare, bun2, "666", bundle_payload(ns2, "EVL="))
    r = B.recv_until("b7")
    log("omemo:2 non-owner bundle publish -> forbidden", "forbidden" in r, r[:300])

    # --- Discovery ---
    B.send(f"<iq type='get' id='i1' to='{a_bare}'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")
    r = B.recv_until("i1")
    log("disco#info advertises urn:xmpp:omemo:1 and urn:xmpp:omemo:2",
        "urn:xmpp:omemo:1" in r and "urn:xmpp:omemo:2" in r, r[:300])

    B.send(f"<iq type='get' id='i2' to='{a_bare}'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")
    r = B.recv_until("i2")
    log("disco#items lists omemo:2 nodes",
        "urn:xmpp:omemo:2:devices" in r and "urn:xmpp:omemo:2:bundles" in r, r[:400])

    # --- PEP notification on the :2 devices node ---
    B.send(f"<iq type='set' id='s1' to='{a_bare}'><pubsub xmlns='{PUBSUB}'><subscribe node='{dev2}' jid='{b_bare}'/></pubsub></iq>")
    r = B.recv_until("s1")
    log("subscribe to peer omemo:2 devices", "subscription" in r, r[:300])
    publish(A, "d5", a_bare, dev2, "current", devices_payload(ns2, [777]))
    A.recv_until("d5")
    note = B.recv_until("device id='777'")
    log("omemo:2 devices republish notifies subscriber",
        dev2 in note and f"from='{a_bare}'" in note, note[:300])

    # --- An <encrypted xmlns='urn:xmpp:omemo:2'> message is routed intact ---
    A.send(
        f"<message type='chat' id='m1' to='{b_jid}'>"
        f"<encrypted xmlns='{ns2}'><header sid='31415'>"
        f"<keys jid='{b_bare}'><key rid='4223'>S0VZREFUQQ==</key></keys></header>"
        f"<payload>Q0lQSEVSVEVYVA==</payload></encrypted>"
        f"<store xmlns='urn:xmpp:hints'/></message>")
    got = B.recv_until("Q0lQSEVSVEVYVA==")
    log("omemo:2 encrypted message element delivered intact",
        "urn:xmpp:omemo:2" in got and "rid='4223'" in got, got[:300])

    # --- OMEMO:1 generation (carol), same single-bundles-node layout ---
    ns1 = "urn:xmpp:omemo:1"
    dev1, bun1 = f"{ns1}:devices", f"{ns1}:bundles"
    publish(C, "e1", c_bare, dev1, "current", devices_payload(ns1, [111, 222]),
            opts_form([("pubsub#access_model", "open")]))
    r = C.recv_until("e1")
    log("omemo:1 devices publish", "type='result'" in r, r[:200])
    publish(C, "e2", c_bare, bun1, "111", bundle_payload(ns1, "MTEx"))
    C.recv_until("e2")
    publish(C, "e3", c_bare, bun1, "222", bundle_payload(ns1, "MjIy"))
    C.recv_until("e3")

    r = fetch(B, "e4", c_bare, bun1)
    log("omemo:1 bundles node keeps both devices, isolated per user",
        "item id='111'" in r and "item id='222'" in r
        and "item id='31415'" not in r, r[:400])
    r = fetch(B, "e5", c_bare, dev1)
    log("omemo:1 peer fetches devices",
        "device id='111'" in r and "device id='222'" in r, r[:300])

    A.close(); B.close(); C.close()
    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main()
