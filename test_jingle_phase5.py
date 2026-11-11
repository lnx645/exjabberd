#!/usr/bin/env python3
"""Raw-socket live probe for Fase 5 — Jingle (XEP-0166 + XEP-0176
ICE-UDP), extdisco (XEP-0215) and OMEMO over PEP (XEP-0384 legacy
nodes, XEP-0163) — against exjabberd C2S on 127.0.0.1:5222.

Usage: start the server first (ELIXIR_ERL_OPTIONS="+fnu -sname
exjabberd" mix run --no-halt), then: python3 test_jingle_phase5.py

Users are created fresh per run via RPC. Records PASS/FAIL per
check. Mirrors test/exjabberd/jingle_omemo_test.exs (same flows,
independent implementation).
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
        f':rpc.call(:"exjabberd@htch-runtime", Exjabberd.Auth, '
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

def rpc_eval(code):
    # `code` must be a complete `:rpc.call(...) |> IO.inspect()`
    # expression: it runs on the throwaway probe node, so the call
    # has to hop to the server node explicitly.
    env = dict(os.environ)
    env["PATH"] = ("/home/hatch/workspace/.toolchain/otp-28.1/bin:"
                   "/home/hatch/workspace/.toolchain/elixir-1.19.7/bin:"
                   + env.get("PATH", ""))
    env["ELIXIR_ERL_OPTIONS"] = "+fnu"
    r = subprocess.run(
        ["elixir", "--sname", "probe", "-e", code],
        capture_output=True, text=True, timeout=60, env=env,
    )
    return r.stdout + r.stderr

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

def iq_result(c, iq_id, frm, to):
    c.send(f"<iq type='result' id='{iq_id}' from='{frm}' to='{to}'/>")

def main():
    andi = f"jgandi{RUN}"
    budi = f"jgbudi{RUN}"
    carol = f"jgcarol{RUN}"
    for u in (andi, budi, carol):
        assert rpc_create(u), f"cannot create {u}"
    a_jid, b_jid = f"{andi}@localhost/m1", f"{budi}@localhost/m1"
    a_bare, b_bare, c_bare = f"{andi}@localhost", f"{budi}@localhost", f"{carol}@localhost"

    A = Conn("andi"); B = Conn("budi"); C = Conn("carol")
    login(A, andi); login(B, budi); login(C, carol)
    A.drain(); B.drain(); C.drain()

    # --- Jingle: initiate -> accept -> transport-info -> terminate ---
    sid = f"sid-{RUN}"
    initiate = (
        f"<iq type='set' id='j1' to='{b_jid}'><jingle xmlns='urn:xmpp:jingle:1' "
        f"action='session-initiate' sid='{sid}' initiator='{a_jid}'>"
        f"<content creator='initiator' name='audio'>"
        f"<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'>"
        f"<payload-type id='0' name='PCMU' clockrate='8000'/></description>"
        f"<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1'>"
        f"<candidate component='1' foundation='abc123' generation='0' id='c1' "
        f"ip='192.0.2.1' network='1' port='5000' priority='100' protocol='udp' type='host'/>"
        f"</transport></content></jingle></iq>")
    A.send(initiate)
    got = B.recv_until("session-initiate")
    log("jingle initiate delivered intact (sid + ICE candidate)",
        "session-initiate" in got and sid in got and "foundation='abc123'" in got,
        got[:300])
    out = rpc_eval(f':rpc.call(:"exjabberd@htch-runtime", Exjabberd.Mod.Jingle, :get_session, ["localhost", "{sid}"]) |> IO.inspect()')
    log("server tracks session as pending", "state: :pending" in out, out.strip()[:160])
    iq_result(B, "j1", b_jid, a_jid)
    log("initiator receives responder's iq-result", "j1" in A.recv_until("j1"))

    accept = (
        f"<iq type='set' id='j2' to='{a_jid}'><jingle xmlns='urn:xmpp:jingle:1' "
        f"action='session-accept' sid='{sid}' responder='{b_jid}'>"
        f"<content creator='initiator' name='audio'>"
        f"<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'/>"
        f"<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1'/></content></jingle></iq>")
    B.send(accept)
    got = A.recv_until("session-accept")
    log("jingle session-accept delivered", "session-accept" in got and sid in got, got[:200])
    out = rpc_eval(f':rpc.call(:"exjabberd@htch-runtime", Exjabberd.Mod.Jingle, :get_session, ["localhost", "{sid}"]) |> IO.inspect()')
    log("server tracks session as active", "state: :active" in out, out.strip()[:160])
    iq_result(A, "j2", a_jid, b_jid)

    transport = (
        f"<iq type='set' id='j3' to='{b_jid}'><jingle xmlns='urn:xmpp:jingle:1' "
        f"action='transport-info' sid='{sid}'>"
        f"<content creator='initiator' name='audio'>"
        f"<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1'>"
        f"<candidate component='1' foundation='def456' generation='0' id='c2' "
        f"ip='192.0.2.1' network='1' port='5001' priority='90' protocol='udp' type='host'/>"
        f"</transport></content></jingle></iq>")
    A.send(transport)
    got = B.recv_until("transport-info")
    log("jingle transport-info (ICE candidate) forwarded verbatim",
        "transport-info" in got and "foundation='def456'" in got, got[:200])
    iq_result(B, "j3", b_jid, a_jid)

    terminate = (
        f"<iq type='set' id='j4' to='{a_jid}'><jingle xmlns='urn:xmpp:jingle:1' "
        f"action='session-terminate' sid='{sid}'><reason><success/></reason></jingle></iq>")
    B.send(terminate)
    got = A.recv_until("session-terminate")
    log("jingle session-terminate delivered", "session-terminate" in got and sid in got, got[:200])
    iq_result(A, "j4", a_jid, b_jid)
    out = rpc_eval(f':rpc.call(:"exjabberd@htch-runtime", Exjabberd.Mod.Jingle, :get_session, ["localhost", "{sid}"]) |> IO.inspect()')
    log("session gone from server list after terminate", "not_found" in out, out.strip()[:120])
    out = rpc_eval(':rpc.call(:"exjabberd@htch-runtime", Exjabberd.Mod.Jingle, :list_sessions, ["localhost"]) |> IO.inspect()')
    log("server session list empty", out.strip() in ("[]", "[ ]") or "[]" in out, out.strip()[:120])

    # --- Jingle errors ---
    A.send(f"<iq type='set' id='e1' to='{b_jid}'><jingle xmlns='urn:xmpp:jingle:1' action='transport-info' sid='no-such-session'><content creator='initiator' name='audio'/></jingle></iq>")
    r = A.recv_until("e1")
    log("unknown session -> unknown-session + item-not-found",
        "unknown-session" in r and "item-not-found" in r, r[:300])
    A.send(f"<iq type='set' id='e2' to='{b_jid}'><jingle xmlns='urn:xmpp:jingle:1' action='session-bogus' sid='x'><content creator='initiator' name='audio'/></jingle></iq>")
    r = A.recv_until("e2")
    log("unknown action -> feature-not-implemented",
        "feature-not-implemented" in r, r[:300])

    # --- extdisco ---
    A.send("<iq type='get' id='x1' to='localhost'><services xmlns='urn:xmpp:extdisco:2'/></iq>")
    r = A.recv_until("x1")
    log("extdisco advertises STUN + TURN with user credentials on 5478",
        "type='stun'" in r and "type='turn'" in r and "port='5478'" in r
        and "username='" in r and f"{andi}@localhost" in r, r[:400])
    A.send("<iq type='get' id='x2' to='localhost'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")
    r = A.recv_until("x2")
    log("server disco advertises jingle + extdisco",
        "urn:xmpp:jingle:1" in r and "urn:xmpp:extdisco:2" in r, r[:300])

    # --- OMEMO: publish devicelist + bundle, fetch from another client ---
    devicelist = lambda ids: "<list xmlns='eu.siacs.conversations.axolotl'>" + "".join(
        f"<device id='{i}'/>" for i in ids) + "</list>"
    bundle = ("<bundle xmlns='eu.siacs.conversations.axolotl'>"
              "<signedPreKeyPublic signedPreKeyId='1'>QUJDREVGR0g=</signedPreKeyPublic>"
              "<signedPreKeySignature>U0lHTkFUVVJF</signedPreKeySignature>"
              "<identityKey>SURFTlRJVFlLRVk=</identityKey><prekeys>"
              "<preKeyPublic preKeyId='1'>UFJFS0VZMQ==</preKeyPublic>"
              "<preKeyPublic preKeyId='2'>UFJFS0VZMg==</preKeyPublic></prekeys></bundle>")
    A.send(f"<iq type='set' id='o1' to='{a_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='eu.siacs.conversations.axolotl.devicelist'><item id='current'>{devicelist([31415, 27182])}</item></publish></pubsub></iq>")
    r = A.recv_until("o1")
    log("omemo devicelist publish (own bare JID)", "type='result'" in r, r[:200])
    A.send(f"<iq type='set' id='o2' to='{a_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='eu.siacs.conversations.axolotl.bundles:31415'><item id='31415'>{bundle}</item></publish></pubsub></iq>")
    r = A.recv_until("o2")
    log("omemo bundle publish (own bare JID)", "type='result'" in r, r[:200])

    B.send(f"<iq type='get' id='o3' to='{a_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='eu.siacs.conversations.axolotl.devicelist'/></pubsub></iq>")
    r = B.recv_until("o3")
    log("peer fetches devicelist (both devices)",
        "device id='31415'" in r and "device id='27182'" in r, r[:300])
    B.send(f"<iq type='get' id='o4' to='{a_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='eu.siacs.conversations.axolotl.bundles:31415'/></pubsub></iq>")
    r = B.recv_until("o4")
    log("peer fetches bundle byte-identical",
        "QUJDREVGR0g=" in r and "UFJFS0VZMg==" in r and "signedPreKeyPublic" in r, r[:300])

    A.send(f"<iq type='set' id='o5' to='{a_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='eu.siacs.conversations.axolotl.devicelist'><item id='current'>{devicelist([999])}</item></publish></pubsub></iq>")
    A.recv_until("o5")
    B.send(f"<iq type='get' id='o6' to='{a_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='eu.siacs.conversations.axolotl.devicelist'/></pubsub></iq>")
    r = B.recv_until("o6")
    log("republish replaces list (max_items 1)",
        "device id='999'" in r and "device id='31415'" not in r, r[:300])

    C.send(f"<iq type='set' id='o7' to='{c_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='eu.siacs.conversations.axolotl.devicelist'><item id='current'>{devicelist([555])}</item></publish></pubsub></iq>")
    C.recv_until("o7")
    B.send(f"<iq type='get' id='o8' to='{c_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='eu.siacs.conversations.axolotl.devicelist'/></pubsub></iq>")
    r = B.recv_until("o8")
    log("per-user isolation (carol's list is hers alone)",
        "device id='555'" in r and "device id='999'" not in r, r[:300])

    B.send(f"<iq type='set' id='o9' to='{a_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='eu.siacs.conversations.axolotl.devicelist'><item id='current'>{devicelist([1])}</item></publish></pubsub></iq>")
    r = B.recv_until("o9")
    log("non-owner publish -> forbidden", "forbidden" in r, r[:300])

    B.send(f"<iq type='get' id='o10' to='{a_bare}'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")
    r = B.recv_until("o10")
    log("disco#items on bare JID lists PEP nodes",
        "eu.siacs.conversations.axolotl.devicelist" in r
        and "eu.siacs.conversations.axolotl.bundles:31415" in r, r[:400])
    B.send(f"<iq type='get' id='o11' to='{a_bare}'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>")
    r = B.recv_until("o11")
    log("disco#info on bare JID advertises urn:xmpp:omemo:0",
        "urn:xmpp:omemo:0" in r, r[:300])
    B.send(f"<iq type='get' id='o12' to='{b_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='eu.siacs.conversations.axolotl.bundles:1'/></pubsub></iq>")
    r = B.recv_until("o12")
    log("unknown bundle node -> item-not-found", "item-not-found" in r, r[:300])

    # Subscribe + republish -> headline notification from bare JID.
    B.send(f"<iq type='set' id='s1' to='{a_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><subscribe node='eu.siacs.conversations.axolotl.devicelist' jid='{b_bare}'/></pubsub></iq>")
    r = B.recv_until("s1")
    log("subscribe to peer devicelist", "subscription" in r, r[:300])
    A.send(f"<iq type='set' id='s2' to='{a_bare}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='eu.siacs.conversations.axolotl.devicelist'><item id='current'>{devicelist([4242])}</item></publish></pubsub></iq>")
    A.recv_until("s2")
    note = B.recv_until("device id='4242'")
    log("republish notifies subscriber (from bare JID)",
        "eu.siacs.conversations.axolotl.devicelist" in note and f"from='{a_bare}'" in note,
        note[:300])

    A.close(); B.close(); C.close()
    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main()
