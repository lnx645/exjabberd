#!/usr/bin/env python3
"""Raw-socket live test for MUC administration (Fase 12, XEP-0045):
owner affiliation for the creator, muc#owner config form get/set,
muc#admin affiliation lists and changes, members-only and
password-protected join gating with presence errors, subject
changes, kick (307), ban (301 + forbidden rejoin), MAM room-archive
membership check, and room destruction.

Assumes a dev server on 127.0.0.1:5222. Users andi/budi/carol/dave
(password "secret") are created via RPC when missing. Room names
carry a per-run suffix so repeated runs start from empty rooms.
"""
import socket, time, sys, re, os, subprocess, base64

HOST, PORT = "127.0.0.1", 5222
CONF = "conference.localhost"
RUN = str(int(time.time()))[-6:]
R1 = f"fase12a-{RUN}"
R2 = f"fase12b-{RUN}"
results = []

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
    r = subprocess.run(["elixir", "--sname", "probe12", "-e", code],
                       capture_output=True, text=True, timeout=60, env=env)
    return ":ok" in (r.stdout + r.stderr)

def ensure_users(users):
    for u in users:
        ok = rpc_create(u)
        print(f"[SETUP] user {u}@localhost: {'ok' if ok else 'FAILED'}", flush=True)
        if not ok:
            print("SETUP FAILED: is the dev server running on 5222?", file=sys.stderr)
            sys.exit(2)

def log(name, ok, detail=""):
    results.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail[:220]}")

class Conn:
    def __init__(self, name):
        self.name = name
        self.s = socket.create_connection((HOST, PORT), timeout=10)
        self.s.settimeout(6)
        self.buf = b""
    def send(self, data):
        if isinstance(data, str): data = data.encode()
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
    def drain(self, timeout=0.7):
        self.recv_until("\x00NEVER\x00", timeout=timeout)
    def close(self):
        try: self.s.close()
        except Exception: pass

STREAM_OPEN = ("<?xml version='1.0'?><stream:stream to='localhost' "
               "xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")

def login(conn, user, pw, resource="test"):
    conn.send(STREAM_OPEN)
    conn.recv_until("stream:features")
    b64 = base64.b64encode(f"\0{user}\0{pw}".encode()).decode()
    conn.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{b64}</auth>")
    r = conn.recv_until("success")
    if "<success" not in r:
        return False
    conn.send(STREAM_OPEN)
    conn.recv_until("stream:features")
    conn.send(f"<iq type='set' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>{resource}</resource></bind></iq>")
    r = conn.recv_until("bind")
    return "<jid>" in r

def join(conn, room, nick, password=None):
    pw = f"<password>{password}</password>" if password is not None else ""
    conn.send(f"<presence to='{room}@{CONF}/{nick}'><x xmlns='http://jabber.org/protocol/muc'>{pw}</x></presence>")

def iq(conn, xml, wait="</iq>"):
    conn.send(xml)
    return conn.recv_until(wait)

def config_submit(conn, iqid, room, fields):
    body = "".join(
        f"<field var='{k}'><value>{v}</value></field>" for k, v in fields.items())
    return iq(conn, f"<iq type='set' id='{iqid}' to='{room}@{CONF}'>"
                    f"<query xmlns='http://jabber.org/protocol/muc#owner'>"
                    f"<x xmlns='jabber:x:data' type='submit'>"
                    f"<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#roomconfig</value></field>"
                    f"{body}</x></query></iq>")

BASE_FORM = {
    "muc#roomconfig_roomname": "Ruang Uji",
    "muc#roomconfig_persistentroom": "1",
    "muc#roomconfig_publicroom": "1",
    "muc#roomconfig_passwordprotectedroom": "0",
    "muc#roomconfig_membersonly": "0",
    "muc#roomconfig_maxusers": "200",
}

try:
    ensure_users(["andi", "budi", "carol", "dave"])
    andi = Conn("andi"); budi = Conn("budi"); carol = Conn("carol"); dave = Conn("dave")
    assert login(andi, "andi", "secret", "m12a"), "andi login"
    assert login(budi, "budi", "secret", "m12b"), "budi login"
    assert login(carol, "carol", "secret", "m12c"), "carol login"
    assert login(dave, "dave", "secret", "m12d"), "dave login"
    print("[SETUP] logins ok", flush=True)

    # 1. Creator becomes owner + moderator (110/201 self-presence).
    join(andi, R1, "andi")
    r = andi.recv_until("affiliation='owner'")
    log("muc: creator self-presence owner/moderator + 110/201",
        "affiliation='owner'" in r and "role='moderator'" in r and "code='201'" in r and "code='110'" in r,
        r[:300])

    # 2. Second user joins as participant; groupchat works.
    join(budi, R1, "budi")
    r = budi.recv_until("code='110'")
    log("muc: joiner participant", "role='participant'" in r, r[:260])
    andi.recv_until(f"{R1}@{CONF}/budi")
    budi.send(f"<message type='groupchat' to='{R1}@{CONF}'><body>pesan-room-{RUN}</body></message>")
    r = andi.recv_until(f"pesan-room-{RUN}")
    log("muc: groupchat delivered", f"pesan-room-{RUN}" in r, r[:200])

    # 3. Non-owner cannot read the config form.
    r = iq(budi, f"<iq type='get' id='ow1' to='{R1}@{CONF}'><query xmlns='http://jabber.org/protocol/muc#owner'/></iq>")
    log("muc: non-owner config get -> forbidden", "forbidden" in r, r[:220])

    # 4. Owner gets the config form.
    r = iq(andi, f"<iq type='get' id='ow2' to='{R1}@{CONF}'><query xmlns='http://jabber.org/protocol/muc#owner'/></iq>")
    m = re.search(r"var='muc#roomconfig_membersonly'><value>(\d)</value>", r)
    log("muc: owner config form with current values",
        "muc#roomconfig" in r and m is not None and m.group(1) == "0", r[:300])

    # 5. Admin: owner list contains the creator.
    r = iq(andi, f"<iq type='get' id='ad1' to='{R1}@{CONF}'><query xmlns='http://jabber.org/protocol/muc#admin'>"
                 f"<item affiliation='owner'/></query></iq>")
    log("muc: admin get owner list", "andi@localhost" in r and "affiliation='owner'" in r, r[:260])

    # 6. Admin: grant membership -> presence update + member list.
    r = iq(andi, f"<iq type='set' id='ad2' to='{R1}@{CONF}'><query xmlns='http://jabber.org/protocol/muc#admin'>"
                 f"<item jid='budi@localhost' affiliation='member'/></query></iq>")
    r2 = budi.recv_until("affiliation='member'")
    r3 = iq(andi, f"<iq type='get' id='ad3' to='{R1}@{CONF}'><query xmlns='http://jabber.org/protocol/muc#admin'>"
                  f"<item affiliation='member'/></query></iq>")
    log("muc: grant member -> result + presence update + list",
        "type='result'" in r and "affiliation='member'" in r2 and "budi@localhost" in r3,
        (r2 + "|" + r3)[:300])

    # 7. Owner sets members-only; form reflects it.
    form = dict(BASE_FORM); form["muc#roomconfig_membersonly"] = "1"
    r = config_submit(andi, "ow3", R1, form)
    r2 = iq(andi, f"<iq type='get' id='ow4' to='{R1}@{CONF}'><query xmlns='http://jabber.org/protocol/muc#owner'/></iq>")
    m = re.search(r"var='muc#roomconfig_membersonly'><value>(\d)</value>", r2)
    log("muc: set members-only -> form shows 1",
        "type='result'" in r and m is not None and m.group(1) == "1", r2[:300])

    # 8. Non-member join to members-only room -> registration-required.
    join(carol, R1, "carol")
    r = carol.recv_until("registration-required")
    log("muc: members-only rejects non-member", "registration-required" in r and "type='error'" in r, r[:260])

    # 9. Grant membership -> join succeeds.
    iq(andi, f"<iq type='set' id='ad4' to='{R1}@{CONF}'><query xmlns='http://jabber.org/protocol/muc#admin'>"
             f"<item jid='carol@localhost' affiliation='member'/></query></iq>")
    join(carol, R1, "carol")
    r = carol.recv_until("code='110'")
    log("muc: member joins members-only room", "code='110'" in r, r[:240])

    # 10. Subject change is broadcast to occupants.
    budi.send(f"<message type='groupchat' to='{R1}@{CONF}'><subject>Topik-{RUN}</subject></message>")
    r = andi.recv_until(f"Topik-{RUN}")
    log("muc: subject broadcast", f"Topik-{RUN}" in r and "<subject>" in r, r[:240])

    # 11. Kick via admin item role=none -> 307 + reason; rejoin works.
    r = iq(andi, f"<iq type='set' id='ad5' to='{R1}@{CONF}'><query xmlns='http://jabber.org/protocol/muc#admin'>"
                 f"<item nick='carol' role='none'><reason>melanggar-{RUN}</reason></item></query></iq>")
    r2 = carol.recv_until("code='307'")
    log("muc: kick -> 307 + reason to victim",
        "type='result'" in r and "code='307'" in r2 and f"melanggar-{RUN}" in r2, r2[:300])
    join(carol, R1, "carol")
    r = carol.recv_until("code='110'")
    log("muc: kicked member may rejoin", "code='110'" in r, r[:200])

    # 12. Ban via affiliation=outcast -> 301, rejoin forbidden.
    iq(andi, f"<iq type='set' id='ad6' to='{R1}@{CONF}'><query xmlns='http://jabber.org/protocol/muc#admin'>"
             f"<item jid='carol@localhost' affiliation='outcast'/></query></iq>")
    r = carol.recv_until("code='301'")
    log("muc: ban -> 301 unavailable to victim", "code='301'" in r, r[:260])
    join(carol, R1, "carol")
    r = carol.recv_until("forbidden")
    log("muc: banned user rejoin -> forbidden", "forbidden" in r and "type='error'" in r, r[:240])

    # 13. MAM room archive: outsider forbidden, member allowed.
    r = iq(dave, f"<iq type='set' id='mm1' to='{R1}@{CONF}'><query xmlns='urn:xmpp:mam:2'/></iq>")
    log("muc: MAM room query by outsider -> forbidden", "forbidden" in r, r[:240])
    budi.drain()
    budi.send(f"<iq type='set' id='mm2' to='{R1}@{CONF}'><query xmlns='urn:xmpp:mam:2'/></iq>")
    r = budi.recv_until(f"pesan-room-{RUN}")
    r2 = budi.recv_until("<fin")
    log("muc: MAM room query by member returns history",
        f"pesan-room-{RUN}" in r and "<fin" in r2, (r + r2)[:300])

    # 14. Password-protected room: no/wrong password rejected, correct admitted.
    join(andi, R2, "andi")
    andi.recv_until("code='201'")
    form = dict(BASE_FORM)
    form["muc#roomconfig_passwordprotectedroom"] = "1"
    form["muc#roomconfig_roomsecret"] = "s3cret"
    r = config_submit(andi, "ow5", R2, form)
    log("muc: set room password -> result", "type='result'" in r, r[:160])
    join(dave, R2, "dave")
    r = dave.recv_until("not-authorized")
    log("muc: join without password -> not-authorized", "not-authorized" in r, r[:220])
    join(dave, R2, "dave", password="salah")
    r = dave.recv_until("not-authorized")
    log("muc: join with wrong password -> not-authorized", "not-authorized" in r, r[:220])
    join(dave, R2, "dave", password="s3cret")
    r = dave.recv_until("code='110'")
    log("muc: join with correct password -> in", "code='110'" in r, r[:220])

    # 15. Destroy: occupants notified, room recreated fresh afterwards.
    r = iq(andi, f"<iq type='set' id='ow6' to='{R2}@{CONF}'><query xmlns='http://jabber.org/protocol/muc#owner'>"
                 f"<destroy jid='{R2}@{CONF}'/></query></iq>")
    r2 = dave.recv_until("<destroy")
    log("muc: destroy -> result + occupant notified with <destroy/>",
        "type='result'" in r and "<destroy" in r2, r2[:260])
    join(andi, R2, "andi")
    r = andi.recv_until("code='201'")
    log("muc: destroyed room can be recreated (201)", "code='201'" in r, r[:200])

    andi.close(); budi.close(); carol.close(); dave.close()
finally:
    passed = sum(1 for _, ok in results if ok)
    print(f"SUMMARY: {passed}/{len(results)} passed")
    sys.exit(0 if passed == len(results) and results else 1)
