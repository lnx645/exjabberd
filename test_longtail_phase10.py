#!/usr/bin/env python3
"""Raw-socket live test for the long-tail IQ modules (Fase 10):
vCard (XEP-0054), private storage (XEP-0049), privacy lists
(XEP-0016) + blocking (XEP-0191) incl. router enforcement, last
activity (XEP-0012) and ad-hoc commands (XEP-0050).

Assumes a dev server on 127.0.0.1:5222 (verify.sh boots one).
Users andi/budi/carol (password "secret") are created via RPC when
missing. Prints a SUMMARY line: N/M passed.
"""
import socket, time, sys, re, os, subprocess, base64

HOST, PORT = "127.0.0.1", 5222
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
    r = subprocess.run(["elixir", "--sname", "probe10", "-e", code],
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

def iq(conn, xml, wait="</iq>", timeout=6):
    conn.send(xml)
    return conn.recv_until(wait, timeout=timeout)

def recv_re(conn, pattern, timeout=6):
    """Accumulate until a regex matches; return (ok, text)."""
    end = time.time() + timeout
    acc = ""
    while time.time() < end:
        chunk = conn.recv_until("</iq>", timeout=max(1, int(end - time.time())))
        acc += chunk
        if re.search(pattern, acc, re.S):
            return True, acc
        if not chunk:
            break
    return False, acc

try:
    ensure_users(["andi", "budi", "carol"])
    andi = Conn("andi"); budi = Conn("budi")
    assert login(andi, "andi", "secret", "lt1"), "andi login"
    assert login(budi, "budi", "secret", "lt2"), "budi login"
    print("[SETUP] logins ok", flush=True)

    # ---------------- vCard (XEP-0054) ----------------
    r = iq(andi, "<iq type='set' id='vc1'><vCard xmlns='vcard-temp'>"
                 "<FN>Andi Wijaya</FN><NICKNAME>andiw</NICKNAME>"
                 "<N><FAMILY>Wijaya</FAMILY><GIVEN>Andi</GIVEN></N></vCard></iq>")
    log("vcard: set own -> result", "type='result'" in r and "id='vc1'" in r, r[:200])

    r = iq(andi, "<iq type='get' id='vc2'><vCard xmlns='vcard-temp'/></iq>")
    log("vcard: get own -> FN + nested N survive",
        "Andi Wijaya" in r and "andiw" in r and "<FAMILY>Wijaya</FAMILY>" in r, r[:260])

    r = iq(budi, "<iq type='get' id='vc3' to='andi@localhost'><vCard xmlns='vcard-temp'/></iq>")
    log("vcard: peer gets addressee's card (not own)",
        "Andi Wijaya" in r, r[:260])

    r = iq(budi, "<iq type='get' id='vc4' to='carol@localhost'><vCard xmlns='vcard-temp'/></iq>")
    log("vcard: unset user -> empty vCard result",
        "type='result'" in r and "Andi Wijaya" not in r and "vcard-temp" in r, r[:260])

    # ---------------- Private storage (XEP-0049) ----------------
    r = iq(andi, "<iq type='set' id='pv1'><query xmlns='jabber:iq:private'>"
                 "<storage xmlns='storage:bookmarks'><item jid='romeo@montague.net' name='somepage'/></storage>"
                 "</query></iq>")
    log("private: set -> result", "type='result'" in r, r[:200])

    r = iq(andi, "<iq type='get' id='pv2'><query xmlns='jabber:iq:private'>"
                 "<storage xmlns='storage:bookmarks'/></query></iq>")
    log("private: get returns stored element verbatim",
        "storage:bookmarks" in r and "somepage" in r, r[:300])

    r = iq(andi, "<iq type='get' id='pv3'><query xmlns='jabber:iq:private'>"
                 "<storage xmlns='storage:roster'/></query></iq>")
    log("private: get unset namespace -> empty result",
        "type='result'" in r and "somepage" not in r, r[:300])

    r = iq(budi, "<iq type='get' id='pv4'><query xmlns='jabber:iq:private'>"
                 "<storage xmlns='storage:bookmarks'/></query></iq>")
    log("private: other user cannot see andi's data",
        "type='result'" in r and "somepage" not in r, r[:300])

    # ---------------- Privacy lists (XEP-0016) ----------------
    r = iq(andi, "<iq type='set' id='pr1'><query xmlns='jabber:iq:privacy'>"
                 "<list name='blocklist-test'>"
                 "<item type='jid' value='budi@localhost' action='deny' order='1'/>"
                 "</list></query></iq>")
    log("privacy: set list -> result", "type='result'" in r, r[:200])

    r = iq(andi, "<iq type='get' id='pr2'><query xmlns='jabber:iq:privacy'>"
                 "<list name='blocklist-test'/></query></iq>")
    log("privacy: get list -> item round-trips",
        "budi@localhost" in r and "deny" in r and "blocklist-test" in r, r[:300])

    r = iq(andi, "<iq type='get' id='pr3'><query xmlns='jabber:iq:privacy'/></iq>")
    log("privacy: overview lists the list name", "blocklist-test" in r, r[:300])

    r = iq(andi, "<iq type='set' id='pr4'><query xmlns='jabber:iq:privacy'>"
                 "<default name='blocklist-test'/></query></iq>")
    r2 = iq(andi, "<iq type='get' id='pr5'><query xmlns='jabber:iq:privacy'/></iq>")
    log("privacy: set default -> overview shows default",
        "type='result'" in r and "<default name='blocklist-test'/>" in r2.replace('"', "'"), r2[:300])

    andi.drain(); budi.drain()
    budi.send("<message type='chat' to='andi@localhost' id='pm1'><body>privacy-secret-1</body></message>")
    r = andi.recv_until("privacy-secret-1", timeout=3)
    log("privacy: default deny list blocks message delivery", "privacy-secret-1" not in r, r[:160])

    r = iq(andi, "<iq type='set' id='pr6'><query xmlns='jabber:iq:privacy'><default/></query></iq>")
    log("privacy: remove default -> result", "type='result'" in r, r[:160])
    budi.send("<message type='chat' to='andi@localhost' id='pm2'><body>privacy-open-2</body></message>")
    r = andi.recv_until("privacy-open-2", timeout=6)
    log("privacy: after default removed, message delivered", "privacy-open-2" in r, r[:200])

    r = iq(andi, "<iq type='set' id='pr7'><query xmlns='jabber:iq:privacy'>"
                 "<list name='blocklist-test'/></query></iq>")
    r2 = iq(andi, "<iq type='get' id='pr8'><query xmlns='jabber:iq:privacy'>"
                  "<list name='blocklist-test'/></query></iq>")
    log("privacy: delete list -> get returns item-not-found",
        "type='result'" in r and "item-not-found" in r2, r2[:240])

    # ---------------- Blocking (XEP-0191) ----------------
    # The server also pushes a blocklist <iq type='set'> to the user's
    # sessions, so reads here are matched on the result stanza by id.
    andi.send("<iq type='set' id='bl1'><block xmlns='urn:xmpp:blocking'>"
              "<item jid='budi@localhost'/></block></iq>")
    ok, r = recv_re(andi, r"<iq[^>]*id='bl1'[^>]*type='result'")
    log("blocking: block -> result", ok, r[:200])

    r = iq(andi, "<iq type='get' id='bl2'><blocklist xmlns='urn:xmpp:blocking'/></iq>")
    log("blocking: blocklist get contains budi", "budi@localhost" in r, r[:260])

    andi.drain(); budi.drain()
    budi.send("<message type='chat' to='andi@localhost' id='bm1'><body>blocked-msg-1</body></message>")
    r = andi.recv_until("blocked-msg-1", timeout=3)
    log("blocking: blocked user's message not delivered", "blocked-msg-1" not in r, r[:160])

    budi.send("<iq type='get' id='bp1' to='andi@localhost'><ping xmlns='urn:xmpp:ping'/></iq>")
    r = budi.recv_until("service-unavailable", timeout=6)
    log("blocking: blocked user's IQ -> service-unavailable", "service-unavailable" in r, r[:240])

    andi.send("<iq type='set' id='bl3'><unblock xmlns='urn:xmpp:blocking'>"
              "<item jid='budi@localhost'/></unblock></iq>")
    ok3, _r3 = recv_re(andi, r"<iq[^>]*id='bl3'[^>]*type='result'")
    andi.send("<iq type='get' id='bl4'><blocklist xmlns='urn:xmpp:blocking'/></iq>")
    ok4, r4 = recv_re(andi, r"<iq[^>]*id='bl4'[^>]*>(.*?)</iq>")
    m4 = re.search(r"<iq[^>]*id='bl4'[^>]*>(.*?)</iq>", r4, re.S)
    log("blocking: unblock -> blocklist empty",
        ok3 and ok4 and m4 is not None and "budi@localhost" not in m4.group(1), r4[:300])

    budi.send("<message type='chat' to='andi@localhost' id='bm2'><body>unblocked-msg-2</body></message>")
    r = andi.recv_until("unblocked-msg-2", timeout=6)
    log("blocking: after unblock, message delivered", "unblocked-msg-2" in r, r[:200])

    # ---------------- Last activity (XEP-0012) ----------------
    r = iq(andi, "<iq type='get' id='la1' to='localhost'><query xmlns='jabber:iq:last'/></iq>")
    m = re.search(r"seconds='(\d+)'", r)
    log("last: server query -> uptime seconds", m is not None, r[:240])

    carol = Conn("carol")
    assert login(carol, "carol", "secret", "lt3"), "carol login"
    carol.close()
    time.sleep(2.5)
    r = iq(andi, "<iq type='get' id='la2' to='carol@localhost'><query xmlns='jabber:iq:last'/></iq>")
    m = re.search(r"seconds='(\d+)'", r)
    log("last: offline user -> seconds since logout >= 1",
        m is not None and int(m.group(1)) >= 1, r[:240])

    # ---------------- Ad-hoc commands (XEP-0050) ----------------
    r = iq(andi, "<iq type='get' id='ad1' to='localhost'>"
                 "<query xmlns='http://jabber.org/protocol/disco#items' node='http://jabber.org/protocol/commands'/></iq>")
    log("adhoc: disco#items on commands node lists commands",
        "admin#get-online-users" in r and "admin#announce" in r, r[:340])

    r = iq(andi, "<iq type='get' id='ad2' to='localhost'>"
                 "<query xmlns='http://jabber.org/protocol/disco#info' node='http://jabber.org/protocol/commands'/></iq>")
    log("adhoc: disco#info on commands node -> command-list identity",
        "command-list" in r, r[:300])

    r = iq(andi, "<iq type='set' id='ad3' to='localhost'>"
                 "<command xmlns='http://jabber.org/protocol/commands' "
                 "node='http://jabber.org/protocol/admin#get-online-users' action='execute'/></iq>")
    log("adhoc: get-online-users completes with jid-multi result",
        "status='completed'" in r and "andi@localhost" in r, r[:360])

    r = iq(andi, "<iq type='set' id='ad4' to='localhost'>"
                 "<command xmlns='http://jabber.org/protocol/commands' "
                 "node='http://jabber.org/protocol/admin#announce' action='execute'/></iq>")
    m = re.search(r"sessionid='([^']+)'", r)
    log("adhoc: announce step 1 -> executing + sessionid + form",
        "status='executing'" in r and m is not None and "var='subject'" in r, r[:360])

    if m:
        sid = m.group(1)
        budi.drain()
        r = iq(andi, f"<iq type='set' id='ad5' to='localhost'>"
                     f"<command xmlns='http://jabber.org/protocol/commands' "
                     f"node='http://jabber.org/protocol/admin#announce' sessionid='{sid}' action='complete'>"
                     f"<x xmlns='jabber:x:data' type='submit'>"
                     f"<field var='subject'><value>Pengumuman</value></field>"
                     f"<field var='body'><value>halo-semua-anggota</value></field>"
                     f"</x></command></iq>")
        log("adhoc: announce complete -> completed", "status='completed'" in r, r[:300])
        r = budi.recv_until("halo-semua-anggota", timeout=6)
        log("adhoc: announcement delivered to online user", "halo-semua-anggota" in r, r[:240])
    else:
        log("adhoc: announce complete -> completed", False, "no sessionid")
        log("adhoc: announcement delivered to online user", False, "no sessionid")

    andi.close(); budi.close()
finally:
    passed = sum(1 for _, ok in results if ok)
    print(f"SUMMARY: {passed}/{len(results)} passed")
    sys.exit(0 if passed == len(results) and results else 1)
