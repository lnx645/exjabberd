#!/usr/bin/env python3
"""Raw-socket live probe for XEP-0313 (MAM) and XEP-0060 (PubSub)
against exjabberd C2S on 127.0.0.1:5222.

Usage: start the server first (ELIXIR_ERL_OPTIONS="+fnu -sname
exjabberd" mix run --no-halt), then: python3 test_mam_pubsub.py

Users are created fresh per run (suffix from the run id) via RPC so
each archive starts empty and counts are exact. Records PASS/FAIL
per check with wire transcript excerpts.
"""
import socket, time, sys, re, base64, subprocess, uuid, os

HOST, PORT = "127.0.0.1", 5222
RUN = uuid.uuid4().hex[:8]
results = []

def log(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail}")

def rpc_create(user):
    # Create a test account on the running node (same helper the
    # README documents); already-existing users report :ok too.
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
        """Return whatever arrives within timeout ('' on timeout)."""
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

STREAM_OPEN = ("<?xml version='1.0'?><stream:stream to='localhost' "
               "xmlns='jabber:client' "
               "xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")

def login(conn, user, pw, resource):
    conn.send(STREAM_OPEN)
    r = conn.recv_until("stream:features")
    assert "stream:features" in r, f"{conn.name}: no features: {r[:200]}"
    b64 = base64.b64encode(f"\0{user}\0{pw}".encode()).decode()
    conn.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' "
              f"mechanism='PLAIN'>{b64}</auth>")
    r2 = conn.recv_until("success")
    assert "<success" in r2, f"{conn.name}: auth failed: {r2[:200]}"
    conn.send(STREAM_OPEN)
    conn.recv_until("stream:features")
    conn.send(f"<iq type='set' id='bind1'><bind "
              f"xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
              f"<resource>{resource}</resource></bind></iq>")
    r4 = conn.recv_until("bind")
    m = re.search(r"<jid>([^<]+)</jid>", r4)
    assert m, f"{conn.name}: bind failed: {r4[:200]}"
    return m.group(1)

# --- MAM wire parsing helpers ---

def mam_results(xml):
    """[(archive_id, body, stamp)] from <result> messages, in order."""
    out = []
    for m in re.finditer(
            r"<result[^>]*? id='([^']+)'[^>]*>.*?"
            r"<delay[^>]*stamp='([^']+)'[^>]*>.*?"
            r"<message[^>]*>.*?<body>([^<]*)</body>",
            xml, re.DOTALL):
        out.append((m.group(1), m.group(3), m.group(2)))
    return out

def mam_fin(xml):
    m = re.search(r"<fin[^>]*complete='([^']+)'[^>]*>.*?<count>(\d+)</count>",
                  xml, re.DOTALL)
    if not m:
        return None
    first = re.search(r"<first[^>]*>([^<]*)</first>", xml)
    last = re.search(r"<last[^>]*>([^<]*)</last>", xml)
    return {"complete": m.group(1),
            "first": first.group(1) if first else None,
            "last": last.group(1) if last else None,
            "count": int(m.group(2))}

def mam_query(conn, qid, extra=""):
    conn.send(f"<iq type='set' id='{qid}'><query xmlns='urn:xmpp:mam:2' "
              f"queryid='{qid}'>{extra}</query></iq>")
    time.sleep(0.7)
    return conn.recv_any(3)

def xdata_field(var, value):
    return (f"<field var='{var}'><value>{value}</value></field>")

def mam_xdata(**fields):
    inner = "".join(xdata_field(k, v) for k, v in fields.items())
    return (f"<x xmlns='jabber:x:data' type='submit'>{inner}</x>")

def utc_now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

# --- main ---

def main():
    andi_u, budi_u, carol_u = f"mamandi{RUN}", f"mambudi{RUN}", f"mamcarol{RUN}"
    for u in (andi_u, budi_u, carol_u):
        ok = rpc_create(u)
        log(f"create user {u}", ok)

    andi = Conn("andi")
    budi = Conn("budi")
    carol = Conn("carol")
    try:
        login(andi, andi_u, "secret", "p1")
        log("andi login", True)
        login(budi, budi_u, "secret", "p1")
        log("budi login", True)
        login(carol, carol_u, "secret", "p1")
        log("carol login", True)
        andi.drain(); budi.drain(); carol.drain()

        # ---------- disco ----------
        andi.send("<iq type='get' id='di1' to='localhost'><query "
                  "xmlns='http://jabber.org/protocol/disco#info'/></iq>")
        r = andi.recv_until("di1")
        log("disco#info advertises urn:xmpp:mam:2",
            "urn:xmpp:mam:2" in r, r[:200])
        log("disco#info advertises pubsub",
            "http://jabber.org/protocol/pubsub" in r, r[:200])
        andi.send("<iq type='get' id='di2'><query "
                  "xmlns='http://jabber.org/protocol/disco#items'/></iq>")
        r = andi.recv_until("di2")
        log("disco#items lists pubsub.localhost",
            "pubsub.localhost" in r, r[:300])
        log("disco#items lists conference.localhost",
            "conference.localhost" in r, r[:300])
        andi.send("<iq type='get' id='di3' to='pubsub.localhost'><query "
                  "xmlns='http://jabber.org/protocol/disco#info'/></iq>")
        r = andi.recv_until("di3")
        log("disco#info pubsub.localhost identity",
            "category='pubsub'" in r and "type='service'" in r, r[:300])

        # ---------- MAM prefs ----------
        andi.send("<iq type='get' id='pf1'><prefs "
                  "xmlns='urn:xmpp:mam:2'/></iq>")
        r = andi.recv_until("pf1")
        log("mam prefs get default always",
            "default='always'" in r and "type='result'" in r, r[:250])

        # ---------- MAM archive + query ----------
        # Small pauses between sends: the two users archive in
        # separate C2S processes, so messages sent in the same
        # millisecond have no defined cross-process order (the same
        # race exists in ejabberd's send/receive hooks). Human-scale
        # spacing makes the expected order deterministic.
        tag = f"MAMT-{RUN}"
        andi.send(f"<message type='chat' to='{budi_u}@localhost' id='a1'>"
                  f"<body>{tag} satu</body></message>")
        time.sleep(0.4)
        andi.send(f"<message type='chat' to='{budi_u}@localhost' id='a2'>"
                  f"<body>{tag} dua</body></message>")
        time.sleep(0.4)
        budi.send(f"<message type='chat' to='{andi_u}@localhost' id='b1'>"
                  f"<body>{tag} balas</body></message>")
        time.sleep(1)
        budi.drain(); andi.drain()

        # Each side's archive holds BOTH sides of the conversation
        # (sent messages via the send hook, received via the receive
        # hook), oldest first.
        r = mam_query(budi, "q1")
        res = mam_results(r)
        fin = mam_fin(r)
        bodies = [b for _, b, _ in res]
        log("mam query returns budi's 3 (2 inbound + 1 sent) in order",
            bodies == [f"{tag} satu", f"{tag} dua", f"{tag} balas"],
            f"bodies={bodies} fin={fin}")
        log("mam results carry delay stamp + id",
            all(i and s.endswith("Z") for i, _, s in res),
            f"res={res}")
        log("mam fin count=3 complete=true + first/last",
            fin and fin["count"] == 3 and fin["complete"] == "true"
            and fin["first"] == res[0][0] and fin["last"] == res[2][0],
            f"fin={fin}")

        r = mam_query(andi, "q2")
        res = mam_results(r)
        bodies = [b for _, b, _ in res]
        log("mam query returns andi's 3 (2 sent + 1 received)",
            bodies == [f"{tag} satu", f"{tag} dua", f"{tag} balas"],
            f"bodies={bodies}")

        # with filter: the peer is the other party of the
        # conversation, so all three match with=andi for budi.
        r = mam_query(budi, "q3", mam_xdata(**{"with": f"{andi_u}@localhost"}))
        res = mam_results(r)
        log("mam with=andi returns 3",
            len(res) == 3, f"n={len(res)}")
        r = mam_query(budi, "q4", mam_xdata(**{"with": f"{carol_u}@localhost"}))
        res = mam_results(r)
        fin = mam_fin(r)
        log("mam with=carol returns 0",
            len(res) == 0 and fin and fin["count"] == 0, f"fin={fin}")

        # start/end filter
        andi.send(f"<message type='chat' to='{budi_u}@localhost' id='a3'>"
                  f"<body>{tag} sebelum</body></message>")
        time.sleep(1.2)
        mid = utc_now_iso()
        time.sleep(0.3)
        andi.send(f"<message type='chat' to='{budi_u}@localhost' id='a4'>"
                  f"<body>{tag} sesudah</body></message>")
        time.sleep(1)
        budi.drain()
        r = mam_query(budi, "q5", mam_xdata(start=mid))
        bodies = [b for _, b, _ in mam_results(r)]
        log("mam start filter keeps only later message",
            bodies == [f"{tag} sesudah"], f"bodies={bodies}")
        r = mam_query(budi, "q6", mam_xdata(end=mid))
        bodies = [b for _, b, _ in mam_results(r)]
        log("mam end filter keeps only earlier messages",
            bodies == [f"{tag} satu", f"{tag} dua", f"{tag} balas",
                       f"{tag} sebelum"],
            f"bodies={bodies}")

        # RSM paging (budi archive with andi now has 5 messages)
        r = mam_query(budi, "q7",
                      mam_xdata(**{"with": f"{andi_u}@localhost"}) +
                      "<set xmlns='http://jabber.org/protocol/rsm'>"
                      "<max>2</max></set>")
        res = mam_results(r)
        fin = mam_fin(r)
        log("mam rsm max=2 returns first 2, complete=false",
            [b for _, b, _ in res] == [f"{tag} satu", f"{tag} dua"]
            and fin and fin["count"] == 5 and fin["complete"] == "false",
            f"bodies={[b for _, b, _ in res]} fin={fin}")
        first_id = res[1][0]
        r = mam_query(budi, "q8",
                      mam_xdata(**{"with": f"{andi_u}@localhost"}) +
                      "<set xmlns='http://jabber.org/protocol/rsm'>"
                      f"<max>2</max><after>{first_id}</after></set>")
        res = mam_results(r)
        log("mam rsm after returns next 2",
            [b for _, b, _ in res] == [f"{tag} balas", f"{tag} sebelum"],
            f"bodies={[b for _, b, _ in res]}")
        last_id = res[1][0]
        r = mam_query(budi, "q9",
                      mam_xdata(**{"with": f"{andi_u}@localhost"}) +
                      "<set xmlns='http://jabber.org/protocol/rsm'>"
                      f"<max>2</max><before>{last_id}</before></set>")
        res = mam_results(r)
        log("mam rsm before returns previous 2",
            [b for _, b, _ in res] == [f"{tag} dua", f"{tag} balas"],
            f"bodies={[b for _, b, _ in res]}")
        r = mam_query(budi, "q10",
                      mam_xdata(**{"with": f"{andi_u}@localhost"}) +
                      "<set xmlns='http://jabber.org/protocol/rsm'>"
                      "<max>2</max><before/></set>")
        res = mam_results(r)
        log("mam rsm empty before returns last page",
            [b for _, b, _ in res] == [f"{tag} sebelum", f"{tag} sesudah"],
            f"bodies={[b for _, b, _ in res]}")

        # ---------- MAM prefs never/always (carol as subject) ----------
        carol.send("<iq type='set' id='pf2'><prefs xmlns='urn:xmpp:mam:2' "
                  "default='never'><always/><never/></prefs></iq>")
        r = carol.recv_until("pf2")
        log("mam prefs set never",
            "type='result'" in r and "default='never'" in r, r[:250])
        andi.send(f"<message type='chat' to='{carol_u}@localhost' id='a5'>"
                  f"<body>{tag} jangan-arsip</body></message>")
        time.sleep(1)
        carol.drain()
        r = mam_query(carol, "q11")
        res = mam_results(r)
        log("mam prefs never: message not archived",
            len(res) == 0, f"n={len(res)}")
        carol.send("<iq type='set' id='pf3'><prefs xmlns='urn:xmpp:mam:2' "
                  "default='always'><always/><never/></prefs></iq>")
        carol.recv_until("pf3")
        andi.send(f"<message type='chat' to='{carol_u}@localhost' id='a6'>"
                  f"<body>{tag} arsip-lagi</body></message>")
        time.sleep(1)
        carol.drain()
        r = mam_query(carol, "q12")
        bodies = [b for _, b, _ in mam_results(r)]
        log("mam prefs always again: message archived",
            bodies == [f"{tag} arsip-lagi"], f"bodies={bodies}")

        # ---------- MUC MAM ----------
        room = f"mamroom{RUN}@conference.localhost"
        andi.send(f"<presence to='{room}/andi-nick'/>")
        budi.send(f"<presence to='{room}/budi-nick'/>")
        time.sleep(1)
        andi.drain(); budi.drain()
        andi.send(f"<message type='groupchat' to='{room}' id='g1'>"
                  f"<body>{tag} obrolan-ruang</body></message>")
        time.sleep(1)
        budi.drain()
        andi.send(f"<iq type='set' id='qm1' to='{room}'><query "
                  f"xmlns='urn:xmpp:mam:2' queryid='qm1'/></iq>")
        time.sleep(0.7)
        r = andi.recv_any(3)
        bodies = [b for _, b, _ in mam_results(r)]
        fin = mam_fin(r)
        log("mam muc query returns room message",
            bodies == [f"{tag} obrolan-ruang"] and fin and fin["count"] == 1,
            f"bodies={bodies} fin={fin}")

        # ---------- PubSub ----------
        node = f"news-{RUN}"
        andi.send(f"<iq type='set' id='s1' to='pubsub.localhost'><pubsub "
                  f"xmlns='http://jabber.org/protocol/pubsub'>"
                  f"<create node='{node}'/></pubsub></iq>")
        r = andi.recv_until("s1")
        log("pubsub create node",
            "type='result'" in r, r[:200])
        andi.send(f"<iq type='set' id='s2' to='pubsub.localhost'><pubsub "
                  f"xmlns='http://jabber.org/protocol/pubsub'>"
                  f"<create node='{node}'/></pubsub></iq>")
        r = andi.recv_until("s2")
        log("pubsub duplicate create -> conflict",
            "type='error'" in r and "conflict" in r, r[:250])
        andi.send(f"<iq type='get' id='s3' to='pubsub.localhost'><query "
                  f"xmlns='http://jabber.org/protocol/disco#items'/></iq>")
        r = andi.recv_until("s3")
        log("pubsub disco#items lists the node",
            f"node='{node}'" in r, r[:300])

        budi.send(f"<iq type='set' id='s4' to='pubsub.localhost'><pubsub "
                  f"xmlns='http://jabber.org/protocol/pubsub'>"
                  f"<subscribe node='{node}' jid='{budi_u}@localhost'/>"
                  f"</pubsub></iq>")
        r = budi.recv_until("s4")
        m = re.search(r"subid='([^']+)'", r)
        log("pubsub subscribe -> subscribed + subid",
            "subscription='subscribed'" in r and m is not None, r[:300])

        andi.send(f"<iq type='set' id='s5' to='pubsub.localhost'><pubsub "
                  f"xmlns='http://jabber.org/protocol/pubsub'>"
                  f"<publish node='{node}'><item id='it1'>"
                  f"<entry>{tag} berita-satu</entry></item>"
                  f"</publish></pubsub></iq>")
        r = andi.recv_until("s5")
        log("pubsub publish by owner ok",
            "type='result'" in r, r[:200])
        time.sleep(0.7)
        r = budi.recv_any(2)
        log("pubsub subscriber receives event notification",
            "pubsub#event" in r and f"{tag} berita-satu" in r
            and "it1" in r, r[:500])

        budi.send(f"<iq type='set' id='s6' to='pubsub.localhost'><pubsub "
                  f"xmlns='http://jabber.org/protocol/pubsub'>"
                  f"<publish node='{node}'><item id='it2'>"
                  f"<entry>{tag} dari-budi</entry></item>"
                  f"</publish></pubsub></iq>")
        r = budi.recv_until("s6")
        log("pubsub publish by non-publisher -> forbidden",
            "type='error'" in r and "forbidden" in r, r[:250])

        budi.send(f"<iq type='get' id='s7' to='pubsub.localhost'><pubsub "
                  f"xmlns='http://jabber.org/protocol/pubsub'>"
                  f"<items node='{node}'/></pubsub></iq>")
        r = budi.recv_until("s7")
        log("pubsub get items returns published item",
            "it1" in r and f"{tag} berita-satu" in r, r[:400])

        andi.send(f"<iq type='set' id='s8' to='pubsub.localhost'><pubsub "
                  f"xmlns='http://jabber.org/protocol/pubsub'>"
                  f"<retract node='{node}'><item id='it1'/>"
                  f"</retract></pubsub></iq>")
        r = andi.recv_until("s8")
        log("pubsub retract ok", "type='result'" in r, r[:200])
        time.sleep(0.7)
        r = budi.recv_any(2)
        log("pubsub subscriber receives retract event",
            "retract" in r and "it1" in r, r[:400])
        budi.send(f"<iq type='get' id='s9' to='pubsub.localhost'><pubsub "
                  f"xmlns='http://jabber.org/protocol/pubsub'>"
                  f"<items node='{node}'/></pubsub></iq>")
        r = budi.recv_until("s9")
        log("pubsub items empty after retract",
            "it1" not in r, r[:300])

        budi.send(f"<iq type='set' id='s10' to='pubsub.localhost'><pubsub "
                  f"xmlns='http://jabber.org/protocol/pubsub'>"
                  f"<unsubscribe node='{node}' jid='{budi_u}@localhost'/>"
                  f"</pubsub></iq>")
        r = budi.recv_until("s10")
        log("pubsub unsubscribe ok", "type='result'" in r, r[:200])
        andi.send(f"<iq type='set' id='s11' to='pubsub.localhost'><pubsub "
                  f"xmlns='http://jabber.org/protocol/pubsub'>"
                  f"<publish node='{node}'><item id='it3'>"
                  f"<entry>{tag} setelah-unsub</entry></item>"
                  f"</publish></pubsub></iq>")
        andi.recv_until("s11")
        time.sleep(0.7)
        r = budi.recv_any(2)
        log("pubsub no event after unsubscribe",
            f"{tag} setelah-unsub" not in r, r[:300])

        # owner configure get/set + max_items enforcement
        andi.send(f"<iq type='get' id='s12' to='pubsub.localhost'><pubsub "
                  f"xmlns='http://jabber.org/protocol/pubsub#owner'>"
                  f"<configure node='{node}'/></pubsub></iq>")
        r = andi.recv_until("s12")
        log("pubsub owner configure get returns form",
            "pubsub#max_items" in r and "pubsub#access_model" in r,
            r[:400])
        andi.send(f"<iq type='set' id='s13' to='pubsub.localhost'><pubsub "
                  f"xmlns='http://jabber.org/protocol/pubsub#owner'>"
                  f"<configure node='{node}'><x xmlns='jabber:x:data' "
                  f"type='submit'><field var='pubsub#max_items'>"
                  f"<value>2</value></field></x></configure>"
                  f"</pubsub></iq>")
        r = andi.recv_until("s13")
        log("pubsub owner configure set max_items=2",
            "type='result'" in r, r[:200])
        for i in ("m1", "m2", "m3"):
            andi.send(f"<iq type='set' id='s14{i}' to='pubsub.localhost'>"
                      f"<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
                      f"<publish node='{node}'><item id='{i}'>"
                      f"<entry>{tag} {i}</entry></item></publish>"
                      f"</pubsub></iq>")
            andi.recv_until(f"s14{i}")
        budi.send(f"<iq type='get' id='s15' to='pubsub.localhost'><pubsub "
                  f"xmlns='http://jabber.org/protocol/pubsub'>"
                  f"<items node='{node}'/></pubsub></iq>")
        r = budi.recv_until("s15")
        log("pubsub max_items=2 keeps only newest 2",
            "m1" not in r and "m2" in r and "m3" in r, r[:400])

        andi.send(f"<iq type='set' id='s16' to='pubsub.localhost'><pubsub "
                  f"xmlns='http://jabber.org/protocol/pubsub#owner'>"
                  f"<delete node='{node}'/></pubsub></iq>")
        r = andi.recv_until("s16")
        log("pubsub owner delete node ok",
            "type='result'" in r, r[:200])
        budi.send(f"<iq type='get' id='s17' to='pubsub.localhost'><pubsub "
                  f"xmlns='http://jabber.org/protocol/pubsub'>"
                  f"<items node='{node}'/></pubsub></iq>")
        r = budi.recv_until("s17")
        log("pubsub items on deleted node -> item-not-found",
            "type='error'" in r and "item-not-found" in r, r[:250])
        andi.send(f"<iq type='get' id='s18' to='pubsub.localhost'><query "
                  f"xmlns='http://jabber.org/protocol/disco#items'/></iq>")
        r = andi.recv_until("s18")
        log("pubsub disco#items no longer lists deleted node",
            f"node='{node}'" not in r, r[:300])
    finally:
        andi.close(); budi.close(); carol.close()

if __name__ == "__main__":
    main()
    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    sys.exit(1 if failed else 0)
