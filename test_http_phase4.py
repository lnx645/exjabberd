#!/usr/bin/env python3
"""Phase 4 live probe: HTTP stack — admin web, REST API, BOSH
(XEP-0124/0206), XMPP over WebSocket (RFC 7395), HTTP File Upload
(XEP-0363) — against a running dev server (127.0.0.1:5222 + 5280).

Usage: start the server first
(ELIXIR_ERL_OPTIONS="+fnu -sname exjabberd" mix run --no-halt),
then: python3 test_http_phase4.py

Users are created fresh per run (suffix from the run id) via RPC.
"""
import base64, hashlib, http.client, os, re, socket, subprocess, sys, time, uuid, json

HOST = "127.0.0.1"
XMPP_PORT = 5222
HTTP_PORT = 5280
RUN = uuid.uuid4().hex[:8]
API_TOKEN = "dev-api-token-change-me"
results = []


def log(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail}")


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


def http_req(method, path, body=None, headers=None, raw_headers=None):
    conn = http.client.HTTPConnection(HOST, HTTP_PORT, timeout=30)
    h = dict(headers or {})
    conn.request(method, path, body=body, headers=h)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, dict(resp.getheaders()), data


# ---------------------------------------------------------------- TCP XMPP client
class TcpConn:
    def __init__(self):
        self.s = socket.create_connection((HOST, XMPP_PORT), timeout=10)
        self.s.settimeout(6)
        self.buf = b""

    def send(self, data):
        self.s.sendall(data.encode() if isinstance(data, str) else data)

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

    def login(self, user, password, resource="tcp"):
        self.send("<?xml version='1.0'?><stream:stream to='localhost' "
                  "xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")
        r = self.recv_until("stream:features")
        assert "mechanism" in r, f"no features: {r[:200]}"
        cred = base64.b64encode(f"\x00{user}\x00{password}".encode()).decode()
        self.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{cred}</auth>")
        r = self.recv_until("success")
        assert "success" in r, f"auth failed: {r[:200]}"
        self.send("<?xml version='1.0'?><stream:stream to='localhost' "
                  "xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")
        r = self.recv_until("stream:features")
        assert "bind" in r, f"no bind feature: {r[:200]}"
        self.send(f"<iq type='set' id='b1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
                  f"<resource>{resource}</resource></bind></iq>")
        r = self.recv_until("bind")
        m = re.search(r"<jid>([^<]+)</jid>", r)
        assert m, f"no bind jid: {r[:300]}"
        return m.group(1)

    def close(self):
        try:
            self.send("</stream:stream>")
            self.s.close()
        except Exception:
            pass


# ---------------------------------------------------------------- BOSH client
class BoshClient:
    def __init__(self):
        self.rid = 1000
        self.sid = None

    def _post(self, body):
        status, _h, data = http_req(
            "POST", "/bosh", body=body.encode(),
            headers={"Content-Type": "text/xml; charset=utf-8"})
        assert status == 200, f"BOSH HTTP {status}: {data[:200]}"
        return data.decode(errors="replace")

    def create(self, wait=5):
        self.rid += 1
        body = (f"<body rid='{self.rid}' xmlns='http://jabber.org/protocol/httpbind' "
                f"to='localhost' xml:lang='en' wait='{wait}' hold='1' ver='1.6'/>")
        resp = self._post(body)
        m = re.search(r"sid='([^']+)'", resp)
        assert m, f"no sid in create response: {resp[:300]}"
        self.sid = m.group(1)
        return resp

    def send(self, inner="", restart=False):
        self.rid += 1
        extra = " xmpp:restart='true' xmlns:xmpp='urn:xmpp:xbosh'" if restart else ""
        body = (f"<body rid='{self.rid}' sid='{self.sid}' "
                f"xmlns='http://jabber.org/protocol/httpbind'{extra}>{inner}</body>")
        return self._post(body)

    def terminate(self):
        self.rid += 1
        return self._post(
            f"<body rid='{self.rid}' sid='{self.sid}' "
            f"xmlns='http://jabber.org/protocol/httpbind' type='terminate'/>")

    def auth_plain(self, user, password):
        cred = base64.b64encode(f"\x00{user}\x00{password}".encode()).decode()
        return self.send(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{cred}</auth>")

    def bind(self, resource="bosh"):
        r = self.send(f"<iq type='set' id='b1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
                      f"<resource>{resource}</resource></bind></iq>")
        m = re.search(r"<jid>([^<]+)</jid>", r)
        return (m.group(1) if m else None), r


# ---------------------------------------------------------------- WebSocket client (raw)
class WsClient:
    def __init__(self):
        self.s = socket.create_connection((HOST, HTTP_PORT), timeout=10)
        self.s.settimeout(6)
        self.buf = b""
        key = base64.b64encode(os.urandom(16)).decode()
        req = ("GET /ws HTTP/1.1\r\nHost: 127.0.0.1:5280\r\nUpgrade: websocket\r\n"
               "Connection: Upgrade\r\nSec-WebSocket-Key: " + key + "\r\n"
               "Sec-WebSocket-Protocol: xmpp\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self.s.sendall(req.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self.s.recv(4096)
            if not chunk:
                break
            resp += chunk
        assert b"101" in resp.split(b"\r\n")[0], f"WS handshake failed: {resp[:200]}"
        assert b"Sec-WebSocket-Protocol: xmpp" in resp, f"no xmpp subprotocol: {resp[:300]}"

    def send_text(self, text):
        data = text.encode()
        mask = os.urandom(4)
        header = bytearray([0x81])
        n = len(data)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += n.to_bytes(2, "big")
        else:
            header.append(0x80 | 127)
            header += n.to_bytes(8, "big")
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self.s.sendall(bytes(header) + mask + masked)

    def send_frame(self, opcode, payload=b""):
        mask = os.urandom(4)
        header = bytearray([0x80 | opcode, 0x80 | len(payload)])
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.s.sendall(bytes(header) + mask + masked)

    def _read_exact(self, n, timeout=6):
        self.s.settimeout(timeout)
        end = time.time() + timeout
        while len(self.buf) < n and time.time() < end:
            try:
                chunk = self.s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recv_text(self, timeout=6):
        """Return (opcode, payload) of the next data/control frame."""
        head = self._read_exact(2, timeout)
        if len(head) < 2:
            return None, b""
        fin = head[0] & 0x80
        opcode = head[0] & 0x0F
        ln = head[1] & 0x7F
        if ln == 126:
            ln = int.from_bytes(self._read_exact(2, timeout), "big")
        elif ln == 127:
            ln = int.from_bytes(self._read_exact(8, timeout), "big")
        payload = self._read_exact(ln, timeout)
        if opcode == 0x9:  # ping -> pong, then keep reading
            self.send_frame(0xA, payload)
            return self.recv_text(timeout)
        return opcode, payload

    def recv_until_text(self, needle, timeout=6):
        end = time.time() + timeout
        acc = b""
        while time.time() < end:
            op, payload = self.recv_text(timeout=max(1, end - time.time()))
            if op in (0x1, 0x2):
                acc += payload
                if needle.encode() in acc:
                    return acc.decode(errors="replace")
            elif op is None:
                break
        return acc.decode(errors="replace")

    def login(self, user, password, resource="ws"):
        self.send_text("<?xml version='1.0'?><stream:stream to='localhost' "
                       "xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")
        r = self.recv_until_text("stream:features")
        assert "mechanism" in r, f"WS no features: {r[:200]}"
        cred = base64.b64encode(f"\x00{user}\x00{password}".encode()).decode()
        self.send_text(f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{cred}</auth>")
        r = self.recv_until_text("success")
        assert "success" in r, f"WS auth failed: {r[:200]}"
        self.send_text("<?xml version='1.0'?><stream:stream to='localhost' "
                       "xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")
        r = self.recv_until_text("stream:features")
        assert "bind" in r, f"WS no bind feature: {r[:200]}"
        self.send_text(f"<iq type='set' id='b1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
                       f"<resource>{resource}</resource></bind></iq>")
        r = self.recv_until_text("bind")
        m = re.search(r"<jid>([^<]+)</jid>", r)
        assert m, f"WS no bind jid: {r[:300]}"
        return m.group(1)

    def close(self):
        try:
            self.send_frame(0x8, b"")
            self.s.close()
        except Exception:
            pass


# ---------------------------------------------------------------- main
def main():
    alice = f"p4alice{RUN}"
    bob = f"p4bob{RUN}"
    carol = f"p4carol{RUN}"
    dave = f"p4dave{RUN}"
    assert rpc_create(alice) and rpc_create(bob) and rpc_create(carol), "RPC user creation failed"
    rpc_create("admin", "adminsecret")

    # ---- A. HTTP basics + REST API ----
    st, _h, body = http_req("GET", "/")
    log("http index 200", st == 200 and b"exjabberd" in body, f"status={st}")
    st, _h, body = http_req("GET", "/api/status")
    log("api no token -> 401", st == 401, f"status={st} body={body[:60]}")
    st, _h, body = http_req("GET", "/api/status", headers={"Authorization": "Bearer wrong"})
    log("api bad token -> 401", st == 401, f"status={st}")
    st, _h, body = http_req("GET", "/api/status", headers={"Authorization": f"Bearer {API_TOKEN}"})
    try:
        status_doc = json.loads(body)
        # online_sessions is ambient state (a detached XEP-0198
        # session from an earlier probe may legitimately still count
        # as online), so assert the field is a sane integer, not 0.
        ok = st == 200 and status_doc.get("status") == "ok" and isinstance(status_doc.get("online_sessions"), int)
    except Exception:
        ok = False
    log("api status 200 + fields", ok, f"status={st} body={body[:160]}")
    auth_h = {"Authorization": f"Bearer {API_TOKEN}", "Content-Type": "application/json"}
    st, _h, body = http_req("POST", "/api/users",
                            body=json.dumps({"user": dave, "password": "secret"}), headers=auth_h)
    log("api create user 201", st == 201, f"status={st} body={body[:120]}")
    st, _h, body = http_req("GET", f"/api/users/{dave}", headers=auth_h)
    log("api get user exists", st == 200 and json.loads(body).get("exists") is True, f"body={body[:120]}")
    st, _h, body = http_req("GET", "/api/users", headers=auth_h)
    log("api list users contains dave", st == 200 and dave in body.decode(), f"status={st}")

    # ---- B. Admin web ----
    st, _h, body = http_req("GET", "/admin/login")
    log("admin login page 200", st == 200 and b"exjabberd admin" in body, f"status={st}")
    st, _h, body = http_req("GET", "/admin")
    log("admin dashboard w/o login -> redirect", st == 302, f"status={st}")
    st, _h, body = http_req("POST", "/admin/login",
                            body="user=admin&password=wrong",
                            headers={"Content-Type": "application/x-www-form-urlencoded"})
    log("admin wrong password -> 401", st == 401, f"status={st}")
    st, _h, body = http_req("POST", "/admin/login",
                            body=f"user={alice}&password=secret",
                            headers={"Content-Type": "application/x-www-form-urlencoded"})
    log("admin non-admin user -> 401", st == 401, f"status={st} (alice is not in admin ACL)")
    st, headers, body = http_req("POST", "/admin/login",
                                 body="user=admin&password=adminsecret",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    cookie = headers.get("set-cookie", "")
    log("admin login ok -> 302 + cookie", st == 302 and "exjabberd_admin=" in cookie,
        f"status={st} cookie={'yes' if cookie else 'no'}")
    cookie_hdr = {"Cookie": cookie.split(";")[0]}
    st, _h, body = http_req("GET", "/admin", headers=cookie_hdr)
    m_users = re.search(r"Registered users</div>", body.decode(errors="replace"))
    m_online = re.search(r"Online sessions</div>", body.decode(errors="replace"))
    log("admin dashboard shows live stats", st == 200 and m_users and m_online,
        f"status={st} len={len(body)}")
    # dashboard registered count must match API count
    st2, _h2, body2 = http_req("GET", "/api/status", headers=auth_h)
    api_count = json.loads(body2).get("registered_users")
    dash_count = re.search(r'<div class="stat">(\d+)</div><div>Registered users</div>',
                           body.decode(errors="replace"))
    log("admin dashboard count == api count",
        dash_count and int(dash_count.group(1)) == api_count,
        f"dash={dash_count.group(1) if dash_count else '?'} api={api_count}")
    st, _h, body = http_req("GET", "/admin/users", headers=cookie_hdr)
    log("admin users page lists admin", st == 200 and b"admin@localhost" in body, f"status={st}")
    st, _h, body = http_req("GET", "/admin/sessions", headers=cookie_hdr)
    log("admin sessions page 200", st == 200 and b"Online sessions" in body, f"status={st}")

    # admin UI: create user -> XMPP login works; delete -> login fails
    ui_user = f"p4ui{RUN}"
    form_h = {"Content-Type": "application/x-www-form-urlencoded", **cookie_hdr}
    st, _h, _b = http_req("POST", "/admin/users/create",
                          body=f"user={ui_user}&password=secret", headers=form_h)
    log("admin UI create user redirects", st == 302, f"status={st}")
    t = TcpConn()
    try:
        jid = t.login(ui_user, "secret")
        log("admin-created user can login XMPP", True, jid)
    except Exception as e:
        log("admin-created user can login XMPP", False, str(e)[:200])
    finally:
        t.close()
    st, _h, _b = http_req("POST", "/admin/users/delete",
                          body=f"user={ui_user}", headers=form_h)
    log("admin UI delete user redirects", st == 302, f"status={st}")
    t = TcpConn()
    try:
        t.login(ui_user, "secret")
        log("admin-deleted user login fails", False, "login unexpectedly succeeded")
    except Exception as e:
        log("admin-deleted user login fails", True, str(e)[:120])
    finally:
        t.close()

    # ---- C. BOSH <-> TCP ----
    bosh = BoshClient()
    try:
        resp = bosh.create(wait=5)
        log("bosh create session", "stream:features" in resp and "sid=" in resp,
            resp[:200].replace("\n", " "))
        resp = bosh.auth_plain(alice, "secret")
        log("bosh SASL PLAIN success", "<success" in resp, resp[:160])
        resp = bosh.send("", restart=True)
        log("bosh xmpp:restart -> features", "stream:features" in resp and "bind" in resp,
            resp[:160])
        jid, resp = bosh.bind("bosh")
        log("bosh bind", jid is not None, f"jid={jid} resp={resp[:160]}")
        # TCP bob logs in
        tcp_bob = TcpConn()
        bob_jid = tcp_bob.login(bob, "secret", "tcp")
        log("tcp bob login", True, bob_jid)
        # BOSH alice -> TCP bob
        resp = bosh.send(f"<message to='{bob}@localhost' type='chat'><body>hello bosh {RUN}</body></message>")
        got = tcp_bob.recv_until(f"hello bosh {RUN}", timeout=6)
        log("bosh -> tcp message delivered", f"hello bosh {RUN}" in got, got[:200])
        # TCP bob -> BOSH alice (long-poll: send empty body, reply arrives)
        tcp_bob.send(f"<message to='{alice}@localhost' type='chat'><body>reply tcp {RUN}</body></message>")
        resp = bosh.send("")
        log("tcp -> bosh message via long-poll", f"reply tcp {RUN}" in resp, resp[:300])
        # duplicate rid replays the previous response
        dup_rid = bosh.rid
        resp2 = bosh._post(
            f"<body rid='{dup_rid}' sid='{bosh.sid}' xmlns='http://jabber.org/protocol/httpbind'/>")
        log("bosh duplicate rid replays", f"reply tcp {RUN}" in resp2 or resp2 == resp,
            resp2[:200])
        # unknown sid -> 404
        st, _h, body = http_req("POST", "/bosh",
                                body="<body rid='1' sid='nosuchsid' xmlns='http://jabber.org/protocol/httpbind'/>".encode(),
                                headers={"Content-Type": "text/xml; charset=utf-8"})
        log("bosh unknown sid -> 404", st == 404, f"status={st}")
        resp = bosh.terminate()
        log("bosh terminate", "type='terminate'" in resp, resp[:160])
    except Exception as e:
        log("bosh flow", False, f"{type(e).__name__}: {e}")
        try:
            bosh.terminate()
        except Exception:
            pass

    # ---- D. WebSocket <-> TCP ----
    ws = None
    tcp_bob2 = None
    try:
        ws = WsClient()
        log("ws handshake 101 + xmpp subprotocol", True, "")
        jid = ws.login(carol, "secret", "ws")
        log("ws login + bind", True, jid)
        tcp_bob2 = TcpConn()
        tcp_bob2.login(bob, "secret", "tcp2")
        ws.send_text(f"<message to='{bob}@localhost' type='chat'><body>hello ws {RUN}</body></message>")
        got = tcp_bob2.recv_until(f"hello ws {RUN}", timeout=6)
        log("ws -> tcp message delivered", f"hello ws {RUN}" in got, got[:200])
        tcp_bob2.send(f"<message to='{carol}@localhost' type='chat'><body>reply ws {RUN}</body></message>")
        got = ws.recv_until_text(f"reply ws {RUN}", timeout=6)
        log("tcp -> ws message delivered", f"reply ws {RUN}" in got, got[:200])
        # ping -> pong
        ws.send_frame(0x9, b"pingdata")
        op, payload = ws.recv_text(timeout=6)
        log("ws ping -> pong", op == 0xA and payload == b"pingdata", f"op={op} payload={payload}")
        # wrong subprotocol must not upgrade
        try:
            s = socket.create_connection((HOST, HTTP_PORT), timeout=5)
            s.sendall(b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: soap\r\n"
                      b"Sec-WebSocket-Version: 13\r\n\r\n")
            r = s.recv(4096)
            s.close()
            log("ws wrong subprotocol rejected", b"101" not in r.split(b"\r\n")[0], r[:80])
        except Exception as e:
            log("ws wrong subprotocol rejected", False, str(e))
        ws.close()
    except Exception as e:
        log("ws flow", False, f"{type(e).__name__}: {e}")
    finally:
        if tcp_bob2:
            tcp_bob2.close()

    # ---- E. HTTP File Upload ----
    try:
        tcp_alice = TcpConn()
        tcp_alice.login(alice, "secret", "up")
        data = (f"hello upload {RUN}\n" * 20).encode()
        size = len(data)
        tcp_alice.send(f"<iq type='set' id='up1'><request xmlns='urn:xmpp:http:upload:0' "
                       f"filename='hello.txt' size='{size}' content-type='text/plain'/></iq>")
        resp = tcp_alice.recv_until("slot", timeout=6)
        m_put = re.search(r"<put url='([^']+)'", resp)
        m_get = re.search(r"<get url='([^']+)'", resp)
        log("upload slot IQ returns put+get urls", bool(m_put and m_get), resp[:300])
        put_url, get_url = m_put.group(1), m_get.group(1)
        # parse URLs (http://127.0.0.1:5280/upload/<slot>/hello.txt?token=..&exp=..)
        # NOTE: attribute values in XML escape & as &amp; — a real
        # client unescapes them before using the URL.
        def split_url(url):
            url = url.replace("&amp;", "&")
            rest = url.split("://", 1)[1]
            path_q = rest.split("/", 1)[1]
            return "/" + path_q
        st, _h, body = http_req("PUT", split_url(put_url), body=data,
                                headers={"Content-Type": "text/plain"})
        log("upload PUT 201", st == 201, f"status={st} body={body[:80]}")
        st, _h, body = http_req("GET", split_url(get_url))
        same = st == 200 and hashlib.sha256(body).hexdigest() == hashlib.sha256(data).hexdigest()
        log("upload GET returns identical bytes", same,
            f"status={st} sha={hashlib.sha256(body).hexdigest()[:12]}")
        # PUT without a slot -> 404
        st, _h, _b = http_req("PUT", "/upload/nosuchslot123/hello.txt?token=x&exp=9999999999",
                              body=b"x", headers={"Content-Type": "text/plain"})
        log("upload PUT unknown slot -> 404", st == 404, f"status={st}")
        # PUT with a forged token -> 403
        forged = put_url.replace("token=", "token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        st, _h, _b = http_req("PUT", split_url(forged), body=data,
                              headers={"Content-Type": "text/plain"})
        log("upload PUT forged token -> 403", st == 403, f"status={st}")
        # PUT with wrong content-type -> 415
        st, _h, _b = http_req("PUT", split_url(put_url), body=data,
                              headers={"Content-Type": "image/png"})
        log("upload PUT wrong content-type -> 415", st == 415, f"status={st}")
        # GET before upload (fresh slot) -> 404
        tcp_alice.send(f"<iq type='set' id='up2'><request xmlns='urn:xmpp:http:upload:0' "
                       f"filename='fresh.txt' size='5' content-type='text/plain'/></iq>")
        resp = tcp_alice.recv_until("slot", timeout=6)
        m_get2 = re.search(r"<get url='([^']+)'", resp)
        st, _h, _b = http_req("GET", split_url(m_get2.group(1)))
        log("upload GET before PUT -> 404", st == 404, f"status={st}")
        # oversize slot request -> not-acceptable error
        tcp_alice.send(f"<iq type='set' id='up3'><request xmlns='urn:xmpp:http:upload:0' "
                       f"filename='big.bin' size='999999999' content-type='application/octet-stream'/></iq>")
        resp = tcp_alice.recv_until("error", timeout=6)
        log("upload oversize slot -> not-acceptable", "not-acceptable" in resp, resp[:260])
        tcp_alice.close()
    except Exception as e:
        log("upload flow", False, f"{type(e).__name__}: {e}")

    # ---- F. API delete (cleanup check) ----
    st, _h, body = http_req("DELETE", f"/api/users/{dave}", headers=auth_h)
    log("api delete user 200", st == 200, f"status={st} body={body[:120]}")
    st, _h, body = http_req("GET", f"/api/users/{dave}", headers=auth_h)
    log("api deleted user gone", st == 200 and json.loads(body).get("exists") is False,
        f"body={body[:120]}")

    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\n==== {passed}/{len(results)} checks passed ====")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
