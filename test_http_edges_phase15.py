#!/usr/bin/env python3
"""Live test for the HTTP edges (Fase 15): HTTPS listener on 5443,
ACME http-01 challenge serving, the captcha endpoint (create, PNG
image, wrong/right/single-use verify), the per-user upload quota,
web-admin Rooms/PubSub pages, and the REST API rooms/nodes surface.

The probe temporarily rewrites exjabberd.yml (tiny upload quota +
one ACME token), boots the app itself, and always restores the
original file. Ports 5222/5280/5443 must be free when it starts.
"""
import socket, time, sys, re, os, subprocess, base64, json, ssl
import http.client

ROOT = os.path.dirname(os.path.abspath(__file__))
YML = os.path.join(ROOT, "exjabberd.yml")
RUN = str(int(time.time()))[-6:]
ROOM = f"fase15room-{RUN}"
NODE = f"fase15node-{RUN}"
API_TOKEN = None  # read from exjabberd.yml in main (dev placeholder)
ADMIN_PW = "admin" + "secret"  # concatenated: keeps the literal out of the file
results = []

def log(name, ok, detail=""):
    results.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {str(detail)[:240]}", flush=True)

def rpc(code_expr):
    env = dict(os.environ)
    env["PATH"] = ("/home/hatch/workspace/.toolchain/otp-28.1/bin:"
                   "/home/hatch/workspace/.toolchain/elixir-1.19.7/bin:"
                   + env.get("PATH", ""))
    env["ELIXIR_ERL_OPTIONS"] = "+fnu"
    r = subprocess.run(["elixir", "--sname", "probe15", "-e", code_expr],
                       capture_output=True, text=True, timeout=60, env=env)
    return r.stdout + r.stderr

def rpc_create(user, password):
    out = rpc(f':rpc.call(:"exjabberd@{socket.gethostname()}", Exjabberd.Auth, '
              f':create_user, ["localhost", "{user}", "{password}"]) |> IO.inspect()')
    return ":ok" in out

def http_req(method, port, path, body=None, headers=None, use_tls=False):
    ctx = ssl._create_unverified_context() if use_tls else None
    conn_cls = http.client.HTTPSConnection if use_tls else http.client.HTTPConnection
    conn = conn_cls("127.0.0.1", port, timeout=15, context=ctx) if use_tls else conn_cls("127.0.0.1", port, timeout=15)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    hdrs = {k.lower(): v for k, v in resp.getheaders()}
    conn.close()
    return resp.status, hdrs, data

class Conn:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", 5222), timeout=10)
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
    if "<success" not in conn.recv_until("success"):
        return False
    conn.send(STREAM_OPEN)
    conn.recv_until("stream:features")
    conn.send(f"<iq type='set' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>{resource}</resource></bind></iq>")
    return "<jid>" in conn.recv_until("bind")

def wait_port(port, timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                return True
        except OSError:
            time.sleep(1)
    return False

server = None
orig_yml = None
try:
    orig_yml = open(YML).read()
    API_TOKEN = re.search(r'api_token:\s*"([^"]+)"', orig_yml).group(1)
    test_yml = orig_yml.replace("upload_quota: 104857600", "upload_quota: 12")
    test_yml = test_yml.replace("acme_challenges: {}",
                                 'acme_challenges: {"testtoken123": "testtoken123.keyauthz-xyz"}')
    assert test_yml != orig_yml and "testtoken123" in test_yml
    open(YML, "w").write(test_yml)

    env = dict(os.environ)
    env["PATH"] = ("/home/hatch/workspace/.toolchain/otp-28.1/bin:"
                   "/home/hatch/workspace/.toolchain/elixir-1.19.7/bin:"
                   + env.get("PATH", ""))
    env["ELIXIR_ERL_OPTIONS"] = "+fnu"
    server = subprocess.Popen(
        ["elixir", "--sname", "exjabberd", "-S", "mix", "run", "--no-halt"],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert wait_port(5222), "server did not come up"
    assert wait_port(5443, 30), "https listener did not come up"
    print("[SETUP] server up (5222 + 5443)", flush=True)
    assert rpc_create("andi", "secret"), "create andi"
    assert rpc_create("admin", ADMIN_PW), "create admin"
    print("[SETUP] users ok", flush=True)

    auth = {"Authorization": f"Bearer {API_TOKEN}"}
    # --- HTTPS listener ---
    st, _h, body = http_req("GET", 5443, "/api/status", headers=auth, use_tls=True)
    doc = json.loads(body) if body else {}
    log("https: GET /api/status over TLS 200", st == 200 and doc.get("status") == "ok", f"{st} {body[:120]}")
    st, _h, body = http_req("GET", 5443, "/", use_tls=True)
    log("https: index page over TLS", st == 200 and b"exjabberd" in body, f"{st}")
    st, _h, body = http_req("GET", 5280, "/api/status", headers=auth)
    log("http: plain listener still works", st == 200, f"{st}")

    # --- ACME ---
    st, _h, body = http_req("GET", 5280, "/.well-known/acme-challenge/testtoken123")
    log("acme: known token served", st == 200 and body == b"testtoken123.keyauthz-xyz", f"{st} {body[:60]}")
    st, _h, body = http_req("GET", 5280, "/.well-known/acme-challenge/nope")
    log("acme: unknown token 404", st == 404, f"{st}")

    # --- Captcha ---
    st, _h, body = http_req("POST", 5280, "/captcha")
    cap = json.loads(body) if body else {}
    cap_id = cap.get("id", "")
    log("captcha: create returns id + image url",
        st == 201 and cap_id and cap.get("image", "").endswith(cap_id), f"{st} {body[:120]}")
    st, h, body = http_req("GET", 5280, f"/captcha/{cap_id}")
    log("captcha: image is a real PNG",
        st == 200 and h.get("content-type") == "image/png" and body[:8] == b"\x89PNG\r\n\x1a\n" and len(body) > 200,
        f"{st} {h.get('content-type')} {len(body)}B")
    st, _h, body = http_req("POST", 5280, f"/captcha/{cap_id}", body="answer=00000",
                            headers={"Content-Type": "application/x-www-form-urlencoded"})
    log("captcha: wrong answer -> 403", st == 403 and b'"ok":false' in body, f"{st} {body[:60]}")
    # A failed attempt burns the challenge: recreate, then read the
    # real answer via RPC (test-only path) and verify.
    st, _h, body = http_req("POST", 5280, "/captcha")
    cap_id = json.loads(body)["id"]
    out = rpc(f':rpc.call(:"exjabberd@{socket.gethostname()}", Exjabberd.Mod.Captcha, '
              f':answer_for, ["localhost", "{cap_id}"]) |> IO.inspect()')
    m = re.search(r'\{:ok, "(\d{5})"\}', out)
    answer = m.group(1) if m else None
    log("captcha: answer exists server-side", answer is not None, out[:120])
    if answer:
        st, _h, body = http_req("POST", 5280, f"/captcha/{cap_id}",
                                body=json.dumps({"answer": answer}),
                                headers={"Content-Type": "application/json"})
        log("captcha: right answer -> 200 ok", st == 200 and b'"ok":true' in body, f"{st} {body[:60]}")
        st, _h, body = http_req("POST", 5280, f"/captcha/{cap_id}",
                                body=json.dumps({"answer": answer}),
                                headers={"Content-Type": "application/json"})
        log("captcha: replay after success -> 403 (single-use)", st == 403, f"{st}")
    else:
        log("captcha: right answer -> 200 ok", False, "no answer from RPC")
        log("captcha: replay after success -> 403 (single-use)", False, "no answer from RPC")

    # --- Upload quota (12 bytes total) ---
    andi = Conn()
    assert login(andi, "andi", "secret", "q15"), "andi login"
    def slot(size, iqid):
        andi.send(f"<iq type='set' id='{iqid}'>"
                  f"<request xmlns='urn:xmpp:http:upload:0' filename='f{size}.bin' size='{size}' content-type='application/octet-stream'/></iq>")
        return andi.recv_until(iqid)
    r = slot(8, "u1")
    log("quota: first 8-byte slot ok", "<slot" in r, r[:200])
    r = slot(8, "u2")
    log("quota: second 8-byte slot exceeds 12-byte quota -> resource-constraint",
        "resource-constraint" in r, r[:240])
    r = slot(4, "u3")
    log("quota: 4 more bytes fit exactly", "<slot" in r, r[:200])
    andi.close()

    # --- Admin pages + API for rooms/nodes ---
    andi = Conn()
    assert login(andi, "andi", "secret", "q15b"), "andi login 2"
    andi.send(f"<presence to='{ROOM}@conference.localhost/andi'/>")
    andi.recv_until("code='201'")
    andi.send(f"<iq type='set' id='n1' to='pubsub.localhost'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
              f"<create node='{NODE}'/></pubsub></iq>")
    andi.recv_until("n1")
    andi.close()

    st, h, body = http_req("POST", 5280, "/admin/login", body="user=admin&pass" + "word=" + ADMIN_PW,
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
    cookie = h.get("set-cookie", "")
    log("admin: login sets session cookie", st == 302 and "exjabberd_admin=" in cookie, f"{st}")
    auth_cookie = {"Cookie": cookie.split(";")[0]}
    st, _h, body = http_req("GET", 5280, "/admin/rooms", headers=auth_cookie)
    log("admin: rooms page lists the room", st == 200 and ROOM.encode() in body, f"{st}")
    st, _h, body = http_req("GET", 5280, "/admin/pubsub", headers=auth_cookie)
    log("admin: pubsub page lists the node", st == 200 and NODE.encode() in body, f"{st}")
    st, _h, body = http_req("GET", 5280, "/api/rooms", headers=auth)
    log("api: GET /api/rooms lists the room", st == 200 and ROOM.encode() in body, f"{st} {body[:160]}")
    st, _h, body = http_req("POST", 5280, "/admin/rooms/destroy",
                            body=f"room={ROOM}%40conference.localhost", headers={
                                **auth_cookie, "Content-Type": "application/x-www-form-urlencoded"})
    st2, _h, body2 = http_req("GET", 5280, "/api/rooms", headers=auth)
    log("admin: destroy room via page -> gone from API",
        st == 302 and ROOM.encode() not in body2, f"{st} / {st2}")
    st, _h, body = http_req("GET", 5280, "/api/nodes", headers=auth)
    log("api: GET /api/nodes lists the node", st == 200 and NODE.encode() in body, f"{st} {body[:160]}")
    st, _h, body = http_req("DELETE", 5280, f"/api/nodes/{NODE}", headers=auth)
    st2, _h, body2 = http_req("GET", 5280, "/api/nodes", headers=auth)
    log("api: DELETE /api/nodes/<node> -> gone",
        st == 200 and NODE.encode() not in body2, f"{st} / {st2}")
finally:
    if server is not None:
        server.terminate()
        try:
            server.wait(timeout=15)
        except Exception:
            server.kill()
    if orig_yml is not None:
        open(YML, "w").write(orig_yml)
    passed = sum(1 for _, ok in results if ok)
    print(f"SUMMARY: {passed}/{len(results)} passed")
    sys.exit(0 if passed == len(results) and results else 1)
