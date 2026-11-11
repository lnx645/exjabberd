#!/usr/bin/env python3
"""Raw-UDP/TCP live probe for Fase 5 — STUN (RFC 5389) + TURN
(RFC 5766) on port 5478: Binding, Allocate (long-term auth),
CreatePermission, Send/Data relay, ChannelBind + ChannelData,
Refresh, Delete, wrong-password 401, and TURN over TCP.

Usage: start the server first (ELIXIR_ERL_OPTIONS="+fnu -sname
exjabberd" mix run --no-halt), then: python3 test_stun_turn_phase5.py

The TURN password is derived exactly as XEP-0215 advertises it
(Base64(HMAC-SHA1(shared_secret, username))); the shared secret
here is the dev default from exjabberd.yml — replace it with the
configured value when the config changes. Mirrors
test/exjabberd/jingle_omemo_test.exs (same flows, independent
implementation, no shared codec).

NOTE: this sandbox blocks UDP sendto with EPERM, so the UDP checks
are skipped loudly there; the TCP Allocate check still runs, and
the server/allocation logic is covered in-process by the ExUnit
tests. Run this file where UDP is allowed for the full wire proof.
"""
import socket, time, sys, struct, hashlib, hmac, base64, binascii, os

HOST, PORT = "127.0.0.1", 5478
SECRET = "dev-only-turn-secret-change-me"
REALM = "localhost"
results = []

def log(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail}")

MAGIC = 0x2112A442
BIND_REQ, BIND_OK = 0x0001, 0x0101
ALLOC_REQ, ALLOC_OK = 0x0003, 0x0103
REFRESH_REQ, REFRESH_OK = 0x0004, 0x0104
SEND_IND, DATA_IND = 0x0006, 0x0007
CREATE_PERM_REQ, CREATE_PERM_OK = 0x0008, 0x0108
CHAN_BIND_REQ, CHAN_BIND_OK = 0x0009, 0x0109
ERR_RESP = 0x0111
A_USERNAME, A_REALM, A_NONCE, A_MI = 0x0006, 0x0014, 0x0015, 0x0008
A_ERROR, A_LIFETIME = 0x0009, 0x000D
A_XOR_PEER, A_DATA = 0x0012, 0x0013
A_XOR_RELAYED, A_XOR_MAPPED = 0x0016, 0x0020
A_REQ_TRANSPORT, A_CHAN_NUM = 0x0019, 0x000C
A_FINGERPRINT, A_SOFTWARE = 0x8028, 0x8022

_tid_counter = [0]

def new_tid():
    _tid_counter[0] += 1
    return struct.pack(">Q", _tid_counter[0]) + os.urandom(4)

def pad4(b):
    return b + b"\x00" * ((4 - len(b) % 4) % 4)

def attr(t, value):
    return struct.pack(">HH", t, len(value)) + pad4(value)

def xor_addr(family, ip, port, tid):
    if family == 1:
        ip_b = socket.inet_aton(ip)
        key = struct.pack(">I", MAGIC) + tid
        xip = bytes(a ^ b for a, b in zip(ip_b, key[:4]))
        xport = port ^ (MAGIC >> 16)
        return struct.pack(">BBH", 0, 1, xport) + xip
    raise ValueError("ipv6 not used here")

def encode(msg_type, tid, attrs, key=None, fingerprint=False):
    body = b"".join(attr(t, v) for t, v in attrs)
    mi = b""
    if key is not None:
        mi_len = len(body) + 24
        partial = struct.pack(">HHI", msg_type, mi_len, MAGIC) + tid + body
        partial += struct.pack(">HH", A_MI, 20) + b"\x00" * 20
        digest = hmac.new(key, partial, hashlib.sha1).digest()
        mi = struct.pack(">HH", A_MI, 20) + digest
    total = len(body) + len(mi) + (8 if fingerprint else 0)
    out = struct.pack(">HHI", msg_type, total, MAGIC) + tid + body + mi
    if fingerprint:
        crc = binascii.crc32(out) ^ 0x5354554E
        out += struct.pack(">HHI", A_FINGERPRINT, 4, crc)
    return out

def parse(data):
    if len(data) < 20:
        return None
    mtype, mlen, cookie = struct.unpack(">HHI", data[:8])
    if cookie != MAGIC:
        return None
    tid = data[8:20]
    attrs = {}
    off = 20
    while off + 4 <= 20 + mlen:
        atype, alen = struct.unpack(">HH", data[off:off + 4])
        val = data[off + 4:off + 4 + alen]
        attrs.setdefault(atype, []).append(val)
        off += 4 + ((alen + 3) // 4) * 4
    return {"type": mtype, "tid": tid, "attrs": attrs}

def get(msg, atype):
    vals = msg["attrs"].get(atype)
    return vals[0] if vals else None

def err_code(msg):
    v = get(msg, A_ERROR)
    if not v:
        return None
    return (v[2] >> 0) * 100 + v[3], v[4:].decode(errors="replace")

def decode_xor(val, tid):
    _res, fam, xport = struct.unpack(">BBH", val[:4])
    port = xport ^ (MAGIC >> 16)
    key = struct.pack(">I", MAGIC) + tid
    xip = val[4:8]
    ip = socket.inet_ntoa(bytes(a ^ b for a, b in zip(xip, key[:4])))
    return (ip, port)

def long_term_key(username, realm, password):
    return hashlib.md5(f"{username}:{realm}:{password}".encode()).digest()

def turn_password(username, secret):
    return base64.b64encode(
        hmac.new(secret.encode(), username.encode(), hashlib.sha1).digest()
    ).decode()

def udp_available():
    a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        a.bind(("127.0.0.1", 0))
        b.bind(("127.0.0.1", 0))
        a.sendto(b"probe", ("127.0.0.1", b.getsockname()[1]))
        return True
    except PermissionError:
        return False
    finally:
        a.close(); b.close()

class UdpClient:
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", 0))
        self.s.settimeout(3)

    def roundtrip(self, data):
        self.s.sendto(data, (HOST, PORT))
        raw, _ = self.s.recvfrom(4096)
        return parse(raw)

    def send(self, data):
        self.s.sendto(data, (HOST, PORT))

    def recv(self, timeout=3):
        self.s.settimeout(timeout)
        raw, addr = self.s.recvfrom(4096)
        return raw, addr

    def close(self):
        self.s.close()

def tcp_frame_read(sock, buf=b""):
    """Read one complete STUN/ChannelData frame from a TCP socket."""
    while True:
        if len(buf) >= 4:
            first, ln = struct.unpack(">HH", buf[:4])
            if 0x4000 <= first <= 0x7FFF:
                need = 4 + ln + ((4 - ln % 4) % 4)
            else:
                need = 20 + ln
            if len(buf) >= need:
                return buf[:need], buf[need:]
        chunk = sock.recv(4096)
        if not chunk:
            return None, buf
        buf += chunk

def main():
    if not udp_available():
        print("SKIP: UDP sendto is blocked in this environment (EPERM) — "
              "UDP checks below are skipped; TCP Allocate still runs.")
    username = "1234:alice@localhost"
    password = turn_password(username, SECRET)
    key = long_term_key(username, REALM, password)

    if udp_available():
        c = UdpClient()
        my_ip, my_port = c.s.getsockname()

        # --- STUN Binding ---
        tid = new_tid()
        msg = c.roundtrip(encode(BIND_REQ, tid, []))
        ok = (msg and msg["type"] == BIND_OK
              and decode_xor(get(msg, A_XOR_MAPPED), tid) == (my_ip, my_port))
        log("STUN Binding -> XOR-MAPPED-ADDRESS == source address", bool(ok),
            str(msg["attrs"].keys()) if msg else "no reply")

        # --- TURN Allocate: 401 first, then authed ---
        tid = new_tid()
        msg = c.roundtrip(encode(ALLOC_REQ, tid, [(A_REQ_TRANSPORT, bytes([17, 0, 0, 0]))]))
        code = err_code(msg) if msg else None
        nonce = get(msg, A_NONCE).decode() if msg and get(msg, A_NONCE) else None
        realm = get(msg, A_REALM).decode() if msg and get(msg, A_REALM) else None
        log("Allocate without auth -> 401 + REALM + NONCE",
            code is not None and code[0] == 401 and realm == REALM and bool(nonce),
            str(code))
        tid2 = new_tid()
        msg = c.roundtrip(encode(ALLOC_REQ, tid2, [
            (A_USERNAME, username.encode()), (A_REALM, REALM.encode()),
            (A_NONCE, nonce.encode()), (A_REQ_TRANSPORT, bytes([17, 0, 0, 0])),
            (A_LIFETIME, struct.pack(">I", 600)),
        ], key=key, fingerprint=True))
        relay = decode_xor(get(msg, A_XOR_RELAYED), tid2) if msg and msg["type"] == ALLOC_OK else None
        lifetime = struct.unpack(">I", get(msg, A_LIFETIME))[0] if msg and get(msg, A_LIFETIME) else None
        log("Allocate with derived credentials -> relayed address + lifetime 600",
            msg is not None and msg["type"] == ALLOC_OK and relay is not None and lifetime == 600,
            f"relay={relay} lifetime={lifetime}")
        if relay is None:
            print("cannot continue UDP TURN checks without an allocation")
            c.close()
        else:
            # --- wrong password -> 401 ---
            bad_key = long_term_key(username, REALM, "wrong-password")
            tid3 = new_tid()
            msg = c.roundtrip(encode(ALLOC_REQ, tid3, [
                (A_USERNAME, username.encode()), (A_REALM, REALM.encode()),
                (A_NONCE, nonce.encode()), (A_REQ_TRANSPORT, bytes([17, 0, 0, 0])),
            ], key=bad_key))
            code = err_code(msg) if msg else None
            log("Allocate with wrong password -> 401",
                code is not None and code[0] == 401, str(code))

            # --- CreatePermission + Send/Data relay ---
            peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            peer.bind(("127.0.0.1", 0))
            peer.settimeout(3)
            peer_ip, peer_port = peer.getsockname()
            tid4 = new_tid()
            msg = c.roundtrip(encode(CREATE_PERM_REQ, tid4, [
                (A_USERNAME, username.encode()), (A_REALM, REALM.encode()),
                (A_NONCE, nonce.encode()),
                (A_XOR_PEER, xor_addr(1, peer_ip, peer_port, tid4)),
            ], key=key, fingerprint=True))
            log("CreatePermission -> success",
                msg is not None and msg["type"] == CREATE_PERM_OK,
                str(msg["type"]) if msg else "no reply")

            tid5 = new_tid()
            c.send(encode(SEND_IND, tid5, [
                (A_XOR_PEER, xor_addr(1, peer_ip, peer_port, tid5)),
                (A_DATA, b"hello-relay"),
            ]))
            try:
                data, addr = peer.recvfrom(4096)
                log("Send indication relayed to peer (from relay addr)",
                    data == b"hello-relay" and addr == relay,
                    f"data={data!r} from={addr} relay={relay}")
            except socket.timeout:
                log("Send indication relayed to peer (from relay addr)", False, "peer got nothing")

            peer.sendto(b"hello-back", relay)
            try:
                raw, _ = c.recv(3)
                ind = parse(raw)
                ok = (ind and ind["type"] == DATA_IND
                      and get(ind, A_DATA) == b"hello-back"
                      and decode_xor(get(ind, A_XOR_PEER), ind["tid"]) == (peer_ip, peer_port))
                log("Peer reply arrives as Data indication", bool(ok),
                    f"type={ind['type'] if ind else None} data={get(ind, A_DATA) if ind else None}")
            except socket.timeout:
                log("Peer reply arrives as Data indication", False, "no indication")

            # --- ChannelBind + ChannelData both ways ---
            tid6 = new_tid()
            msg = c.roundtrip(encode(CHAN_BIND_REQ, tid6, [
                (A_USERNAME, username.encode()), (A_REALM, REALM.encode()),
                (A_NONCE, nonce.encode()),
                (A_CHAN_NUM, struct.pack(">H", 0x4000) + b"\x00\x00"),
                (A_XOR_PEER, xor_addr(1, peer_ip, peer_port, tid6)),
            ], key=key, fingerprint=True))
            log("ChannelBind 0x4000 -> success",
                msg is not None and msg["type"] == CHAN_BIND_OK,
                str(msg["type"]) if msg else "no reply")

            chan = struct.pack(">HH", 0x4000, 9) + pad4(b"chan-data")
            c.send(chan)
            try:
                data, addr = peer.recvfrom(4096)
                log("ChannelData forwarded to peer",
                    data == b"chan-data" and addr == relay, f"data={data!r}")
            except socket.timeout:
                log("ChannelData forwarded to peer", False, "peer got nothing")
            peer.sendto(b"chan-back", relay)
            try:
                raw, _ = c.recv(3)
                ch, ln = struct.unpack(">HH", raw[:4])
                payload = raw[4:4 + ln]
                log("Peer reply arrives as ChannelData 0x4000",
                    ch == 0x4000 and payload == b"chan-back",
                    f"channel={ch:#x} payload={payload!r}")
            except socket.timeout:
                log("Peer reply arrives as ChannelData 0x4000", False, "no frame")

            # --- Refresh extends, Refresh 0 deletes ---
            tid7 = new_tid()
            msg = c.roundtrip(encode(REFRESH_REQ, tid7, [
                (A_USERNAME, username.encode()), (A_REALM, REALM.encode()),
                (A_NONCE, nonce.encode()), (A_LIFETIME, struct.pack(">I", 600)),
            ], key=key, fingerprint=True))
            lt = struct.unpack(">I", get(msg, A_LIFETIME))[0] if msg and get(msg, A_LIFETIME) else None
            log("Refresh extends lifetime to 600",
                msg is not None and msg["type"] == REFRESH_OK and lt == 600, f"lifetime={lt}")
            tid8 = new_tid()
            msg = c.roundtrip(encode(REFRESH_REQ, tid8, [
                (A_USERNAME, username.encode()), (A_REALM, REALM.encode()),
                (A_NONCE, nonce.encode()), (A_LIFETIME, struct.pack(">I", 0)),
            ], key=key, fingerprint=True))
            lt = struct.unpack(">I", get(msg, A_LIFETIME))[0] if msg and get(msg, A_LIFETIME) else None
            log("Refresh lifetime 0 deletes allocation",
                msg is not None and msg["type"] == REFRESH_OK and lt == 0, f"lifetime={lt}")
            peer.close()
            c.close()

    # --- TURN over TCP (works even where UDP is blocked) ---
    try:
        s = socket.create_connection((HOST, PORT), timeout=5)
        s.settimeout(3)
        tid = new_tid()
        s.sendall(encode(ALLOC_REQ, tid, [(A_REQ_TRANSPORT, bytes([17, 0, 0, 0]))]))
        raw, _ = tcp_frame_read(s)
        msg = parse(raw) if raw else None
        code = err_code(msg) if msg else None
        nonce = get(msg, A_NONCE).decode() if msg and get(msg, A_NONCE) else None
        ok401 = code is not None and code[0] == 401 and bool(nonce)
        log("TCP Allocate without auth -> 401 + NONCE", ok401, str(code))
        if ok401:
            tid2 = new_tid()
            s.sendall(encode(ALLOC_REQ, tid2, [
                (A_USERNAME, username.encode()), (A_REALM, REALM.encode()),
                (A_NONCE, nonce.encode()), (A_REQ_TRANSPORT, bytes([17, 0, 0, 0])),
                (A_LIFETIME, struct.pack(">I", 600)),
            ], key=key, fingerprint=True))
            raw, _ = tcp_frame_read(s)
            msg = parse(raw) if raw else None
            relay = decode_xor(get(msg, A_XOR_RELAYED), tid2) if msg and msg["type"] == ALLOC_OK else None
            log("TCP Allocate with credentials -> relayed address",
                msg is not None and msg["type"] == ALLOC_OK and relay is not None
                and relay[0] == "127.0.0.1",
                f"relay={relay}")
        s.close()
    except Exception as e:
        log("TCP Allocate", False, f"{type(e).__name__}: {e}")

    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main()
