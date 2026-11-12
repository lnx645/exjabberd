# Parity assessment — exjabberd vs ejabberd

Date: 2026-11-11 (end of Fase 9, the last parity round).
Method: every item below is judged only from evidence produced in this
repo — a named probe with a pass count, or `mix test`. "Works" means a
real client spoke to a real server over the wire; a module that merely
starts, or an in-process unit test with no wire proof, does not count
as verified. Reproduce everything with `./verify.sh`.

## Verdict

**Not 100%.** On the 64-item checklist below: **34 verified, 9 partial,
21 not implemented — (34 + 9×0.5) / 64 ≈ 60%.**

That 60% is honest only for this checklist. Against ejabberd's full
module catalogue it would be lower: the long tail of ejabberd modules
(avatar, caps, announce, shared roster, push, proxy65, private
storage, vCard, last activity, ad-hoc commands, …) is counted here as
a handful of grouped items, not one item per module, and none of them
is wire-verified in this repo. The core that a small private server
actually needs — C2S, SM/Carbons/CSI, MAM, PubSub/PEP, MUC basics,
S2S dialback, BOSH/WebSocket, upload, Jingle signaling, MQTT 3.1.1,
clustering, Mnesia + SQLite auth — is real and proven. The gaps are
the enterprise edges: alternate auth backends, full MUC, MIX,
MQTT 5.0, OMEMO generations :1/:2, HTTPS listener, and the long tail.

## Evidence (all re-run green by `./verify.sh` on 2026-11-11)

| Proof | Result |
|---|---|
| `mix test` (12 ExUnit files) | 119/119, 0 failures |
| `mix compile` | 0 warnings (warnings are errors) |
| `audit_raw_test.py` (raw sockets, C2S core) | 18/18 |
| `audit_slix_test.py` (slixmpp 1.17) | 10/10 |
| `test_sm_carbons_csi.py` (XEP-0198/0280/0352) | 36/36 |
| `test_mam_pubsub.py` (raw, MAM + PubSub) | 47/47 |
| `test_mam_pubsub_slix.py` (slixmpp xep_0313 + xep_0060) | 12/12 |
| `test_s2s.py` (two nodes, dialback + STARTTLS) | 17/17 |
| `test_s2s_slix.py` (two nodes, slixmpp) | 4/4 |
| `test_http_phase4.py` (admin + API + BOSH + WS + upload) | 46/46 |
| `test_jingle_phase5.py` (Jingle + extdisco + OMEMO) | 25/25 |
| `test_stun_turn_phase5.py` (STUN/TURN over TCP) | 2/2, UDP checks skipped in the sandbox (see below) |
| `test_mqtt_phase6.py` (paho-mqtt + bridge) | 28/28 |
| `test_cluster_phase7.py` (two nodes, same domain) | 22/22 |
| `test_auth_sqlite_phase8.py` (SQLite backend + migration) | 19/19 |

Total wire-probe checks: 18+10+36+47+12+17+4+46+25+2+28+22+19 = **286**.

## Checklist

Status: **V** = verified over the wire (probe + count in the table
above) · **P** = partial (works, with a named limit) ·
**N** = not implemented / not wire-verified.

### C2S core (RFC 6120 / RFC 6121) — 14/14 V

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | Stream open returns exactly one `<stream:features>` | V | raw 18/18 |
| 2 | SASL PLAIN (verified against stored SCRAM data, no cleartext) | V | raw 18/18, slix 10/10 |
| 3 | SASL SCRAM-SHA-256 (RFC 5802; `n`/`y` binding, `p` rejected) | V | raw 18/18, slix 10/10 |
| 4 | STARTTLS C2S (TLS 1.2/1.3, real `:ssl`) | V | raw 18/18 |
| 5 | Direct-TLS C2S on 5223 | V | raw 18/18 |
| 6 | Resource binding | V | raw 18/18, slix 10/10 |
| 7 | Roster get/set/remove, versioning, push | V | raw 18/18 |
| 8 | Presence broadcast | V | raw 18/18, slix 10/10 |
| 9 | 1-1 messages both ways; unknown user → `service-unavailable` | V | raw 18/18, slix 10/10 |
| 10 | Offline messages (Mnesia, cap 100/user, flushed on login) | V | raw 18/18 |
| 11 | Service discovery (XEP-0030) | V | raw 18/18, slix 10/10 |
| 12 | Ping (XEP-0199), entity time (XEP-0202), version (XEP-0092) | V | raw 18/18, slix 10/10 |
| 13 | In-band registration (XEP-0077, duplicate → `conflict`) | V | raw 18/18 |
| 14 | Malformed XML → `invalid-xml`; stanza > 262144 B → `policy-violation` | V | raw 18/18 |

### Session extensions — 3/3 V

| # | Item | Status | Evidence |
|---|---|---|---|
| 15 | Stream Management (XEP-0198): enable/ack/resume + replay | V | SM 36/36 |
| 16 | Message Carbons (XEP-0280) | V | SM 36/36 |
| 17 | Client State Indication (XEP-0352): queue while inactive | V | SM 36/36 |

### MAM / PubSub / MUC / MIX — 4 V, 1 P, 4 N

| # | Item | Status | Evidence / limit |
|---|---|---|---|
| 18 | MAM (XEP-0313): archive, `with`/`start`/`end`, RSM, prefs | V | MAM/PubSub 47/47 + slix 12/12 |
| 19 | MAM for MUC room history | V | MAM/PubSub 47/47 — but no room-membership check on query |
| 20 | PubSub core (XEP-0060): create/delete/subscribe/publish/retract/purge/items/affiliations/owner config | V | MAM/PubSub 47/47 + slix 12/12 |
| 21 | PubSub collection nodes | N | rejected with `bad-request` |
| 22 | PubSub `authorize` approval flow | N | subscriptions stay `pending`, no owner approval |
| 23 | PEP (XEP-0163): per-user nodes on the bare JID | V | Jingle 25/25 (OMEMO over PEP) |
| 24 | MUC (XEP-0045) basics: join, presence, groupchat, leave, disco | P | live_c2s ExUnit + raw 18/18; no affiliations/roles, no room config, no passwords, no bans |
| 25 | MUC admin: affiliations, roles, room configuration, persistent rooms | N | — |
| 26 | MIX (XEP-0369) | N | module exists as a partial implementation; never verified over the wire |

### S2S / federation — 3 V, 2 N

| # | Item | Status | Evidence / limit |
|---|---|---|---|
| 27 | Server Dialback (XEP-0220) both directions, forged keys rejected | V | S2S 17/17 |
| 28 | S2S STARTTLS (TLS 1.2/1.3) | V | S2S 17/17 |
| 29 | Federated messages / directed presence / IQ (incl. remote disco) | V | S2S 17/17 + slix 4/4 |
| 30 | SASL EXTERNAL for S2S | N | — |
| 31 | Bidirectional S2S streams (XEP-0288) | N | one dialback-verified connection per direction |

### HTTP stack — 2 V, 3 P, 3 N

| # | Item | Status | Evidence / limit |
|---|---|---|---|
| 32 | Web admin: login (SCRAM, admin ACL), dashboard, users, sessions | P | HTTP 46/46 — no MUC/PubSub management pages |
| 33 | REST API: status, user CRUD, sessions (Bearer token) | P | HTTP 46/46 — small surface vs ejabberd's full API |
| 34 | BOSH (XEP-0124 + XEP-0206) | V | HTTP 46/46 |
| 35 | XMPP over WebSocket (RFC 7395) | V | HTTP 46/46 |
| 36 | HTTP File Upload (XEP-0363): slots, HMAC URLs, PUT/GET | P | HTTP 46/46 — no per-user quota, no virus scanning |
| 37 | TLS HTTP listener (HTTPS, 5443) | N | plain HTTP on 5280 only; use a reverse proxy |
| 38 | Captcha endpoint | N | — |
| 39 | ACME challenge handling, HTTP/2 | N | — |

### Media / signaling — 2 V, 3 P, 1 N

| # | Item | Status | Evidence / limit |
|---|---|---|---|
| 40 | Jingle signaling (XEP-0166 + ICE-UDP): routed verbatim, tracked | P | Jingle 25/25 — signaling only, no media/DTLS/SRTP by design; federated session tracked on one node only |
| 41 | STUN (RFC 5389) Binding | P | TCP path verified; **live UDP wire proof missing** — the sandbox blocks UDP `sendto` with EPERM, so UDP checks skip loudly and the same logic is covered in-process only |
| 42 | TURN (RFC 5766): Allocate/Refresh/Permissions/ChannelBind/relay | P | TURN over TCP verified live 2/2; live UDP relay unproven for the same sandbox reason; no per-user quota beyond global `max_allocations` |
| 43 | External service discovery (XEP-0215, incl. time-limited TURN credentials) | V | Jingle 25/25 |
| 44 | OMEMO legacy generation (XEP-0384 over PEP) | V | Jingle 25/25 |
| 45 | OMEMO generations `:1` / `:2` | N | not implemented or advertised |

### MQTT — 2 V, 1 N

| # | Item | Status | Evidence / limit |
|---|---|---|---|
| 46 | MQTT v3.1.1 broker: QoS 0/1/2, retained, Will, persistent sessions, takeover | V | MQTT 28/28 |
| 47 | MQTT ↔ XMPP PubSub bridge (both directions, loop protection) | V | MQTT 28/28 |
| 48 | MQTT 5.0 | N | broker speaks 3.1.1 only |

### Clustering — 2 V, 1 P

| # | Item | Status | Evidence / limit |
|---|---|---|---|
| 49 | Cross-node routing: messages/presence/IQ reach users on other nodes (not via S2S) | V | cluster 22/22 |
| 50 | Shared Mnesia tables (accounts, roster, offline, MAM, PubSub) | V | cluster 22/22 |
| 51 | Cluster completeness | P | MUC rooms, vCards, SM resume state and per-host ETS caches stay node-local; two nodes with independent schemas cannot merge live; same resource on two nodes is last-registration-wins |

### Auth backends — 2 V, 1 P, 2 N

| # | Item | Status | Evidence / limit |
|---|---|---|---|
| 52 | Mnesia auth (SCRAM-SHA-256 verifiers, survives restart) | V | raw 18/18 + restart proofs |
| 53 | SQLite auth (same verifier format, migration tool) | V | SQLite 19/19 + 10 ExUnit |
| 54 | SQL / PostgreSQL / MySQL auth | N | honest stub — no PostgreSQL server exists in this sandbox to verify against |
| 55 | LDAP / JWT / OAuth / external / PAM auth | N | stubs that return `false` / `not_implemented` |
| 56 | Anonymous auth | P | "works as before" — not re-probed in Fase 1–9 |

### Remaining ejabberd surface — 0 V, 0 P, 8 N

| # | Item | Status | Evidence / limit |
|---|---|---|---|
| 57 | Roster subscription requests (subscribe/subscribed flows) | N | presence is broadcast to all sessions for now |
| 58 | `starttls_required` | N | STARTTLS offered but optional; PLAIN/SCRAM work without TLS |
| 59 | vCard (XEP-0054) | N | partial implementation only, not wire-verified |
| 60 | Private XML storage (XEP-0049) | N | partial implementation only, not wire-verified |
| 61 | Privacy lists / blocking (XEP-0016 / XEP-0191) | N | partial implementation only, not wire-verified |
| 62 | Last activity (XEP-0012) | N | partial implementation only, not wire-verified |
| 63 | Ad-hoc commands (XEP-0050) | N | partial implementation only, not wire-verified |
| 64 | Long tail: SOCKS5 bytestreams (XEP-0065), Push (XEP-0357), shared roster, avatars (XEP-0084), caps, announce, CAPTCHA, delegation, … | N | partial implementations only, none wire-verified; "39 modules start at boot" means they load, not that they work |

## Count

- Verified (V): 34 — items 1–20, 23, 27–29, 34–35, 43–44, 46–47, 49–50, 52–53.
- Partial (P): 9 — items 24, 32–33, 36, 40–42, 51, 56.
- Not implemented (N): 21 — items 21–22, 25–26, 30–31, 37–39, 45, 48, 54–55, 57–64.
- Total: 64. Score: (34 + 9 × 0.5) / 64 = 38.5 / 64 ≈ **60%**.

## Known limitations that are not bugs

- **UDP wire proof missing (STUN/TURN):** the sandbox blocks UDP
  `sendto` with EPERM for every process (proven by a minimal Python
  repro). The UDP checks skip loudly; run `test_stun_turn_phase5.py`
  where UDP is allowed for the full proof.
- **Mnesia persistence quirk:** a VM halted abruptly (e.g. `mix run -e`
  exiting) can lose the not-yet-flushed transaction log; a clean stop
  (SIGTERM) keeps accounts. `verify.sh` and the probes stop servers
  with SIGTERM for exactly this reason.
- **Supervisor restart intensity:** stopping the supervised SQLite
  backend repeatedly trips the supervisor (3 restarts in 5 s), so the
  backend exposes `close/0` instead of being stopped.
- **epmd:** Erlang distribution sometimes fails because `epmd` is not
  running; `verify.sh` and the boot scripts start `epmd -daemon`
  first.
- **Flakes fixed in Fase 9:** MUC self-presence 110/201 could arrive
  in separate TCP chunks — `live_c2s_test.exs` now waits for both
  markers (`recv_until_all/3`); the slixmpp presence wait in
  `audit_slix_test.py` went from 3 s to 10 s. Other two-marker
  assertions in the ExUnit suite share the same theoretical risk but
  have not flaked; they are documented here, not silently fixed.
- **Fresh-clone gap found and fixed in Fase 9:** `audit_raw_test.py`,
  `audit_slix_test.py` and `test_sm_carbons_csi.py` used to assume
  users andi/budi/carol already existed from an earlier run, so they
  failed with `not-authorized` on a fresh clone with an empty Mnesia
  schema (found by the fresh-clone `verify.sh` run: 3/19 steps
  failed). All three now create their users via RPC when missing
  (`[SETUP]` lines, not counted in the SUMMARY, so the counts stay
  18/18, 10/10, 36/36).
- **TLS is dev-only:** the certificate is self-signed for `localhost`;
  production needs a real certificate and, for S2S, domain verification
  (currently `verify_none`). The dialback verify connection is plain
  TCP, as XEP-0220 allows.
