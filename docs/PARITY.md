# Parity assessment — exjabberd vs ejabberd

Date: 2026-11-12 (Fase 10–15 of the 100% round); re-verified and
extended 2026-11-13 (Fase 16: verify.sh harness fix, room-creation
race fix, SQL/PostgreSQL auth backend — see Known limitations;
Fase 17: MQTT 5.0).
Method: every item below is judged only from evidence produced in this
repo — a named probe with a pass count, or `mix test`. "Works" means a
real client spoke to a real server over the wire; a module that merely
starts, or an in-process unit test with no wire proof, does not count
as verified. Reproduce everything with `./verify.sh`.

## Verdict

**Not 100%.** On the 64-item checklist below: **53 verified, 7 partial,
4 not implemented — (53 + 7×0.5) / 64 ≈ 88%.**

That 88% is honest only for this checklist. Against ejabberd's full
module catalogue it would be lower: the long tail of ejabberd modules
is counted here as a handful of grouped items, not one item per
module. The core that a small private server actually needs — C2S,
SM/Carbons/CSI, MAM, PubSub/PEP with collections and subscription
authorization, full MUC with admin IQs, MIX core, S2S dialback,
BOSH/WebSocket, upload with quota, HTTPS + captcha + ACME http-01,
Jingle signaling, MQTT 3.1.1 and 5.0, clustering,
Mnesia + SQLite auth, roster subscriptions, privacy/blocking, vCard,
private storage, last activity, ad-hoc commands — is real and proven.
The gaps are the enterprise edges: alternate auth backends (MySQL /
LDAP / PAM), OMEMO generations :1/:2, S2S EXTERNAL/Bidi, HTTP/2, and
the remaining grouped long tail (item 64).

## Evidence (all re-run green by `./verify.sh` on 2026-11-13, Fase 17)

| Proof | Result |
|---|---|
| `mix test` (12 ExUnit files) | 135/135, 0 failures |
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
| `test_longtail_phase10.py` (vCard/private/privacy/blocking/last/adhoc) | 30/30 |
| `test_subscriptions_phase11.py` (RFC 6121 subscription flows) | 17/17 |
| `test_starttls_anon_phase11.py` (`starttls_required` + anonymous auth) | 10/10 |
| `test_muc_admin_phase12.py` (MUC owner/admin IQs, join gates, kick/ban, destroy) | 23/23 |
| `test_pubsub_extra_phase13.py` (collections + authorize approval) | 16/16 |
| `test_mix_phase14.py` (MIX channels XEP-0369) | 17/17 |
| `test_http_edges_phase15.py` (HTTPS, ACME, captcha, upload quota, admin/API rooms+nodes) | 21/21 |
| `test_auth_sql_phase16.py` (SQL auth vs real PostgreSQL 16.9; own server + own PG) | 19/19 |
| `test_auth_backends_phase16.py` (JWT / OAuth / external auth; own server per backend) | 25/25 |
| `test_mqtt5_phase17.py` (MQTT 5.0: paho v5 + raw-socket client) | 21/21 |

Total wire-probe checks: 18+10+36+47+12+17+4+46+25+2+28+22+19+30+17+10+23+16+17+21+19+25+21 = **485**.

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

### MAM / PubSub / MUC / MIX — 9 V, 0 P, 0 N

| # | Item | Status | Evidence / limit |
|---|---|---|---|
| 18 | MAM (XEP-0313): archive, `with`/`start`/`end`, RSM, prefs | V | MAM/PubSub 47/47 + slix 12/12 |
| 19 | MAM for MUC room history | V | MAM/PubSub 47/47; room archives now require occupant/affiliated requester (Fase 12 probe §13) |
| 20 | PubSub core (XEP-0060): create/delete/subscribe/publish/retract/purge/items/affiliations/owner config | V | MAM/PubSub 47/47 + slix 12/12 |
| 21 | PubSub collection nodes | V | `test_pubsub_extra_phase13.py` 16/16 — create with `pubsub#type`, disco#info type `collection`, leaf membership via `pubsub#collection`, disco#items lists children, items aggregate children, publish to a collection is `forbidden` |
| 22 | PubSub `authorize` approval flow | V | `test_pubsub_extra_phase13.py` 16/16 — subscribe lands `pending`, owner gets the `subscribe_authorization` form message, non-owner replies ignored, deny → `none` notification + removed, approve → `subscribed` notification + publish events flow; owner IQ set-subscriptions writes state directly |
| 23 | PEP (XEP-0163): per-user nodes on the bare JID | V | Jingle 25/25 (OMEMO over PEP) |
| 24 | MUC (XEP-0045) basics: join, presence, groupchat, leave, disco | V | `test_muc_admin_phase12.py` 23/23 — affiliations keyed by bare JID (creator = owner/moderator), roles, subject broadcast, join gates (members-only `registration-required`, password `not-authorized`, ban `forbidden`, nick `conflict`) answered as presence errors |
| 25 | MUC admin: affiliations, roles, room configuration, persistent rooms | V | `test_muc_admin_phase12.py` 23/23 — muc#owner config form get/set (title, persistent, public, members-only, password, max users), muc#admin affiliation lists + role items with presence updates, kick 307, ban 301, destroy with occupant notification; temporary rooms vanish when empty |
| 26 | MIX (XEP-0369) | V | `test_mix_phase14.py` 17/17 — service at `mix.<host>` (registered in gen_mod + yml), create/destroy with owner check, join/leave/setnick with stable participant JIDs, participants node retrieval, groupchat reflection with `<mix>` nick/jid, non-participant messages dropped. Limits: no presence/info PubSub nodes, no MAM for channels, no PAM (XEP-0405) |

### S2S / federation — 3 V, 2 N

| # | Item | Status | Evidence / limit |
|---|---|---|---|
| 27 | Server Dialback (XEP-0220) both directions, forged keys rejected | V | S2S 17/17 |
| 28 | S2S STARTTLS (TLS 1.2/1.3) | V | S2S 17/17 |
| 29 | Federated messages / directed presence / IQ (incl. remote disco) | V | S2S 17/17 + slix 4/4 |
| 30 | SASL EXTERNAL for S2S | N | — |
| 31 | Bidirectional S2S streams (XEP-0288) | N | one dialback-verified connection per direction |

### HTTP stack — 7 V, 1 P, 0 N

| # | Item | Status | Evidence / limit |
|---|---|---|---|
| 32 | Web admin: login (SCRAM, admin ACL), dashboard, users, sessions | V | HTTP 46/46 + HTTP-edges 21/21 — rooms page (occupant counts, destroy) and PubSub page (nodes, delete) included |
| 33 | REST API: status, user CRUD, sessions (Bearer token) | V | HTTP 46/46 + HTTP-edges 21/21 — surface widened with rooms/nodes list + delete; ejabberd's full command set remains larger |
| 34 | BOSH (XEP-0124 + XEP-0206) | V | HTTP 46/46 |
| 35 | XMPP over WebSocket (RFC 7395) | V | HTTP 46/46 |
| 36 | HTTP File Upload (XEP-0363): slots, HMAC URLs, PUT/GET | V | HTTP 46/46 + HTTP-edges 21/21 — per-user quota `http.upload_quota` enforced (resource-constraint); virus scanning: ejabberd core has none either |
| 37 | TLS HTTP listener (HTTPS, 5443) | V | HTTP-edges 21/21: `tls: true` listener serves the full stack on 5443, plain 5280 unaffected |
| 38 | Captcha endpoint | V | HTTP-edges 21/21: create, PNG image, wrong answer 403, right answer 200, replay 403 (single-use, 300 s TTL) |
| 39 | ACME challenge handling, HTTP/2 | P | ACME http-01 serving verified (HTTP-edges 21/21: configured token served, unknown 404). HTTP/2 NOT implemented: the listener is a hand-rolled HTTP/1.1 server; an h2/HPACK stack is out of scope here |

### Media / signaling — 2 V, 3 P, 1 N

| # | Item | Status | Evidence / limit |
|---|---|---|---|
| 40 | Jingle signaling (XEP-0166 + ICE-UDP): routed verbatim, tracked | P | Jingle 25/25 — signaling only, no media/DTLS/SRTP by design; federated session tracked on one node only |
| 41 | STUN (RFC 5389) Binding | P | TCP path verified; **live UDP wire proof missing** — the sandbox blocks UDP `sendto` with EPERM, so UDP checks skip loudly and the same logic is covered in-process only |
| 42 | TURN (RFC 5766): Allocate/Refresh/Permissions/ChannelBind/relay | P | TURN over TCP verified live 2/2; live UDP relay unproven for the same sandbox reason; no per-user quota beyond global `max_allocations` |
| 43 | External service discovery (XEP-0215, incl. time-limited TURN credentials) | V | Jingle 25/25 |
| 44 | OMEMO legacy generation (XEP-0384 over PEP) | V | Jingle 25/25 |
| 45 | OMEMO generations `:1` / `:2` | N | not implemented or advertised |

### MQTT — 3 V, 0 N

| # | Item | Status | Evidence / limit |
|---|---|---|---|
| 46 | MQTT v3.1.1 broker: QoS 0/1/2, retained, Will, persistent sessions, takeover | V | MQTT 28/28 |
| 47 | MQTT ↔ XMPP PubSub bridge (both directions, loop protection) | V | MQTT 28/28 |
| 48 | MQTT 5.0 | V | `test_mqtt5_phase17.py` 21/21 (paho MQTTv5 + raw-socket client) + 16 ExUnit codec/broker tests — negotiated per CONNECT: full property codec, CONNACK limits (Receive Maximum 65535, Maximum Packet Size, Topic Alias Maximum 16, availability flags), property pass-through (content type, response topic, correlation data, user properties), subscription identifiers, subscription options (No Local, Retain As Published, Retain Handling 0/1/2), shared subscriptions (`$share`, round-robin, one copy per group), topic aliases (unknown alias → DISCONNECT 0x94), session expiry (persists across graceful DISCONNECT, DISCONNECT may narrow it to 0, raising it is a protocol error), Will Delay (fires at delay, at session end, or never when the session is continued; DISCONNECT 0x04 publishes at once), message expiry (retained + queued; remaining interval stamped at delivery), Receive Maximum windowing and Maximum Packet Size drop on outbound deliveries, assigned client identifiers for empty ClientIds, reason codes (0x86 bad auth, 0x8C authentication method refused — enhanced auth itself is not offered, a stray AUTH packet closes with DISCONNECT 0x82). Limits: no outbound topic-alias compression (server always sends full topic names), no request/response-information service beyond passing Response Topic through, server-initiated re-authentication not implemented |

### Clustering — 2 V, 1 P

| # | Item | Status | Evidence / limit |
|---|---|---|---|
| 49 | Cross-node routing: messages/presence/IQ reach users on other nodes (not via S2S) | V | cluster 22/22 |
| 50 | Shared Mnesia tables (accounts, roster, offline, MAM, PubSub) | V | cluster 22/22 |
| 51 | Cluster completeness | P | MUC rooms, vCards, SM resume state and per-host ETS caches stay node-local; two nodes with independent schemas cannot merge live; same resource on two nodes is last-registration-wins |

### Auth backends — 3 V, 2 P, 0 N

| # | Item | Status | Evidence / limit |
|---|---|---|---|
| 52 | Mnesia auth (SCRAM-SHA-256 verifiers, survives restart) | V | raw 18/18 + restart proofs |
| 53 | SQLite auth (same verifier format, migration tool) | V | SQLite 19/19 + 10 ExUnit |
| 54 | SQL / PostgreSQL / MySQL auth | P | **PostgreSQL: real backend, wire-verified (Fase 16)** — native PostgreSQL wire-protocol client written for this codebase (`Exjabberd.PgWire`: startup, cleartext/MD5/**SCRAM-SHA-256** auth with server-signature verification, extended query protocol, bytea) + `Exjabberd.Auth.Sql` storing the same SCRAM verifier format as Mnesia/SQLite in a `passwd` table; `test_auth_sql_phase16.py` boots a real PostgreSQL 16.9 (embedded binaries, SCRAM password auth) and proves PLAIN + SCRAM logins, slixmpp login, verifier hygiene (16 B salt / 4096 iters / 32 B keys, never the password), restart persistence, password rotation, remove_user, and Mnesia→SQL migration keeping the password — 19/19. **MySQL: NOT implemented** — no MySQL/MariaDB server exists in this sandbox to verify against, and the backend rejects a non-PostgreSQL `auth_sql.server` config explicitly instead of pretending (`{:error, :unsupported_server}`) |
| 55 | LDAP / JWT / OAuth / external / PAM auth | P | **JWT, OAuth and external are real backends, wire-verified (Fase 16)** by `test_auth_backends_phase16.py` — 25/25: JWT (native HS256 verification, `sub` = username, `exp`/`nbf` enforced, alg=none and wrong-secret tokens rejected), OAuth (RFC 7662 introspection over `:httpc` against a fixture endpoint: active/username/exp enforced, fails closed when the endpoint is down), external (ejabberd extauth length-prefixed stdio protocol against a fixture script: auth/isuser/tryregister/setpass/removeuser all effective on the wire). **LDAP: NOT implemented** — no LDAP server exists in this sandbox to verify a bind/search flow against, so it stays an honest stub. **PAM: NOT implemented** — PAM cannot be exercised meaningfully in this sandbox (no PAM service stack; the sandbox also runs as root), honest stub |
| 56 | Anonymous auth | V | re-probed Fase 11 (`test_starttls_anon_phase11.py`): with `auth_method: anonymous`, a never-registered user logs in with any password, binds and uses the session — the SASL `ANONYMOUS` mechanism itself is not advertised/implemented |

### Remaining ejabberd surface — 7 V, 0 P, 1 N

| # | Item | Status | Evidence / limit |
|---|---|---|---|
| 57 | Roster subscription requests (subscribe/subscribed flows) | V | Fase 11, `test_subscriptions_phase11.py` 17/17: full RFC 6121 state machine on both roster items (ask/pending-in), presence fan-out only to `from`/`both` contacts, initial-presence replay, unsubscribe/denial flows, server-generated unavailable on disconnect; plain roster sets no longer fabricate `both` |
| 58 | `starttls_required` | V | Fase 11, `test_starttls_anon_phase11.py`: with `starttls_required: true`, mechanisms are withheld on plaintext, `<starttls>` carries `<required/>`, plaintext auth is rejected with `policy-violation`, and login+bind succeed after the STARTTLS upgrade |
| 59 | vCard (XEP-0054) | V | Fase 10, `test_longtail_phase10.py`: set/get round-trip incl. nested elements, peer fetch returns the *addressee's* card, empty card for unset users (ETS storage — does not survive restart) |
| 60 | Private XML storage (XEP-0049) | V | Fase 10, `test_longtail_phase10.py`: set/get per namespace with verbatim element round-trip and per-user isolation (ETS storage) |
| 61 | Privacy lists / blocking (XEP-0016 / XEP-0191) | V | Fase 10, `test_longtail_phase10.py`: list get/set/delete, `<active/>`/`<default/>`, router-level enforcement (blocked message dropped, blocked IQ answered `service-unavailable`, unblock restores delivery) |
| 62 | Last activity (XEP-0012) | V | Fase 10, `test_longtail_phase10.py`: server uptime query and per-user seconds-since-logout with status text (also fixed the dead `"global"` hook registration that had prevented recording entirely) |
| 63 | Ad-hoc commands (XEP-0050) | V | Fase 10, `test_longtail_phase10.py`: disco#items/#info on the commands node, `get-online-users` completes with a jid-multi result, two-step `announce` form flow delivers a headline message to online users |
| 64 | Long tail: SOCKS5 bytestreams (XEP-0065), Push (XEP-0357), shared roster, avatars (XEP-0084), caps, announce, CAPTCHA, delegation, … | N | partial implementations only, none wire-verified; "39 modules start at boot" means they load, not that they work |

## Count

- Verified (V): 53 — items 1–29, 32–38, 43–44, 46–48, 49–50, 52–53, 56–63.
- Partial (P): 7 — items 39 (ACME yes, HTTP/2 no), 40–42 (Jingle signaling; STUN/TURN UDP unproven in the sandbox), 51 (cluster completeness), 54 (SQL auth: PostgreSQL verified, MySQL not implemented), 55 (JWT/OAuth/external verified; LDAP + PAM not implemented).
- Not implemented (N): 4 — items 30–31 (S2S EXTERNAL, Bidi), 45 (OMEMO :1/:2), 64 (grouped long tail).
- Total: 64. Score: (53 + 7 × 0.5) / 64 = 56.5 / 64 ≈ **88%**.

(The earlier draft of this section still carried the pre-Fase-10
counts — 34/9/21 ≈ 60% — long after the checklist rows above it had
been updated. Corrected 2026-11-13 during re-verification; the
verdict at the top of this file was already the right one.)

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
- **Room-creation race — ROOT-CAUSED AND FIXED (2026-11-13, Fase
  16):** what first looked like a MAM flake (`test_mam_pubsub.py`
  failing its room-history check in ~half of runs, always with a
  correct archive afterwards) was a check-then-act race in
  `Muc.create_room/3`: two joins hitting a new room at the same
  moment both saw an empty ETS index, both started a room process,
  and the second `:ets.insert` silently overwrote the first — the
  losing room kept its creator as a stranded occupant while the
  index pointed at the winner, so the loser missed reflections and
  room MAM answers (traced live with `:dbg`: the loser's handler
  correctly returned `forbidden` for a room he had "joined"; occupant
  dumps showed exactly one nick per room, alternating by run,
  instead of two). The claim is now atomic (`:ets.insert_new`; the
  loser terminates its duplicate and joins the winner), and MIX
  channel creation got the same treatment. Evidence after the fix:
  8/8 two-client join races show both occupants, and
  `test_mam_pubsub.py` passes 47/47 in four consecutive runs
  (before: 5 failures in 6 runs on an aged server).
- **verify.sh harness gap found and fixed (2026-11-13):** the Fase
  12–14 probes assume a running dev server on 5222, but verify.sh
  stopped its step-03 server before them, so a from-scratch
  `./verify.sh` could never pass that block (the Fase 10–15 probes
  had been run against a manually booted server instead). verify.sh
  now boots a fresh dev server for that block (step 04c) and the
  full script passes end-to-end.
