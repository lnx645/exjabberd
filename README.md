# exjabberd

XMPP server in Elixir (rewrite from scratch, not a fork of ejabberd).
Partial ejabberd compatibility — no module claims full parity. See
[Verified features](#verified-features) for what actually works over
the wire, and [Not implemented](#not-implemented) for the rest.

## Running

Requires Elixir ~> 1.19 and Erlang/OTP 28.

```sh
mix deps.get
mix compile
```

The server **must be started with a named node**: Mnesia `disc_copies`
tables (durable accounts) require one, and without it account creation
fails loudly instead of silently keeping accounts in ETS only.

```sh
ELIXIR_ERL_OPTIONS="+fnu -sname exjabberd" mix run --no-halt
```

Listens on TCP **5222** (C2S, STARTTLS optional) and, when
`exjabberd.yml` enables it, **5223** (direct TLS C2S), **5280**
(HTTP: web admin `/admin`, REST API `/api`, BOSH
`/bosh` + `/http-bind`, XMPP over WebSocket `/ws`, HTTP File Upload
`/upload`, captcha `/captcha`) and **5443** (the same HTTP stack
over TLS — any `exjabberd_http` listener with `tls: true`). The
TLS certificate is self-signed for `localhost`,
generated on first use into `priv/ssl/` (gitignored). Production
deployments must use a real certificate for the server domain
instead.

HTTP settings live in the `http:` section of `exjabberd.yml`
(REST API Bearer token, HMAC secret for upload URLs + admin
cookies, upload directory/size/lifetime, BOSH wait/inactivity).
Admin login uses a real XMPP account listed in the `admin` ACL
(default `admin@localhost` — create it first); there is no
separate admin password and no default credential.

Configuration lives in `exjabberd.yml` at the repo root (the
application also accepts `config/exjabberd.yml` and `nxmpps.yml`, in
that order). Only listeners and modules that are actually implemented
are listed there; the file documents what is missing in commented
blocks.

## Creating users

```sh
# from a shell on the same machine (RPC into the running node):
ELIXIR_ERL_OPTIONS="+fnu -sname helper" elixir -e '
  Node.connect(:"exjabberd@<hostname>")
  :timer.sleep(500)
  IO.inspect(Exjabberd.Auth.create_user("localhost", "alice", "secret"))
'
```

Or in-band registration (XEP-0077) over XMPP, which is enabled by
default. Passwords are stored as SCRAM-SHA-256 verifier data only
(salt, iterations, StoredKey, ServerKey) — never cleartext.

## Tests

One command runs the whole verification — ExUnit plus every probe,
against real servers:

```sh
./verify.sh
```

It fetches dependencies (`mix deps.get`, a no-op when `deps/` is
already populated), compiles (warnings are errors), runs `mix test`, boots a
single-node dev server and runs every single-node probe, then the
SQLite probe (which boots its own server), then the two-node S2S
probes, then the two-node cluster probe — stopping every server it
started, and printing a per-step PASS/FAIL summary at the end
(logs in `/tmp/exjabberd-verify-logs/`). All green on 2026-11-11
from a fresh clone: 19/19 steps. Requirements: Elixir ~> 1.19 / OTP 28 on PATH (or
`$EXJABBERD_TOOLCHAIN`, default `$HOME/workspace/.toolchain`) and
Python with slixmpp + paho-mqtt (`$EXJABBERD_PY`, or
`$HOME/workspace/.venv-xmpp/bin/python`); no server already
listening on the test ports.

`mix test` alone (119 tests, 0 failures) needs a clean run — wipe
the test Mnesia dir first, and stop any dev server (the suite boots
the app on port 5222 itself):

```sh
rm -rf mnesia_data_test
ELIXIR_ERL_OPTIONS="+fnu -sname exjabberd-test" mix test
```

| Suite | File | Tests |
|---|---|---|
| Stream parser | `test/exjabberd/xmpp/stream_parser_test.exs` | 8 |
| SCRAM | `test/exjabberd/auth/scram_test.exs` | 5 |
| SQLite auth + migration | `test/exjabberd/auth/sqlite_test.exs` | 10 |
| Cluster | `test/exjabberd/cluster_test.exs` | 16 |
| HTTP stack | `test/exjabberd/http_test.exs` | 9 |
| Jingle / OMEMO / STUN / TURN | `test/exjabberd/jingle_omemo_test.exs` | 11 |
| Live C2S | `test/exjabberd/live_c2s_test.exs` | 12 |
| MAM / PubSub | `test/exjabberd/mam_pubsub_test.exs` | 8 |
| MQTT codec + broker | `test/exjabberd/mqtt_test.exs` | 15 |
| S2S dialback | `test/exjabberd/s2s_dialback_test.exs` | 5 |
| SM / Carbons / CSI | `test/exjabberd/sm_carbons_csi_test.exs` | 9 |
| STUN / TURN codec | `test/exjabberd/stun_turn_test.exs` | 11 |

The repeatable wire probes at the repo root (all run by
`verify.sh`):

| Probe | What it proves | Result |
|---|---|---|
| `audit_raw_test.py` | C2S core over raw sockets | 18/18 |
| `audit_slix_test.py` | C2S core with slixmpp 1.17 | 10/10 |
| `test_sm_carbons_csi.py` | XEP-0198 / 0280 / 0352 | 36/36 |
| `test_mam_pubsub.py` / `test_mam_pubsub_slix.py` | MAM + PubSub, raw / slixmpp | 47/47, 12/12 |
| `test_s2s.py` / `test_s2s_slix.py` | S2S dialback, two nodes (boot with `./boot_s2s_nodes.sh start`) | 17/17, 4/4 |
| `test_http_phase4.py` | admin + REST API + BOSH + WebSocket + upload | 46/46 |
| `test_jingle_phase5.py` | Jingle + extdisco + OMEMO | 25/25 |
| `test_stun_turn_phase5.py` | STUN/TURN (TCP live; UDP skips in the sandbox, see below) | 2/2 |
| `test_mqtt_phase6.py` | MQTT 3.1.1 + PubSub bridge | 28/28 |
| `test_cluster_phase7.py` | clustering, two nodes (boot with `./boot_cluster_nodes.sh start`) | 22/22 |
| `test_auth_sqlite_phase8.py` | SQLite auth + migration (boots its own server) | 19/19 |

286 wire-probe checks in total, all passing. Formatting: a
`.formatter.exs` exists now (added in Fase 9); the files changed in
Fase 9 are `mix format`-clean. The rest of the repo predates it and
is deliberately NOT reformatted in one sweep — a repo-wide
`mix format` is a separate cleanup, not a parity change.

## Verified features

Verified over the wire with real clients (raw sockets + slixmpp 1.17
+ paho-mqtt) on 2026-11-11 — raw harness 18/18, slixmpp harness
10/10, probe `test_sm_carbons_csi.py` 36/36,
probe `test_mam_pubsub.py` 47/47, probe
`test_mam_pubsub_slix.py` 12/12, probe `test_s2s.py` 17/17,
probe `test_s2s_slix.py` 4/4, probe `test_http_phase4.py` 46/46,
probe `test_jingle_phase5.py` 25/25, probe
`test_stun_turn_phase5.py` 2/2 (TCP; UDP checks skipped in the
sandbox — see the Fase 5 limits below), probe
`test_mqtt_phase6.py` 28/28, probe `test_cluster_phase7.py`
22/22, probe `test_auth_sqlite_phase8.py` 19/19. `mix test` is
119/119 green. Run it all yourself with `./verify.sh`
(19/19 steps green). The honest per-area score is in
[`docs/PARITY.md`](docs/PARITY.md): **≈60% of the 64-item
checklist — not 100%**. What is verified is listed below; what is
not is in [Not implemented](#not-implemented).

* Stream open returns exactly one valid `<stream:features>` (RFC 6120 §4.3).
* SASL PLAIN and **SCRAM-SHA-256** (RFC 5802, channel binding `n` and
  `y` accepted; `p` rejected). PLAIN is verified against the stored
  SCRAM verifier data — there is no plaintext password anywhere.
* STARTTLS (RFC 6120 §4.7): real `:ssl` handshake, TLS 1.2/1.3.
  After TLS, STARTTLS is no longer offered. Direct-TLS C2S on 5223.
* Resource binding; one C2S process per connection holds the socket
  and writes routed stanzas to it.
* Roster (RFC 6121): get/set/remove, versioning, push to sessions.
* Service discovery (XEP-0030), ping (XEP-0199), entity time
  (XEP-0202), software version (XEP-0092), in-band registration
  (XEP-0077, incl. duplicate → `conflict`).
* Presence broadcast and 1-1 messages both ways; message to an
  unknown user gets a `service-unavailable` error.
* Multi-user chat (XEP-0045): join (self-presence 110, 201 for the
  creator), presence exchange, groupchat messages, leave, disco on
  `conference.localhost`. Rooms are supervised GenServers.
* Offline messages (RFC 6121 §5): stored in Mnesia (disc_copies,
  cap 100/user), flushed on next login.
* Malformed XML → `<stream:error><invalid-xml/></stream:error>`
  (RFC 6120 §4.9); stanza over 262,144 bytes → `policy-violation`.
* Accounts survive a server restart (Mnesia schema + disc_copies
  under `mnesia_data/`; the test env uses `mnesia_data_test/`).
* 39 modules start at boot from `modules:` in `exjabberd.yml`
  (`Exjabberd.Mod.Supervisor.loaded("localhost")` is no longer empty).
* **Stream Management (XEP-0198, `urn:xmpp:sm:3`)**: `<enable/>` →
  `<enabled id previd max resume/>` (after resource binding),
  `<r/>` → `<a h='N'/>` with exact inbound counting (message,
  presence and IQ replies all count), client `<a h='N'/>` drops
  acked stanzas (too-high `h` → `handled-count-too-high` stream
  error), `<resume h previd/>` → `<resumed h previd/>` with replay
  of unacked stanzas only (unknown previd → `<failed/>`
  `item-not-found`). A dropped TCP connection detaches the session
  instead of killing it; the session stays resumable for
  `resume_timeout` seconds (60, configured in `exjabberd.yml`),
  then ends and offers unacked messages to offline storage.
* **Message Carbons (XEP-0280, `urn:xmpp:carbons:2`)**: IQ-set
  `<enable/>` / `<disable/>` per resource (off by default);
  outbound messages copied to the user's other enabled resources
  as `<sent/>`, inbound as `<received/>`, each wrapping the
  original in `<forwarded/>` and sent from the bare JID. Not
  copied: `type='error'` / `groupchat`, MUC-sent messages,
  messages with `<private/>`, and carbons themselves.
* **Client State Indication (XEP-0352, `urn:xmpp:csi:0`)**:
  `<active/>` / `<inactive/>` (no reply); while inactive, message
  and presence stanzas are queued and flushed in order on
  `<active/>`, while IQ and error stanzas are still delivered
  immediately. CSI resets to `active` on stream resumption.
* **Message Archive Management (XEP-0313, `urn:xmpp:mam:2`)**: 1-1
  messages archived per user in Mnesia (`disc_copies`, survives a
  restart; verified across a kill + reboot) with a unique id and an
  XEP-0082 delay stamp; query via IQ with `with` / `start` / `end`
  filters and RSM paging (`max` / `before` / `after`, incl. empty
  `<before/>` = last page); results arrive as `<message/>` stanzas
  carrying `<result><forwarded><delay/><message/></forwarded></result>`
  and the IQ result carries only `<fin complete><set><first/><last/><count/></set></fin>`.
  Prefs get/set (`default='always|never|roster'`, `<always/>` /
  `<never/>` lists; `roster` archives only roster peers). Archive
  size is capped per user by `max_archive_size` (500, configured in
  `exjabberd.yml`, oldest dropped first). MUC room history is
  archived the same way (owner = room bare JID) and queryable with a
  MAM query addressed to the room. Advertised in disco#info.
* **Publish-Subscribe (XEP-0060 core)**: service at
  `pubsub.localhost` (disco#info / disco#items, incl. per-node
  disco#info), nodes / items / subscriptions / affiliations
  persisted in Mnesia (`disc_copies`, survives a restart; verified
  across a kill + reboot). Create / delete (owner namespace),
  subscribe / unsubscribe (with `subid`), publish (owner/publisher
  or open publish model; non-publishers get `forbidden`), retract,
  purge, get items (with `max_items` / RSM `<max/>`), get
  subscriptions / affiliations, and owner get/set node
  configuration (`access_model`, `publish_model`, `max_items`,
  `persist_items`, `deliver_payloads`). Subscribers receive
  `<message type='headline'>` event notifications with the item
  payload. Node `max_items` is enforced (oldest dropped first).
  Duplicate create → `conflict`; unknown node → `item-not-found`.
* **Server-to-Server / federation (RFC 6120 §4, XEP-0220 Server
  Dialback, port 5269)**: inbound S2S listener (`jabber:server`
  streams, features advertise STARTTLS + dialback) and one
  outbound connection per remote domain, reused across stanzas.
  Dialback in both directions — initiating side sends
  `<db:result/>` with an HMAC-SHA256 key
  (`HMAC-SHA256(hex(SHA256(secret)), "to from stream-id")`, verified
  against both worked examples in XEP-0220 v0.15), receiving side
  verifies it by opening a dialback connection to the Authoritative
  Server for the asserted domain and answering `<db:result
  type='valid'|'invalid'/>`, and every server answers
  `<db:verify/>` as Authoritative Server from its own secret.
  STARTTLS on S2S (TLS 1.2/1.3, same dev certificate as C2S);
  the feature disappears after the upgrade so a peer never asks
  for TLS twice. Stanzas flow only over dialback-verified
  connections and only from the verified domain; a forged key is
  answered `invalid`, the stream is closed, and no stanza leaks.
  Messages / directed presence / IQ (incl. disco#info to the remote
  server domain, answered back over the reverse connection) all
  federate. A stanza to an unreachable domain is bounced to its
  sender as `<remote-server-not-found/>` — never silently dropped
  (a failed outbound connection lingers briefly in `:failed`,
  bouncing arrivals, instead of losing stanzas that were sent
  while it was dying). Domain resolution: `s2s_host_overrides`
  in `exjabberd.yml` first (domain → host/port, for tests and
  DNS-less deployments), then DNS SRV `_xmpp-server._tcp`, then
  A/AAAA on 5269. The dialback secret comes from
  `s2s_dialback_secret` in `exjabberd.yml`; when absent the server
  generates a random ephemeral secret at boot (logged as a
  warning). Listeners are now started from the config's `listen:`
  list (C2S plain/TLS + S2S inbound), and a client that opens a
  stream to a non-default host is bound under that host (before,
  every session was `user@localhost`, which broke federation).

  Honest limits of this phase (not bugs, just not built yet):
  no SASL EXTERNAL for S2S and no bidirectional streams (XEP-0288)
  — federation uses one dialback-verified connection per direction;
  the dialback verify connection is plain TCP (XEP-0220 allows
  verify-only connections without TLS), so a peer with
  `s2s_use_starttls: required` cannot be verified that way; TLS
  peer verification is off (`verify_none`, self-signed dev
  certificate) — production needs a real certificate and domain
  check (RFC 6120 §5.4.2); S2S uses the first configured host as
  the sender domain (multi-host sender selection is not done);
  the sandbox DNS resolver answers for every name, so a negative
  DNS test is meaningless there — the unreachable-domain probe uses
  a configured override to a closed port instead. Two-node proof:
  `test_s2s.py` 17/17 and `test_s2s_slix.py` 4/4 (two live nodes,
  `a.localhost` ↔ `b.localhost`).

  Honest limits of this phase (not bugs, just not built yet):
  `presence` / `roster` access models behave like `open` for local
  users; two messages archived within the same millisecond from two
  different sessions have no defined cross-process order (the same
  race exists in ejabberd's send/receive hooks) — the probes space
  sends out to keep the expected order deterministic.
  (Collection nodes and the `authorize` approval flow arrived in
  Fase 13, MUC room administration and the MAM membership check in
  Fase 12 — see `docs/PARITY.md`.)


* **HTTP stack (port 5280, plain `:gen_tcp`, zero new dependencies)**:
  the stack decision is documented in `Exjabberd.Http.Server`:
  BOSH long-polling and WebSocket framing need custom
  per-connection processes anyway, so Plug/Bandit would add a Hex
  dependency without removing any of the real work.
* **Web admin (`/admin`)**: real login page — the password is
  verified against the stored SCRAM verifier data and the user
  must be listed in the `admin` ACL (wrong password → 401,
  correct password for a non-admin user → 401); after login a
  signed HttpOnly session cookie (HMAC-SHA256, 8 h) guards the
  dashboard (uptime, registered-user count, online sessions,
  loaded modules — all live numbers, cross-checked against the
  REST API), the users page (list / create / delete / reset
  password — a user created in the UI can log in over XMPP, a
  deleted user cannot, and live sessions are closed on delete),
  the sessions page (every online session), the rooms page (MUC
  rooms with occupant counts + destroy) and the PubSub page
  (service nodes with type/owner/subscriber counts + delete).
  No external assets, no placeholder pages.
* **REST API (`/api`, Bearer token from `http.api_token`)**:
  `GET /api/status` (version, uptime, hosts, user/session
  counts), user CRUD (`GET/POST /api/users`,
  `GET/DELETE /api/users/:user`, `POST /api/users/:user/password`),
  `GET /api/sessions`, and the MUC/PubSub surface
  (`GET /api/rooms`, `DELETE /api/rooms/:room`,
  `GET /api/nodes`, `DELETE /api/nodes/:node`); no token or a
  wrong token → 401.
* **HTTPS listener**: any `exjabberd_http` listen entry with
  `tls: true` serves the whole HTTP stack over TLS (the shipped
  config adds port 5443 next to plain 5280), using the server's
  TLS certificate (`Exjabberd.Tls`, self-signed in dev).
* **Captcha endpoint (`/captcha`)**: `POST /captcha` creates a
  challenge and returns its id; `GET /captcha/:id` renders the
  answer as a PNG generated in-process (bitmap font + noise);
  `POST /captcha/:id` verifies an answer — challenges are
  single-use (any attempt burns them) and expire after 300 s.
  The answer is stored server-side only (`mod_captcha`).
* **ACME http-01**: `GET /.well-known/acme-challenge/:token`
  serves the key authorization configured under
  `http.acme_challenges` (filled in by your ACME client during
  issuance); unknown tokens → 404.
* **BOSH (XEP-0124 + XEP-0206, `/bosh` + `/http-bind`)**: session
  creation returns `sid` + `wait`/`inactivity`/`polling`/
  `requests`/`hold` + stream features; SASL PLAIN (and SCRAM, via
  the shared transport), `xmpp:restart`, resource binding and
  long-polling all work. A BOSH client and a TCP client exchange
  messages both ways; a repeated `rid` replays the cached
  response; unknown `sid` → 404; `type='terminate'` ends the
  session.
* **XMPP over WebSocket (RFC 7395, `/ws`, subprotocol `xmpp`)**:
  RFC 6455 handshake + framing (masked client frames, text/binary/
  continuation, ping → pong, close handshake) with a full XMPP
  stream on top (stream open, auth, bind, messages, `<open/>`
  framing also accepted). A WebSocket client and a TCP client
  exchange messages both ways; a wrong subprotocol is rejected.
* **HTTP File Upload (XEP-0363)**: IQ-set `<request filename size
  content-type/>` → `<slot><put url/><get url/></slot>`; PUT
  uploads the exact bytes (size and content-type verified) and
  GET downloads byte-identical content (hash-checked); URLs are
  HMAC-signed with an expiry (forged token → 403, unknown slot →
  404, GET before upload → 404, oversize request →
  `not-acceptable`); a per-user quota (`http.upload_quota`,
  default 100 MB of live slots) refuses further slot requests
  with `resource-constraint`; files live under `priv/uploads/`
  (gitignored)
  as bare slot ids, so the client filename never touches the
  filesystem; expired slots are swept periodically.
* **Shared XMPP transport** (`Exjabberd.Http.XmppTransport`):
  BOSH and WebSocket run the *same* session code as TCP (SASL,
  bind, SM, CSI, IQ dispatch for roster/disco/MAM/PubSub/upload,
  message/presence routing) by starting a `C2S` process with an
  `out_pid` instead of a socket (`Exjabberd.C2S.set_out_pid/2` +
  `sync/1` barrier so IQ replies reach the HTTP response).

  Honest limits of this phase (not bugs, just not built yet):
  no HTTP/2 (the listener speaks HTTP/1.1); ACME is limited to
  serving pre-configured http-01 challenges (no built-in ACME
  client);
  BOSH `hold` is fixed at 1 and only the last 5 responses are
  kept for `rid` replay; Stream Management `<resume/>` across
  BOSH/WebSocket connections is refused (`item-not-found` —
  BOSH retransmits by `rid` instead, and a WebSocket reconnect
  starts a fresh stream); upload has no per-user quota and no
  virus scanning; the admin UI has no MUC/PubSub management
  pages; the old stub `Exjabberd.Web.*` modules were deleted and
  `Exjabberd.Web.handle/1` now delegates to the real router.

* **Jingle signaling (XEP-0166 + XEP-0176 ICE-UDP, `mod_jingle`)**:
  the server is signaling-only — it never touches media. IQ-sets
  with a `<jingle/>` payload between two full JIDs are intercepted
  (`session-initiate`, `session-accept`, `session-terminate`,
  `transport-info`, `session-info`): the stanza is routed verbatim
  to the peer (content / description / transport / ICE candidates
  byte-identical on the wire) and the peer's own IQ-result/error
  is the initiator's answer — the server never fakes an ack.
  Sessions live in ETS keyed `{host, sid}` with initiator,
  responder and state (`pending` → `active` on accept); a
  `session-terminate` or either party disconnecting deletes the
  session. Wrong-side actions and unknown actions get the spec
  errors: `session-terminate` on an unknown sid →
  `item-not-found` + `<unknown-session/>`
  (`urn:xmpp:jingle:errors:1`), an unknown action →
  `feature-not-implemented`, a malformed initiate →
  `bad-request`. Federated Jingle to a local user passes the same
  gate (tracked, routed, or answered back over S2S); Jingle to a
  remote user is routed onward untouched. The old stub
  `handle_jingle` (which answered without forwarding) is gone.
* **STUN (RFC 5389) + TURN (RFC 5766) on port 5478
  (`Exjabberd.StunTurn.*`, UDP + TCP)**: Binding Request →
  Binding Success with XOR-MAPPED-ADDRESS (and MAPPED-ADDRESS)
  and MESSAGE-INTEGRITY + FINGERPRINT when requested; Allocate
  with the RFC 5389 long-term credential mechanism (401 with
  REALM + stateless NONCE, then USERNAME / REALM / NONCE /
  MESSAGE-INTEGRITY with key `MD5(username:realm:password)` where
  the password is `Base64(HMAC-SHA1(shared_secret, username))` —
  the same derivation XEP-0215 advertises, so no password store
  exists); wrong password → 401, duplicate allocation → 437,
  Refresh (lifetime 0 deletes), CreatePermission (300 s),
  ChannelBind + ChannelData relay (600 s), Send/Data indication
  relay through a real relayed UDP socket per allocation, and
  Delete Allocation. TURN over TCP uses the RFC 5766 §7.2
  length-prefixed framing (STUN + ChannelData share one
  per-connection process). The relay socket binds `0.0.0.0` but
  advertises a reachable address (the resolved `turn.host`,
  `127.0.0.1` by default; `turn.relay_ip` / `turn.advertise_ip`
  override it). All of it is configured in the `turn:` section of
  `exjabberd.yml` (port, host, realm, shared secret, TCP on/off,
  lifetimes, `max_allocations`); the secret is never hardcoded —
  when absent the server generates an ephemeral one at boot (like
  the dialback secret) and logs a warning.
* **External service discovery (XEP-0215, `urn:xmpp:extdisco:2`)**:
  IQ-get `<services/>` answers the STUN service and the TURN
  service (UDP + TCP) with per-user time-limited credentials
  (`username='<unix-expiry>:<user>@<host>'`, password derived from
  the TURN shared secret); the legacy `:1` namespace is answered
  the same way. The server disco#info advertises
  `urn:xmpp:jingle:1`, `urn:xmpp:jingle:apps:rtp:1`,
  `urn:xmpp:jingle:transports:ice-udp:1` and `urn:xmpp:extdisco:2`.
* **OMEMO over PEP (XEP-0384 legacy generation + XEP-0163,
  `mod_omemo`)**: the device list node
  `eu.siacs.conversations.axolotl.devicelist` and one bundle node
  per device `eu.siacs.conversations.axolotl.bundles:<deviceId>`
  live on the user's own bare JID as PEP nodes (internal key
  `<bare JID>/<node>`, so two users publishing the same node name
  never collide). First publish auto-creates the node (XEP-0163
  §4) with the OMEMO config — access `open`, publish `open`,
  `max_items: 1`, `persist_items: true`; publish-options are
  honoured, and `pubsub#max_items = "max"` means 100,000.
  Publishing to someone else's PEP nodes is `forbidden`; a contact
  fetches the list / bundle with an IQ-get to the owner's bare
  JID and gets the payload byte-identical; subscriptions get a
  `<message type='headline'>` notification from the owner's bare
  JID on republish. Bare-JID disco#info advertises
  `urn:xmpp:omemo:0` and bare-JID disco#items lists the user's PEP
  nodes (the service disco#items no longer leaks them). PEP
  PubSub and bare-JID disco IQs addressed to a local user are now
  answered by the server itself instead of being delivered to
  that user's client socket — that was a pre-existing routing gap
  (C2S delivered every routed IQ to the client); the same
  interception applies to federated PEP/disco over S2S. The old
  `Exjabberd.Mod.Omemo` in `mod/encryption.ex` (wrong node names
  `urn:xmpp:omemo:0` / `urn:xmpp:omemo:0:devicelist`, and a
  duplicate module definition shadowing the new one) was deleted.
* **MQTT v3.1.1 broker (Fase 6, port 1883, `mod_mqtt`)**: real
  `paho-mqtt` clients connect (anonymous when `mqtt.allow_anonymous`
  is true, otherwise the username/password is checked against the
  XMPP accounts — no separate MQTT password store), subscribe with
  `+`/`#` wildcards, and publish at QoS 0/1/2 with the full
  handshake (PUBACK, PUBREC/PUBREL/PUBCOMP); retained messages are
  stored and delivered to late subscribers (an empty retained
  publish clears them); PINGREQ → PINGRESP; a client that dies
  without DISCONNECT publishes its Will message, a clean DISCONNECT
  does not; a second connection with the same client id takes over
  the session; persistent sessions (`clean_session: false`) keep
  their subscriptions and queue QoS 1/2 messages while offline,
  replayed on reconnect; keep-alive timeout (1.5 × keep alive)
  closes silent clients; oversize payloads (over `mqtt.max_payload`,
  262144) close the connection; a bad protocol version gets CONNACK
  `0x01` and a refused login gets `0x05`. All limits live in the
  `mqtt:` section of `exjabberd.yml` (`allow_anonymous`,
  `max_payload`, `max_clients`, `max_queued`, `bridge.*`).
* **MQTT ↔ XMPP PubSub bridge (Fase 6, `mod_mqtt_bridge`)**: an
  MQTT topic maps to a PubSub node of the same name, both
  directions — an MQTT publish auto-creates the node (open/open)
  and arrives at XMPP subscribers as a PubSub event, and an XMPP
  publish arrives at MQTT subscribers as a plain publish. Each
  message crosses the bridge once per direction (loop protection
  via the `from_bridge` flag); the bridge is disabled with
  `mqtt.bridge.enabled: false`. MQTT 5.0 is NOT implemented — the
  broker speaks 3.1.1 only. The two-node S2S probe
  (`test_s2s.py`, 17/17 in Fase 3) was not re-run in this phase:
  it needs a second working copy of the repo, which this phase's
  scope forbids; the single-node S2S probe (`test_s2s_slix.py`)
  still passes 4/4 and no S2S code was touched.
* **Clustering (Fase 7, distributed Erlang, multi-node, same
  domain)**: two (or more) nodes with the SAME domain and the SAME
  Erlang cookie form one cluster. Session and route registrations
  are mirrored cluster-wide (`Exjabberd.Cluster` ETS mirrors,
  broadcast on register/unregister, full state exchange on
  `:nodeup`, purge on `:nodedown`), so a message, presence or IQ
  from a user on node A reaches a user on node B without the
  sender knowing which node the recipient is on — and NOT via S2S
  (S2S stays for foreign domains only). Presence is broadcast to
  every online session in the cluster. On `:nodedown` the dead
  node's sessions are purged, an `unavailable` presence is
  broadcast for each of its users, and messages to them fall
  through to the normal offline/error path (stored offline when
  the user exists, `service-unavailable` otherwise — never a
  hang). A node that returns rejoins on its own: the
  auto-connect loop retries `cluster.nodes` every 5 s, and a node
  booted with `EXJABBERD_CLUSTER_JOIN=<peer>` re-copies the
  cluster schema. Configuration lives in the `cluster:` section
  of `exjabberd.yml` (`enabled`, `nodes`, `cookie`) — no
  hardcoding; the cookie may also come from
  `EXJABBERD_ERLANG_COOKIE` or `config :exjabberd,
  cluster_cookie:`. When no cookie is configured the node's
  default cookie (`~/.erlang.cookie`, generated by Erlang itself
  when missing) stays in effect — deliberately no per-boot random
  cookie is generated, because it would break `:rpc` tooling
  (probes, remote shells) without making clustering work: two
  nodes still need the SAME cookie. Verified live with two real
  nodes (`boot_cluster_nodes.sh` + `test_cluster_phase7.py`,
  22/22): mutual visibility, chat both ways, presence both ways,
  roster shared, accounts shared, kill B → unavailable presence
  + message stored offline, restart B → cluster reforms +
  offline message delivered on relogin + chat works again.
  Shared Mnesia tables (`disc_copies` on every joined node):
  `:passwd`, `:roster`, `:offline_messages`, `:mam_archive`,
  `:pubsub_nodes`, `:pubsub_items`, `:pubsub_subs`,
  `:pubsub_affs`. Roster items are written through to Mnesia as
  well as the local ETS cache (Fase 7 change in `Mod.Roster`).
  Join mechanics worth knowing: a joining node wipes its own
  fresh schema directory and starts Mnesia with `extra_db_nodes`
  pointing at the peer, so it copies the cluster schema; the
  local schema must become `disc_copies` BEFORE table replicas
  are added (`add_table_copy` fails with "has no disc" otherwise,
  and `change_table_copy_type` cannot add a copy where none
  exists — `Exjabberd.Mnesia.ensure_table/2` now handles the
  no-local-copy case with `add_table_copy`); `Process.alive?/1`
  raises `ArgumentError` for remote pids, so remote liveness is
  checked with an `:rpc` probe (`Exjabberd.Cluster.alive?/1`);
  `:net_kernel.monitor_nodes(true)` sends 2-tuples
  `{:nodeup | :nodedown, node}` — handlers must match both the
  2-tuple and the 3-tuple form; `net_ticktime` 10 s in the boot
  script keeps dead-node detection near 10 s instead of 60 s.
  Admin visibility: `Exjabberd.Cluster.status/0` (also in the
  admin `:status` command) reports nodes, cookie state, Mnesia
  state and session counts; the cookie value is never exposed.
  Limits: MUC rooms, vCards, Stream Management resume state and
  per-host ETS caches stay node-local (an SM resume must hit the
  node that holds the session); the roster version counter is
  per-node (versions are random strings, so divergence is
  harmless); two nodes that already have independent Mnesia
  schemas cannot merge live — session routing still works, but
  tables stay unshared until the node is restarted with
  `EXJABBERD_CLUSTER_JOIN`; a user bound with the same resource
  on two nodes at once is last-registration-wins in the mirror
  (each node's local routing still works); the mirror is
  eventually consistent (broadcast + nodeup sync), so a stanza
  sent in the ~1 s window before a join sync may miss a
  just-registered remote session and fall through to offline
  storage instead.

  Honest limits of this phase (not bugs, just not built yet):
  the server does no media processing and no DTLS/SRTP — Jingle
  is signaling only; federated Jingle is routed but the session
  is only tracked on the node that saw the initiate (a terminate
  arriving via the other node is not tracked there); OMEMO is the
  legacy generation only — the newer `urn:xmpp:omemo:1` / `:2`
  generations (single `...:bundles` node, `urn:xmpp:omemo:2:devices`)
  are not implemented or advertised; TURN has no per-user quota
  beyond the global `max_allocations`; STUN Binding without
  credentials is answered unauthenticated (allowed by RFC 5389);
  **UDP wire verification could not run in this sandbox**: the
  sandbox blocks UDP `sendto` with EPERM for every process
  (proven by a minimal Python repro — `socket.sendto` to
  127.0.0.1 fails with `PermissionError` — and `aiortc` 1.16 was
  installed but cannot help, it uses UDP too), so the live UDP
  STUN/TURN checks in `test_stun_turn_phase5.py` and in
  `test/exjabberd/jingle_omemo_test.exs` are skipped loudly there
  and the same logic is covered in-process instead (synthetic
  `{:udp, ...}` messages to the real server process +
  `Allocation` with `server: self()`, asserting the exact Data
  indication / ChannelData bytes the relay builds). TURN over TCP
  *is* verified live (2/2 in the probe, plus the ExUnit TCP test).
  Run `test_stun_turn_phase5.py` where UDP is allowed for the
  full UDP wire proof.

* **SQLite auth backend (Fase 8, `auth_method: sqlite`)**: the
  first real non-Mnesia backend. `Exjabberd.Auth.Sqlite` stores
  exactly the same SCRAM-SHA-256 verifier data as the Mnesia
  backend (salt, iteration count, StoredKey, ServerKey — raw
  bytes as BLOBs, one row per `(host, user)` in a `passwd` table
  in the configured file), so PLAIN and SCRAM-SHA-256 logins
  verify identically on either backend and an account keeps its
  password when it moves. Selection is per-host from
  `auth_method:` in `exjabberd.yml` (default stays `mnesia`, so
  existing installs are untouched); the file comes from
  `auth_sqlite.path` (default `priv/auth.sqlite3`) or the
  `EXJABBERD_AUTH_SQLITE_PATH` environment variable, never from a
  hardcoded path, and the file holds verifier data only — no
  credentials are configured anywhere. All access is serialized
  through one GenServer connection (WAL mode, `busy_timeout`
  5000). The behaviour is now complete (`Exjabberd.Auth.Behaviour`
  gained optional `get_scram/2`, `get_users/1`,
  `store_scram_verifier/3` callbacks; the Mnesia backend
  implements them, the stub backends do not need to). Moving
  accounts: `mix exjabberd.auth.migrate --from mnesia --to sqlite`
  copies every user's verifier verbatim (`--dry-run` counts
  without writing; the source is never modified, so it stays as a
  rollback — switch the server over afterwards with
  `auth_method: sqlite`). Verified live (`test_auth_sqlite_phase8.py`,
  real slixmpp clients): create → PLAIN + SCRAM login → server
  restart → login still works → password change (old fails, new
  works) → delete (login fails); a Mnesia-created user logs in on
  SQLite after migration with the same password; plus 10 ExUnit
  tests (`test/exjabberd/auth/sqlite_test.exs`) including
  persistence across a backend restart and the verbatim-verifier
  round-trip. Honest limits of this phase: at the time, PostgreSQL/
  MySQL were NOT implemented (no PostgreSQL server existed in this
  sandbox then). **Update (Fase 16): PostgreSQL IS implemented and
  wire-verified** — a native PostgreSQL wire-protocol client
  (`Exjabberd.PgWire`, incl. SCRAM-SHA-256 database auth) plus
  `Exjabberd.Auth.Sql` with the same verifier format, proven
  against a real PostgreSQL 16.9 by `test_auth_sql_phase16.py`
  (19/19). The JWT, OAuth (introspection) and external (extauth)
  backends are also real since Fase 16
  (`test_auth_backends_phase16.py`, 25/25). MySQL is still NOT
  implemented (no MySQL/MariaDB server exists in this sandbox);
  LDAP/PAM stay stubs too; the SQLite backend is single-file (no clustering of
  the auth store itself — a cluster still shares accounts through
  Mnesia, see Fase 7); Mnesia has a pre-existing persistence
  quirk worth knowing — a VM halted abruptly (e.g. `mix run -e`
  exiting) can lose the not-yet-flushed transaction log, so
  accounts created that way may vanish on the next boot, while a
  clean server stop (SIGTERM, which stops Mnesia properly) keeps
  them — the probe stops the server with SIGTERM for exactly this
  reason. A second lesson from this phase: stopping the supervised
  SQLite server repeatedly trips the supervisor's restart
  intensity (3 restarts in 5 s) and takes the whole application
  down — so the backend exposes `close/0` (release the
  connection, reopen lazily) instead of being stopped.

## Not implemented

Honest list — these were claimed by the old code/config and are not
there. Do not rely on them until they land. The full per-area table
with the counting method is in [`docs/PARITY.md`](docs/PARITY.md)
(34 verified / 9 partial / 21 not, ≈60% of the 64-item checklist).

* **HTTP stack (remaining)**: no TLS HTTP listener (5443), no
  captcha endpoint, no ACME challenge handling, no HTTP/2.
  Admin has no MUC/PubSub management pages; upload has no per-user
  quota and no virus scanning; BOSH `hold` is fixed at 1 and only
  the last 5 responses are kept for `rid` replay; Stream Management
  `<resume/>` across BOSH/WebSocket connections is refused.
* **MIX** (XEP-0369): core implemented and wire-verified since
  Fase 14 (channels, stable participant JIDs, participants node,
  message reflection); the presence/info PubSub nodes, MIX-MAM and
  PAM (XEP-0405) are not implemented.
* **PubSub (edges)**: `presence` / `roster` access models behave
  like `open` for local users. (Collections and the `authorize`
  approval flow are implemented and wire-verified since Fase 13;
  MUC administration since Fase 12.)
* **Auth backends other than Mnesia, SQLite, SQL/PostgreSQL, JWT,
  OAuth and external** (MySQL, LDAP, PAM): stubs that return
  `false` / `not_implemented` — no MySQL or LDAP server exists in
  this sandbox to verify against, and PAM cannot be exercised
  meaningfully here. (`anonymous` works as before, but was
  not re-probed in Fase 1–9; SQLite is real since Fase 8 and
  SQL/PostgreSQL, JWT, OAuth and external since Fase 16, see above.)
* ~~**Roster subscription requests**~~ — implemented in Fase 11
  (full RFC 6121 state machine, wire-verified).
  ~~`starttls_required`~~ — likewise real since Fase 11: a per-host
  config option that withholds SASL mechanisms on plaintext and
  rejects plaintext auth with `policy-violation`.
* **S2S (edges)**: no SASL EXTERNAL, no bidirectional streams
  (XEP-0288); TLS peer verification is off (`verify_none`,
  self-signed dev certificate); the dialback verify connection is
  plain TCP; multi-host sender selection is not done.
* **Jingle / media**: signaling only — no media processing, no
  DTLS/SRTP; federated Jingle is routed but the session is only
  tracked on the node that saw the initiate.
* **STUN/TURN live UDP proof**: TURN over TCP is verified live (2/2),
  but the sandbox blocks UDP `sendto` with EPERM, so the live UDP
  STUN/TURN wire checks could not run there — the logic is covered
  in-process only. Run `test_stun_turn_phase5.py` where UDP is
  allowed for the full proof. TURN has no per-user quota beyond the
  global `max_allocations`.
* **OMEMO generations `:1` / `:2`**: only the legacy generation is
  implemented and advertised.
* **MQTT 5.0**: the broker speaks MQTT v3.1.1 only.
* **Clustering (edges)**: MUC rooms, vCards, Stream Management
  resume state and per-host ETS caches stay node-local; two nodes
  with independent Mnesia schemas cannot merge live; a user bound
  with the same resource on two nodes is last-registration-wins.
* **Long-tail modules**: vCard, private XML storage, privacy lists /
  blocking, last activity, ad-hoc commands, SOCKS5 bytestreams
  (proxy65), Push, shared roster, avatars, caps, announce and the
  rest exist as partial implementations that load at boot — none of
  them is verified over the wire. "39 modules start at boot" means
  they load, not that they work.

## Layout

* `lib/exjabberd/cluster/cluster.ex` — Fase 7 clustering: node
  auto-connect + monitor, session/route ETS mirrors, state sync,
  node-down purge + unavailable presence, Mnesia join, cookie
  handling, `status/0`; `lib/exjabberd/mnesia.ex` —
  `setup_cluster_join/1` (extra_db_nodes schema copy) +
  `cluster_tables/0`.
* `boot_cluster_nodes.sh` — boots two cluster nodes from working
  copies in /tmp for `test_cluster_phase7.py` (22/22 live checks).
* `lib/exjabberd/listener/c2s_listener.ex` — TCP accept loop, stream
  parser, SASL, STARTTLS, IQ dispatch.
* `lib/exjabberd/listener/s2s_listener.ex` — inbound S2S accept loop,
  server streams, STARTTLS, dialback receive/verify, stanza gate.
* `lib/exjabberd/core/s2s.ex` — S2S manager + outbound connection
  (connect, STARTTLS, dialback, queue, bounce on failure).
* `lib/exjabberd/core/s2s_dialback.ex` — XEP-0220 key generation /
  verification + the dialback verify connection.
* `lib/exjabberd/xmpp/stream_parser.ex` — incremental stanza splitter.
* `lib/exjabberd/auth/scram.ex` — SCRAM-SHA-256 (RFC 5802).
* `lib/exjabberd/auth/sqlite.ex` — Fase 8 SQLite auth backend
  (Exqlite, same SCRAM verifier format as Mnesia, BLOB columns,
  serialized GenServer connection, lazy open from config);
  `lib/exjabberd/auth/migrate.ex` + `mix exjabberd.auth.migrate`
  — verbatim-verifier migration between backends;
  `test/exjabberd/auth/sqlite_test.exs` — backend + migration
  unit tests; `test_auth_sqlite_phase8.py` — live probe (slixmpp
  PLAIN + SCRAM, restart persistence, migration).
* `lib/exjabberd/tls.ex` — self-signed dev certificate.
* `lib/exjabberd/mod/offline.ex` — offline message store.
* `lib/exjabberd/mod/stream_mgmt.ex` — XEP-0198 registry + config.
* `lib/exjabberd/mod/carbons.ex` — XEP-0280 message carbons.
* `lib/exjabberd/mod/csi.ex` — XEP-0352 policy + config.
* `lib/exjabberd/http/server.ex` — plain-`:gen_tcp` HTTP listener
  + request parser + router (admin / API / BOSH / upload).
* `lib/exjabberd/http/xmpp_transport.ex` — one XMPP session over
  BOSH/WebSocket (stream, SASL, bind, SM, CSI, IQ dispatch).
* `lib/exjabberd/http/bosh.ex` — BOSH sessions (long-poll, rid
  replay, inactivity) + `lib/exjabberd/http/websocket.ex` —
  RFC 6455 framing + RFC 7395.
* `lib/exjabberd/http/upload.ex` — XEP-0363 slot store, HMAC-signed
  URLs, file storage + expiry sweep; `lib/exjabberd/http/admin.ex`
  — web admin UI + signed session cookies;
  `lib/exjabberd/http/api.ex` — REST API;
  `lib/exjabberd/http/config.ex` — the `http:` config section.
* `lib/exjabberd/core/c2s.ex` — now also supports non-TCP
  transports via `out_pid` (`set_out_pid/2`, `sync/1`).
* `lib/exjabberd/mod/mam.ex` — XEP-0313 archive store (Mnesia),
  prefs, archiving hooks.
* `lib/exjabberd/mod/mam_query.ex` — XEP-0313 IQ handler
  (query with `with`/`start`/`end` + RSM, prefs get/set, MUC query).
* `lib/exjabberd/mod/pubsub.ex` — XEP-0060 PubSub service
  (Mnesia-backed nodes/items/subs/affs, IQ + owner handlers, disco)
  plus PEP namespacing (nodes under the owner's bare JID),
  auto-create on first publish, and publish-options.
* `lib/exjabberd/stun_turn.ex` — STUN/TURN codec (RFC 5389/5766):
  encode/decode, XOR addresses, MESSAGE-INTEGRITY, FINGERPRINT,
  long-term keys, stateless nonces, ChannelData framing.
* `lib/exjabberd/stun_turn/server.ex` — STUN/TURN server (UDP 5478
  + TCP): auth, allocations registry, TCP accept loop.
* `lib/exjabberd/stun_turn/allocation.ex` — one TURN allocation:
  relay UDP socket, permissions (300 s), channels (600 s), expiry.
* `lib/exjabberd/stun_turn/tcp_connection.ex` — one TURN-over-TCP
  connection (RFC 5766 §7.2 framing, dies with its allocations).
* `lib/exjabberd/mod/jingle.ex` — XEP-0166 signaling-only session
  tracking + XEP-0215 extdisco (STUN/TURN services + credentials).
* `lib/exjabberd/mod/omemo.ex` — XEP-0384 legacy OMEMO nodes over
  PEP (devicelist + per-device bundles, open/open, max_items 1).
* `lib/exjabberd/mqtt/codec.ex` — MQTT v3.1.1 packet codec
  (fixed header, Remaining Length, all 14 packet types, topic
  validation + `+`/`#` matching).
* `lib/exjabberd/mqtt/broker.ex` — MQTT broker core: subscriptions,
  retained messages, clean/persistent sessions, QoS 1/2 flows,
  offline queueing, session takeover.
* `lib/exjabberd/mqtt/connection.ex` — one MQTT client connection
  (CONNECT auth against `Exjabberd.Auth`, keep-alive, Will).
* `lib/exjabberd/mqtt/bridge.ex` — MQTT ↔ XMPP PubSub bridge
  (topic = node name, both directions, loop protection).
* `lib/exjabberd/mqtt.ex` — `mqtt:` config accessors.
* `lib/exjabberd/listener/mqtt_listener.ex` — TCP accept loop for
  the MQTT broker (port 1883, `listen:` module `exjabberd_mqtt`).
* `test/exjabberd/mqtt_test.exs` — codec + broker unit tests;
  `test_mqtt_phase6.py` — live probe (paho-mqtt + raw frames +
  slixmpp bridge).
* `test/exjabberd/stun_turn_test.exs` — codec unit tests;
  `test/exjabberd/jingle_omemo_test.exs` — live Jingle / OMEMO /
  STUN / TURN integration tests (raw sockets + raw UDP/TCP);
  `test_jingle_phase5.py` / `test_stun_turn_phase5.py` — the same
  flows as repeatable raw-socket probes.
* `lib/exjabberd/mnesia.ex` — Mnesia setup (schema + disc_copies).
* `test/` — unit + live C2S integration tests.
* `verify.sh` — Fase 9: one-command full verification (compile +
  `mix test` + single-node probes + SQLite probe + S2S probes +
  cluster probe, 19 steps, all green 2026-11-11 from a fresh clone); logs in
  `/tmp/exjabberd-verify-logs/`.
* `boot_s2s_nodes.sh` — Fase 9: boots the two S2S nodes for
  `test_s2s.py` / `test_s2s_slix.py` (a.localhost ↔ b.localhost,
  test dialback secrets, host overrides), modeled on
  `boot_cluster_nodes.sh`.
* `docs/PARITY.md` — Fase 9: honest parity assessment (64-item
  checklist, 34 verified / 9 partial / 21 not, ≈60%) with the
  evidence table and the counting method.
* `.formatter.exs` — Fase 9: `mix format` config (files changed in
  Fase 9 are format-clean; the older tree predates it and is not
  reformatted in one sweep).
