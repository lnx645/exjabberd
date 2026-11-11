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
`exjabberd.yml` enables it, **5223** (direct TLS C2S).
The TLS certificate is self-signed for `localhost`, generated on first
use into `priv/ssl/` (gitignored). Production deployments must use a
real certificate for the server domain instead.

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

```sh
# Stop any dev server first: the suite boots the app on port 5222.
ELIXIR_ERL_OPTIONS="+fnu -sname exjabberd-test" mix test
```

The suite has unit tests (`StreamParser`, `Scram`, carbons
eligibility, CSI policy) and live C2S integration tests
(`test/exjabberd/live_c2s_test.exs`,
`test/exjabberd/sm_carbons_csi_test.exs`,
`test/exjabberd/mam_pubsub_test.exs`) that speak real XMPP
over a raw socket: login, roster, disco, ping, time, version,
presence, 1-1 messages, MUC, offline messages, in-band registration,
malformed/oversized stanzas, STARTTLS and SCRAM-SHA-256, plus
stream-management ack/resume, message carbons and CSI queue/flush,
MAM archive/query/prefs and PubSub node lifecycle.
`test_sm_carbons_csi.py` at the repo root is the repeatable
raw-socket probe for the same three features against a running
dev server; `test_mam_pubsub.py` (raw sockets) and
`test_mam_pubsub_slix.py` (slixmpp 1.17, plugins `xep_0313` and
`xep_0060`) are the repeatable probes for MAM and PubSub.

## Verified features

Verified over the wire with real clients (raw sockets + slixmpp 1.17)
on 2026-11-11 — raw harness 18/18, slixmpp harness 10/10,
`mix test` 42/42, probe `test_sm_carbons_csi.py` 36/36,
probe `test_mam_pubsub.py` 47/47, probe
`test_mam_pubsub_slix.py` 12/12:

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
  collection nodes are rejected (`bad-request`); `access_model`
  `authorize` records subscriptions as `pending` but owner approval
  is not implemented; `presence` / `roster` access models behave
  like `open` for local users; MUC MAM queries do not check room
  membership (rooms here have no membership enforcement either);
  two messages archived within the same millisecond from two
  different sessions have no defined cross-process order (the same
  race exists in ejabberd's send/receive hooks) — the probes space
  sends out to keep the expected order deterministic.

## Not implemented

Honest list — these were claimed by the old code/config and are not
there. Do not rely on them until they land:

* **HTTP stack**: no web admin (5280), no BOSH (XEP-0206), no
  WebSocket, no file upload (XEP-0363), no HTTP API. No
  Plug/Cowboy/Bandit/Phoenix dependency.
* **STUN/TURN** (5478), **MQTT** (1883).
* **MAM, PubSub, Jingle, OMEMO, MIX, PEP**: MAM and PubSub are
  implemented and verified (see above). Jingle, OMEMO, MIX and PEP
  modules exist as partial implementations or stubs; none verified
  over the wire.
* **Clustering**: single node only.
* **Auth backends other than Mnesia** (SQL, LDAP, JWT, anonymous,
  OAuth, external, PAM): stubs that return `false` / `not_implemented`.
* **Roster subscription requests** (subscribe/subscribed flows):
  presence is broadcast to all local sessions for now.
* `starttls_required`: STARTTLS is offered but optional; PLAIN/SCRAM
  also work without TLS.

## Layout

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
* `lib/exjabberd/tls.ex` — self-signed dev certificate.
* `lib/exjabberd/mod/offline.ex` — offline message store.
* `lib/exjabberd/mod/stream_mgmt.ex` — XEP-0198 registry + config.
* `lib/exjabberd/mod/carbons.ex` — XEP-0280 message carbons.
* `lib/exjabberd/mod/csi.ex` — XEP-0352 policy + config.
* `lib/exjabberd/mod/mam.ex` — XEP-0313 archive store (Mnesia),
  prefs, archiving hooks.
* `lib/exjabberd/mod/mam_query.ex` — XEP-0313 IQ handler
  (query with `with`/`start`/`end` + RSM, prefs get/set, MUC query).
* `lib/exjabberd/mod/pubsub.ex` — XEP-0060 PubSub service
  (Mnesia-backed nodes/items/subs/affs, IQ + owner handlers, disco).
* `lib/exjabberd/mnesia.ex` — Mnesia setup (schema + disc_copies).
* `test/` — unit + live C2S integration tests.
