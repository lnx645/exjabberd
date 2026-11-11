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
`config/exjabberd.yml` enables it, **5223** (direct TLS C2S).
The TLS certificate is self-signed for `localhost`, generated on first
use into `priv/ssl/` (gitignored). Production deployments must use a
real certificate for the server domain instead.

Configuration lives in `config/exjabberd.yml` (hosts, `listen:`, `modules:`).
Only listeners and modules that are actually implemented are listed
there; the file documents what is missing in commented blocks.

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
`test/exjabberd/sm_carbons_csi_test.exs`) that speak real XMPP
over a raw socket: login, roster, disco, ping, time, version,
presence, 1-1 messages, MUC, offline messages, in-band registration,
malformed/oversized stanzas, STARTTLS and SCRAM-SHA-256, plus
stream-management ack/resume, message carbons and CSI queue/flush.
`test_sm_carbons_csi.py` at the repo root is the repeatable
raw-socket probe for the same three features against a running
dev server.

## Verified features

Verified over the wire with real clients (raw sockets + slixmpp 1.17)
on 2026-11-11 — raw harness 18/18, slixmpp harness 10/10,
`mix test` 34/34, probe `test_sm_carbons_csi.py` 36/36:

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
* 38 modules start at boot from `modules:` in `exjabberd.yml`
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

## Not implemented

Honest list — these were claimed by the old code/config and are not
there. Do not rely on them until they land:

* **S2S / federation** (port 5269): no S2S listener; `S2S` module is a
  stub. Messages to remote domains are queued and dropped.
* **HTTP stack**: no web admin (5280), no BOSH (XEP-0206), no
  WebSocket, no file upload (XEP-0363), no HTTP API. No
  Plug/Cowboy/Bandit/Phoenix dependency.
* **STUN/TURN** (5478), **MQTT** (1883).
* **MAM, PubSub, Jingle, OMEMO, MIX, PEP**: modules exist as partial
  implementations or stubs; none verified over the wire.
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
* `lib/exjabberd/xmpp/stream_parser.ex` — incremental stanza splitter.
* `lib/exjabberd/auth/scram.ex` — SCRAM-SHA-256 (RFC 5802).
* `lib/exjabberd/tls.ex` — self-signed dev certificate.
* `lib/exjabberd/mod/offline.ex` — offline message store.
* `lib/exjabberd/mod/stream_mgmt.ex` — XEP-0198 registry + config.
* `lib/exjabberd/mod/carbons.ex` — XEP-0280 message carbons.
* `lib/exjabberd/mod/csi.ex` — XEP-0352 policy + config.
* `lib/exjabberd/mnesia.ex` — Mnesia setup (schema + disc_copies).
* `test/` — unit + live C2S integration tests.
