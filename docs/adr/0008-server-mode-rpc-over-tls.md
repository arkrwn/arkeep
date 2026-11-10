# ADR 0008: Server mode is RPC over TLS, reusing the existing wire protocol

Status: accepted

cofferak needed a way to run on a server and be called remotely, not only
over a local Unix socket. Three shapes were on the table: a REST/HTTP
API, WebSocket, or RPC (a custom protocol over an encrypted transport).

**Decision: RPC — the existing newline-delimited JSON `Request`/
`Response` protocol (`docs/SPEC.md` §6), unchanged, now also reachable
over TLS-wrapped TCP (`$COFFERAK_TLS_ADDR`) in addition to the Unix
socket, both served by the same `cofferakd` process from the same
`Daemon`.**

Why this over REST/WebSocket:

- **Fastest.** No HTTP request/response framing, no header parsing, no
  WebSocket handshake/upgrade — one TLS handshake per connection, then
  the same compact JSON lines the Unix socket already uses. Measurably
  less per-request overhead than an HTTP round trip for a protocol this
  small (four request shapes, six response shapes).
- **Safest, in the sense of smallest new attack surface.** Reusing the
  protocol means zero new parsing/ACL logic — `Daemon::handle_request`
  is exactly the same code path for a local Unix-socket client and a
  remote TLS client. The only new code is the TLS listener itself.
  Building a REST API or WebSocket server instead would mean pulling in
  a full HTTP server framework (and, for WebSocket, a websocket crate on
  top of that) — real new dependency surface and real new code to
  secure, for a protocol cofferak already has working and tested.
- **TLS via `rustls`**, not OpenSSL. Pure Rust, no C FFI, no system
  OpenSSL version to track — consistent with this project's general
  preference for memory-safe, dependency-light implementations (ADR
  0003's "no external vault/KMS dependency" reasoning extends naturally
  to "no C TLS library dependency" here).
- **Mutual TLS is supported, not required.** `$COFFERAK_TLS_CLIENT_CA`
  turns on client certificate verification for operators who want
  transport-level mutual authentication in addition to the existing
  per-service access token (ADR 0001's capability model). Token auth at
  the application layer is unconditional either way — TLS adds
  transport confidentiality/integrity (and optionally mTLS), it is not
  a substitute for the token check.

Rejected: REST (HTTP semantics — verbs, status codes, content
negotiation — add nothing a four-request-shape protocol needs, and cost
a whole HTTP server dependency); WebSocket (solves a full-duplex
streaming problem cofferak doesn't have — every request here already gets
exactly one response, there's no server-push use case yet).

**What this does not change:** the Unix socket path is untouched and
remains the default/primary transport for same-host services (still
faster than any network transport, no TLS handshake, OS-enforced file
permissions). TLS/TCP is additive, opt-in via `$COFFERAK_TLS_ADDR`, for
when a service genuinely isn't on the same host.

**Update:** all four SDKs now speak TLS/TCP (Rust `rustls`, Go
`crypto/tls`, Python `ssl`, TypeScript/JavaScript `node:tls` — every one
a language standard library, no third-party TLS dependency added
anywhere). Each went through the same adversarial battery in
`scripts/server-mode-smoke.sh`: happy-path round trip, wrong-hostname
rejection, mTLS no-client-cert rejection, mTLS rogue-CA-signed-cert
rejection, mTLS correct-cert acceptance. See `docs/PROGRESS.md`.

## Security hardening applied (and what's intentionally not done yet)

Reviewed and fixed before this reached `main`:

- **TLS 1.3-only.** `tls12` is deliberately not enabled — both ends of
  this protocol are cofferak's own code, so there's no legacy-client
  compatibility reason to allow the weaker, older protocol version.
- **Bounded request/response lines** (`protocol::read_line_bounded`,
  `MAX_LINE_BYTES` = 16 MiB on the daemon side, and the same cap
  independently reimplemented by every SDK for its own response
  reading). The daemon previously used `read_until` with no cap on
  *every* transport, including the now-network-reachable TLS listener —
  a client that never sends `\n` would otherwise grow the read buffer
  without limit (memory-exhaustion DoS). A hostile/compromised daemon
  could do the same thing back to a client, so every SDK's own read
  path is bounded too, not just the daemon's.
- **Per-connection I/O timeout (30s)** on the TLS listener and every
  SDK's TLS client — a stalled/slow connection is dropped rather than
  parking a thread/goroutine/event-loop callback forever (mitigates,
  not eliminates, a slowloris-style attack — see the limitation below).
- **No public-root fallback, in any SDK.** Every TLS client trusts
  *only* the CA path it's given — Rust's `RootCertStore::empty()` before
  adding just that CA, Go's fresh `x509.NewCertPool()` (never
  `SystemCertPool()`), Python's `SSLContext` with `load_default_certs()`
  never called, Node's `ca` option (which replaces, not adds to, the
  bundled public root store). cofferak's TLS is for a self-managed
  deployment; falling back to a public trust store would let any
  public-CA-issued certificate impersonate the server.
- **Verified, not assumed, by `scripts/server-mode-smoke.sh`, for every
  SDK:** server cert validated against the configured CA; a wrong
  expected server name is rejected (MITM-with-a-different-cert
  defense); mTLS rejects both *no* client cert and a client cert signed
  by a *different, untrusted* CA, and accepts only a cert signed by the
  configured one.

**Known, disclosed limitation — not fixed here:** there is no
connection-count or rate limit on the TLS listener. The 30-second
timeout bounds how long any *one* connection can hold a thread, but an
attacker opening many connections in parallel can still exhaust threads
for that duration. For an internet-facing deployment, put a reverse
proxy or load balancer with connection/rate limiting in front of
`$COFFERAK_TLS_ADDR` rather than exposing it directly; a connection
semaphore inside `cofferakd` itself is a reasonable future improvement,
tracked in `docs/PROGRESS.md`, not implemented yet.
