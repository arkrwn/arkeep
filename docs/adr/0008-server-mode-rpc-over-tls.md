# ADR 0008: Server mode is RPC over TLS, reusing the existing wire protocol

Status: accepted

mikavt needed a way to run on a server and be called remotely, not only
over a local Unix socket. Three shapes were on the table: a REST/HTTP
API, WebSocket, or RPC (a custom protocol over an encrypted transport).

**Decision: RPC — the existing newline-delimited JSON `Request`/
`Response` protocol (`docs/SPEC.md` §6), unchanged, now also reachable
over TLS-wrapped TCP (`$MIKAVT_TLS_ADDR`) in addition to the Unix
socket, both served by the same `mikavtd` process from the same
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
  secure, for a protocol mikavt already has working and tested.
- **TLS via `rustls`**, not OpenSSL. Pure Rust, no C FFI, no system
  OpenSSL version to track — consistent with this project's general
  preference for memory-safe, dependency-light implementations (ADR
  0003's "no external vault/KMS dependency" reasoning extends naturally
  to "no C TLS library dependency" here).
- **Mutual TLS is supported, not required.** `$MIKAVT_TLS_CLIENT_CA`
  turns on client certificate verification for operators who want
  transport-level mutual authentication in addition to the existing
  per-service access token (ADR 0001's capability model). Token auth at
  the application layer is unconditional either way — TLS adds
  transport confidentiality/integrity (and optionally mTLS), it is not
  a substitute for the token check.

Rejected: REST (HTTP semantics — verbs, status codes, content
negotiation — add nothing a four-request-shape protocol needs, and cost
a whole HTTP server dependency); WebSocket (solves a full-duplex
streaming problem mikavt doesn't have — every request here already gets
exactly one response, there's no server-push use case yet).

**What this does not change:** the Unix socket path is untouched and
remains the default/primary transport for same-host services (still
faster than any network transport, no TLS handshake, OS-enforced file
permissions). TLS/TCP is additive, opt-in via `$MIKAVT_TLS_ADDR`, for
when a service genuinely isn't on the same host.

**Follow-up, not yet done:** only the Rust SDK speaks TLS/TCP today
(`Client::connect_tls`); the Go/Python/TypeScript SDKs are still
Unix-socket-only. Extending each to the network transport is tracked in
`docs/PROGRESS.md`, following the same ADR 0005 rule (real smoke test
before claiming it works).
