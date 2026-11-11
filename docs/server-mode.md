# Server mode (mutual TLS)

By default `cofferakd` only listens on a local Unix socket - the fastest
and smallest-attack-surface option when every client is on the same
host. **Server mode** is the opt-in path for when a client genuinely
isn't: set `$COFFERAK_TLS_ADDR` (e.g. `0.0.0.0:8443`) and the daemon also
listens on TLS-wrapped TCP, serving the *exact same* `Request`/`Response`
protocol and the *exact same* per-service access tokens - not a second
API to learn, not a second thing to keep in sync. See
[ADR 0008](adr/0008-server-mode-rpc-over-tls.md) for why this (RPC
over TLS) was chosen over REST or WebSocket.

Don't have certificates yet? One command makes a private P-384 CA, a
server certificate and client certificates. Name each client certificate
after the service it belongs to (the id you gave `enroll-service`): the
daemon accepts a token only together with its own service's certificate.

```bash
./scripts/gen-certs.sh ./tls cofferak.internal app1 app2   # for services app1 and app2
```

```bash
# Server side: turn on TLS alongside the existing Unix socket. All four
# TLS variables are required: mutual TLS is mandatory.
COFFERAK_DATA_DIR=./data \
COFFERAK_TLS_ADDR=0.0.0.0:8443 \
COFFERAK_TLS_CERT=./tls/server.pem \
COFFERAK_TLS_KEY=./tls/server.key \
COFFERAK_TLS_CLIENT_CA=./tls/ca.pem \
  cofferak daemon     # cofferakd on a Linux systemd install
```

| Variable | Purpose |
|---|---|
| `COFFERAK_TLS_ADDR` | `host:port` to listen on. Unset = server mode is off (Unix socket only). |
| `COFFERAK_TLS_CERT` / `COFFERAK_TLS_KEY` | Server certificate + private key (PEM). Required once `COFFERAK_TLS_ADDR` is set. |
| `COFFERAK_TLS_CLIENT_CA` | **Required.** CA (PEM) that signs every client certificate. The daemon refuses to start server mode without it. |
| `COFFERAK_TLS_MAX_CONNECTIONS` | Optional. Maximum concurrent TLS connections (default `256`), connections beyond it are closed immediately. |
| `COFFERAK_TLS_CRL` | Optional. PEM revocation lists (comma separated): revoked client certificates are refused. |
| `COFFERAK_TLS_BIND_SERVICE` | Optional, default `1`: a token works only with a client certificate whose CN or DNS SAN is that token's service id. `0` turns it off. |

The transport is locked to the strongest settings every SDK supports
([ADR 0011](adr/0011-cnsa-grade-crypto-and-hardened-transport.md)):

- **TLS 1.3 only** - the newest TLS version; 1.2 and older are refused.
- **One cipher suite:** `TLS_AES_256_GCM_SHA384`. AES-128 is refused.
- **Key exchange:** post-quantum `ML-KEM-1024` first (CNSA 2.0), then
  the `X25519MLKEM768` hybrid that Go and newer OpenSSL clients offer,
  then classical `P-384` for TLS libraries with no post-quantum support
  yet.
- **Mutual TLS, always:** no client certificate from your CA, no
  connection. The per-service token is still checked on every request,
  and it must match the certificate's service, so a leaked token alone,
  or a certificate alone, gets nothing. Revoked certificates are refused
  when you give a CRL.
- Bounded request/response lines, a 30-second per-connection timeout,
  and a concurrent-connection cap. There is no per-client rate limit
  yet, for an internet-facing deployment keep a firewall or a
  per-IP-limiting proxy in front.

All four SDKs support this transport: Rust (`rustls` + AWS-LC), Go
(`crypto/tls`), Python (`ssl`), TypeScript/JavaScript (`node:tls`), see
each SDK's page under [`docs/sample-integration/`](sample-integration/README.md).
Every claim above is tested on every commit by:

```bash
./scripts/server-mode-smoke.sh
```

It proves that server mode won't start without a client CA, that every
SDK is rejected without a client certificate, with one from an untrusted
CA, or with the wrong hostname, that TLS 1.2 and AES-128 clients are
refused, and that the Rust SDK negotiates
`TLSv1_3 TLS13_AES_256_GCM_SHA384 MLKEM1024`.
