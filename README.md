<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/arkeep-logo-dark.svg">
    <img src="docs/assets/arkeep-logo.svg" alt="arkeep" width="220">
  </picture>
</p>

<p align="center">
  <strong>A self-hosted secrets vault for Linux and macOS.</strong><br>
  Envelope encryption, OS-sealed keys, scoped per-service tokens — no external server, cloud KMS, or account.
</p>

<p align="center">
  <a href="https://github.com/arkrwn/arkeep/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/arkrwn/arkeep/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <img alt="Rust 1.89+" src="https://img.shields.io/badge/rust-1.89%2B-C95428.svg?logo=rust">
  <img alt="Platforms: Linux | macOS" src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-254434.svg">
  <img alt="TLS 1.3 only" src="https://img.shields.io/badge/server%20mode-TLS%201.3%20%2B%20mTLS-254434.svg">
  <img alt="SDKs: Rust, Go, Python, TypeScript" src="https://img.shields.io/badge/SDKs-Rust%20%7C%20Go%20%7C%20Python%20%7C%20TypeScript-C95428.svg">
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> ·
  <a href="#how-it-works-envelope-encryption-briefly">How it works</a> ·
  <a href="#server-mode">Server mode</a> ·
  <a href="#sdks">SDKs</a> ·
  <a href="docs/deployment.md">Deployment</a> ·
  <a href="docs/SPEC.md">Spec</a>
</p>

---

**arkeep** keeps application secrets (API keys, database passwords,
tokens) in a single encrypted file and serves them to your services
through a small daemon, `arkeepd`. The key that decrypts the vault is
sealed by the operating system itself — `systemd-creds` on Linux,
Keychain on macOS — so there is never a plaintext master key on disk.
Each service gets its own token, limited to the paths and permissions you
grant it.

By default `arkeepd` listens only on a local Unix socket. Turn on
**[server mode](#server-mode)** and it is also reachable over the
network through TLS 1.3, optionally with mutual TLS, using the same
protocol and the same tokens.

### Highlights

- **Envelope encryption** — AES-256-GCM-SIV data key, wrapped per host
  and once for an offline X25519 recovery key.
- **OS-sealed host keys** — the unseal key never sits next to the vault
  as a plain file; on Linux the daemon runs unprivileged and receives it
  from systemd.
- **Least-privilege tokens** — each service is scoped to path prefixes
  with read, write or read-write access.
- **Durable, crash-safe writes** — every acknowledged write is already on
  disk, written atomically under a lock.
- **Audit log** — every request, allowed or denied, is recorded.
- **Disaster recovery** — rebuild access on a new machine with the
  offline root key.
- **Client SDKs** — Rust, Go, Python and TypeScript/JavaScript, each
  tested against a real daemon in CI over the Unix socket and TLS/mTLS.

> **Status:** feature-complete and tested on every commit (Linux and
> macOS). See [`docs/PROGRESS.md`](docs/PROGRESS.md) for what is proven
> and the known limitations.

## Why

Most secrets-management setups either hand you a server to operate
(Vault, a cloud KMS) or a flat encrypted file with one shared passphrase.
arkeep is neither: it's an **envelope-encryption** vault where the key
that decrypts your secrets is itself sealed by the operating system's own
secure-storage primitive — `systemd-creds` on Linux, Keychain on macOS —
so the unseal key is never a plaintext file sitting next to the vault.

- **No external dependency.** No third-party server to run, no account
  to create, no call out to any third-party KMS. `arkeep` is the only
  server involved, and it's yours — local Unix socket by default, or
  your own TLS endpoint if you turn on server mode.
- **One codebase, two platforms.** `arkeep-core` (crypto, on-disk
  format, ACL) is entirely platform-agnostic; only the small `HostSeal`
  trait has a platform-specific implementation, so the same logic — and
  the same tests — run on both Linux and macOS.
- **Per-service, least-privilege access.** Consumers get a scoped
  capability token (path prefix + read/write), not a master key.

## How it works (envelope encryption, briefly)

- A **root keypair** (X25519) is generated once, offline. Its private
  half is exported once for the operator to store off-machine; it is
  never kept on any host running the daemon.
- A random 256-bit **DEK** (Data Encryption Key) encrypts the secrets
  store (AES-256-GCM-SIV). It is never stored unwrapped: it's wrapped
  once per enrolled host (under that host's sealed unseal key) and once
  under the root public key (for disaster recovery).
- Each enrolled **host** has its own random unseal key, sealed by the
  platform's `HostSeal` backend so it is only recoverable on that
  specific host, inside the daemon process.
- Each enrolled **service** gets an access token scoped to a set of path
  prefixes and a permission level (read / write / read-write) — never
  the DEK itself.

See [`docs/SPEC.md`](docs/SPEC.md) for the full design, including the
on-disk format, the daemon's request protocol, and the disaster-recovery
flow, and [`docs/adr/`](docs/adr/) for the point decisions behind it.

## Server mode

By default `arkeepd` only listens on a local Unix socket — the fastest
and smallest-attack-surface option when every client is on the same
host. **Server mode** is the opt-in path for when a client genuinely
isn't: set `$ARKEEP_TLS_ADDR` (e.g. `0.0.0.0:8443`) and the daemon also
listens on TLS-wrapped TCP, serving the *exact same* `Request`/`Response`
protocol and the *exact same* per-service access tokens — not a second
API to learn, not a second thing to keep in sync. See
[ADR 0008](docs/adr/0008-server-mode-rpc-over-tls.md) for why this (RPC
over TLS) was chosen over REST or WebSocket.

```bash
# Server side: turn on TLS alongside the existing Unix socket.
ARKEEP_DATA_DIR=./data \
ARKEEP_TLS_ADDR=0.0.0.0:8443 \
ARKEEP_TLS_CERT=./server.pem \
ARKEEP_TLS_KEY=./server.key \
  ./target/release/arkeepd &

# Optional: require a client certificate too (mutual TLS), on top of
# the service's access token — belt and suspenders, not a replacement.
# ARKEEP_TLS_CLIENT_CA=./ca.pem
```

| Variable | Purpose |
|---|---|
| `ARKEEP_TLS_ADDR` | `host:port` to listen on. Unset = server mode is off (Unix socket only). |
| `ARKEEP_TLS_CERT` / `ARKEEP_TLS_KEY` | Server certificate + private key (PEM). Required once `ARKEEP_TLS_ADDR` is set. |
| `ARKEEP_TLS_CLIENT_CA` | Optional. CA (PEM) to verify client certificates against — turns on mutual TLS. |
| `ARKEEP_TLS_MAX_CONNECTIONS` | Optional. Maximum concurrent TLS connections (default `256`); connections beyond it are closed immediately. |

TLS is pure-Rust (`rustls`, no OpenSSL/C dependency), **TLS 1.3-only**
(both ends are arkeep's own code, so there's no compatibility reason to
allow the older, weaker protocol version), with bounded request/response
lines and a 30-second per-connection timeout — see
[ADR 0008](docs/adr/0008-server-mode-rpc-over-tls.md)'s "Security
hardening applied" section. Concurrent connections are capped
(`ARKEEP_TLS_MAX_CONNECTIONS`); there is no per-client rate limit yet, so
for an internet-facing deployment keep a firewall or per-IP-limiting
proxy in front and prefer mTLS. **All four SDKs** support this transport
today, each using only its own language's standard-library TLS (no
third-party TLS dependency anywhere): Rust (`rustls`), Go
(`crypto/tls`), Python (`ssl`), TypeScript/JavaScript (`node:tls`) — see
each SDK's page under [`docs/sample-integration/`](docs/sample-integration/)
for its `connect_tls`/`ConnectTLS`/`connect_tls`/`connectTls` usage.
Proven for real, for every one of them — server-cert validation,
hostname-mismatch rejection, and mutual-TLS's reject/accept paths
(including a cert signed by a different, untrusted CA) — by:

```bash
./scripts/server-mode-smoke.sh
```

## Repository layout

```
arkeep/
  arkeep-core/   # lib: crypto, on-disk format, ACL, HostSeal — no process I/O beyond disk reads/writes
  arkeepd/       # daemon: Unix-socket API, platform seal integration, audit log
  arkeep-cli/    # admin CLI: init/enroll-host/enroll-service/set/get/rm/list/rotate-dek/recover/audit tail
  sdk/           # client SDKs: rust, go, python, javascript (TypeScript)
  deployment/    # copy-and-edit systemd unit (Linux) and launchd plist (macOS)
  scripts/       # sdk-smoke.sh, server-mode-smoke.sh — real, run-it-yourself proof
  docs/          # SPEC.md, adr/, PROGRESS.md, deployment guide, recovery
                 # runbook, sample-integration/
SDD.md             # the design/documentation practice this repo follows
```

## What's implemented

- **Envelope crypto** (`arkeep-core::crypto`): AES-256-GCM-SIV DEK
  wrap/unwrap per host, X25519 ECIES wrap/unwrap for the offline root key,
  AEAD entry encryption, zeroize-on-drop key handling.
- **On-disk format** (`arkeep-core::format`): the `vault.arkeep` binary
  file and its `meta.json` sidecar, with corrupt/truncated input returned
  as a typed error rather than a panic or a silently fresh vault.
- **Path-prefix ACL** (`arkeep-core::acl`): per-service access tokens
  scoped to path prefixes and a permission level, with a traversal-safe
  prefix check.
- **`HostSeal` trait + both backends** (`arkeep-core::seal`): the one
  platform-dependent abstraction, with:
  - `SystemdCredsSeal` (Linux) — shells out to the real `systemd-creds`
    binary.
  - `KeychainSeal` (macOS) — stores/retrieves the key as a generic
    password in the Keychain via `security-framework`.

  Both map failures to the same `SealError::{Unavailable, Invalid, Io}`
  taxonomy, so callers (and tests) don't need to care which platform
  they're on.
- **`arkeepd`**: the daemon. Loads `vault.arkeep`, unseals its own host
  key, opens the append-only audit log, then serves `Get`/`Set`/`Rm`/`List`
  requests from service tokens over a Unix socket (newline-delimited
  JSON) and, in [server mode](#server-mode), TLS/TCP too — the same
  protocol, same tokens, same `Daemon::handle_request` either way.
  Reads `ARKEEP_DATA_DIR` and `ARKEEP_SOCKET` at startup (falling back
  to a per-OS default — see [`docs/deployment.md`](docs/deployment.md)),
  and refuses to start rather than silently creating an empty vault if
  `vault.arkeep` or the sealed host key is missing or unreadable.
- **Server mode** (`arkeepd::tls_server`): opt-in TLS/TCP listener
  alongside the Unix socket, pure-Rust TLS (`rustls`), optional mutual
  TLS. See [Server mode](#server-mode) and
  [ADR 0008](docs/adr/0008-server-mode-rpc-over-tls.md).
- **`arkeep-cli`** (binary name `arkeep`): the admin CLI (see
  [Commands](#commands) below) —
  vault/host bootstrap, service enrollment, `set`/`get`/`rm`/`list` over
  the daemon socket, DEK rotation, disaster recovery, and audit log
  inspection.
- **Deployment templates** (`deployment/`): a systemd unit for Linux and a
  launchd plist for macOS, documented end to end in
  [`docs/deployment.md`](docs/deployment.md).
- **Audit log** (`arkeepd::audit`): an append-only JSON-lines log of
  every service request (`<ts> <service_id> <action> <path> <result>`),
  readable offline via `arkeep audit tail`.

## Quickstart

Requires a stable Rust toolchain (MSRV 1.89; CI uses the exact version
pinned in `rust-toolchain.toml`).

This quickstart runs everything as your own user, which works on macOS.
**On Linux, run the admin commands (`init`, `enroll-*`, `rotate-dek`,
`recover`) with `sudo`**: `systemd-creds`' host scope is root-only. For a
real Linux install — unprivileged daemon under systemd, host key delivered
via `LoadCredentialEncrypted=` — follow
[`docs/deployment.md`](docs/deployment.md) and
[ADR 0009](docs/adr/0009-linux-host-key-via-systemd-credentials.md).

```bash
# Build everything (library, daemon, CLI).
cargo build --workspace --release

# 1. Create a brand-new vault and its root keypair. The root private key
#    is printed to stdout exactly once — copy it offline (e.g. onto a
#    hardware token or a printed page) and never store it on a host that
#    runs the daemon. It is the only way to recover the vault if every
#    enrolled host is lost; see docs/key-security.md (how to actually
#    secure it) and docs/recovery-runbook.md (how to use it to recover).
./target/release/arkeep init --root --data-dir ./data

# 2. Enroll this host. This generates the vault's DEK, wraps it for the
#    root key and for this host, and seals this host's own unseal key
#    with the platform HostSeal backend (systemd-creds on Linux, Keychain
#    on macOS).
./target/release/arkeep init --host myhost --data-dir ./data

# 3. Start the daemon (foreground, for a quickstart — see
#    docs/deployment.md to run it as a systemd/launchd service instead).
ARKEEP_DATA_DIR=./data ARKEEP_SOCKET=./data/arkeepd.sock \
  ./target/release/arkeepd &

# 4. Enroll a consuming service, scoped to a path prefix. The printed
#    token is shown exactly once — hand it to the service's own config.
#    The daemon loads tokens at startup, so restart it afterwards.
./target/release/arkeep enroll-service myapp \
  --paths myapp --perm rw --data-dir ./data
kill %1; ARKEEP_DATA_DIR=./data ARKEEP_SOCKET=./data/arkeepd.sock \
  ./target/release/arkeepd &

# 5. Set and get a secret over the daemon's socket.
export ARKEEP_TOKEN=<token printed by step 4>
./target/release/arkeep set myapp/db-password 's3cr3t' \
  --socket ./data/arkeepd.sock
./target/release/arkeep get myapp/db-password \
  --socket ./data/arkeepd.sock
```

## Commands

All `arkeep-cli` subcommands accept `--data-dir <DIR>` (or
`$ARKEEP_DATA_DIR`), defaulting to the platform data directory
(`/var/lib/arkeep` on Linux, `~/Library/Application Support/arkeep`
on macOS). `set`/`get`/`rm`/`list` additionally accept `--socket <PATH>`
(or `$ARKEEP_SOCKET`) and a service token via `--token` (or
`$ARKEEP_TOKEN`).

| Command | Purpose |
|---------|---------|
| `init --root` | Create a brand-new vault and root X25519 keypair. Prints the root private key once. |
| `init --host <id>` | Enroll the *first* host into a vault created by `init --root`. |
| `enroll-host <new-id> --this-host <id>` | Enroll an *additional* host, using an already-enrolled host's own sealed key to recover the DEK. |
| `enroll-service <id> --paths <csv> --perm <ro\|rw>` | Enroll a consuming service and print its one-time access token. |
| `set <path> <value> --token <t>` | Write a secret (over the daemon socket). |
| `get <path> --token <t>` | Read a secret (over the daemon socket). |
| `rm <path> --token <t>` | Remove a secret (over the daemon socket). |
| `list [prefix] --token <t>` | List secret paths under a prefix (over the daemon socket). |
| `rotate-dek --hosts <csv>` | Generate a fresh DEK, re-encrypt every entry/token, and re-wrap it for the root key and the given hosts. Operates on `vault.arkeep` directly, not over the socket. Restart `arkeepd` afterwards: until then it refuses writes rather than using the stale DEK. |
| `recover --root-key <path> --new-host <id>` | Disaster recovery: enroll a new host using the offline root private key, bypassing every enrolled host's own sealed blob. See [`docs/recovery-runbook.md`](docs/recovery-runbook.md). |
| `audit tail [--count N]` | Print the last `N` (default 20) entries of the daemon's audit log, read directly from `<data_dir>/audit.jsonl`. |

`arkeepd` itself takes no CLI flags; it reads `ARKEEP_DATA_DIR` and
`ARKEEP_SOCKET` from the environment (same per-OS defaults as above),
`ARKEEP_HOST_ID` to pick which enrolled host's sealed key to use when the
vault has more than one (unneeded, and inferred automatically, when
there's exactly one), and `ARKEEP_TLS_*` to turn on [server
mode](#server-mode). See [`docs/deployment.md`](docs/deployment.md) for
running it as a systemd service (Linux) or a launchd agent (macOS),
including the `systemd-creds`/Keychain host-key sealing steps and socket
permissions.

## SDKs

A consuming service talks to `arkeepd` over its Unix socket — or, in
[server mode](#server-mode), TLS/mTLS over TCP — using the
newline-delimited JSON protocol in [`docs/SPEC.md`](docs/SPEC.md) §6.
Four client SDKs implement it today, **all four over both transports**
— each is smoke-tested for real against a running daemon in CI
(`scripts/sdk-smoke.sh` for the Unix socket, `scripts/server-mode-smoke.sh`
for TLS/mTLS including adversarial reject cases, both wired into
`.github/workflows/ci.yml`), not just documented:

| Language | Package | TLS library | Example |
|---|---|---|---|
| Rust | [`sdk/rust/arkeep-sdk`](sdk/rust/arkeep-sdk) | `rustls` | [`docs/sample-integration/rust.md`](docs/sample-integration/rust.md) |
| Go | [`sdk/go/arkeep`](sdk/go/arkeep) | `crypto/tls` (stdlib) | [`docs/sample-integration/go.md`](docs/sample-integration/go.md) |
| Python | [`sdk/python/arkeep_sdk`](sdk/python/arkeep_sdk) | `ssl` (stdlib) | [`docs/sample-integration/python.md`](docs/sample-integration/python.md) |
| TypeScript | [`sdk/javascript/arkeep-sdk`](sdk/javascript/arkeep-sdk) | `node:tls` (stdlib) | [`docs/sample-integration/typescript.md`](docs/sample-integration/typescript.md) |
| JavaScript | same package, compiled `dist/` | `node:tls` (stdlib) | [`docs/sample-integration/javascript.md`](docs/sample-integration/javascript.md) |

No third-party TLS library anywhere — every SDK uses its own language's
standard library for the TLS transport.

```python
# Python, the shortest example — same shape in every SDK above.
from arkeep_sdk import Client

client = Client("/run/arkeep/arkeepd.sock")
client.set("<token>", "myapp/DB_PASSWORD", b"s3cr3t")
value = client.get("<token>", "myapp/DB_PASSWORD")
```

None of these are published to a package registry yet — consume them via
a local path/relative reference (see each SDK's own page above) until
the wire protocol and SDK surface area are stable enough to commit to.
Planned next: C, C++, Perl, Ruby — see
[`docs/sample-integration/roadmap.md`](docs/sample-integration/roadmap.md).

## Building and testing

```bash
cargo build --workspace
cargo test --workspace
```

`arkeep-core`'s test suite includes real integration tests against the
platform's actual sealing facility — `tests/seal_linux.rs` (skips with a
clear message if `systemd-creds` isn't on `PATH`, e.g. off Linux) and
`tests/seal_macos.rs` (runs for real against a uniquely-named,
test-scoped Keychain item on macOS, and cleans it up afterward).

To additionally prove every SDK against a real running daemon:

```bash
./scripts/sdk-smoke.sh
```

And to prove server mode (TLS + mutual TLS) for real, including the
mTLS reject/accept paths:

```bash
./scripts/server-mode-smoke.sh
```

## Further reading

- [`docs/comparison.md`](docs/comparison.md) — how arkeep compares to
  `.env` files, HashiCorp Vault, Infisical, and AWS Secrets Manager,
  and honestly, when one of those is the better fit instead.
- [`docs/deployment.md`](docs/deployment.md) — running `arkeepd` as a
  systemd service or launchd agent, environment variables, socket
  permissions.
- [`docs/key-security.md`](docs/key-security.md) — how to actually
  secure the root private key `init --root` prints once: offline
  storage options, custody splitting, what never to do with it, and
  periodic recovery drills.
- [`docs/recovery-runbook.md`](docs/recovery-runbook.md) — disaster
  recovery with the offline root private key, for an operator who has
  never seen this project before.
- [`docs/sample-integration/`](docs/sample-integration/) — worked, CI-run
  examples: CLI/shell, and the Rust/Go/Python/TypeScript/JavaScript SDKs
  below.
- [`docs/SPEC.md`](docs/SPEC.md) — full design: on-disk format, the
  daemon's request protocol, and the disaster-recovery flow.
- [`docs/adr/`](docs/adr/) — numbered point decisions (why envelope
  encryption, why no external vault/KMS dependency, why the `HostSeal`
  abstraction, why `arkeepd` has a library target, why server mode is
  RPC-over-TLS rather than REST/WebSocket).
- [`docs/PROGRESS.md`](docs/PROGRESS.md) — implementation status, one row
  per area, each backed by what was actually run.
- [`SDD.md`](SDD.md) — the design/documentation practice this project
  follows; read it before making an architectural change.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions require accepting
the project's CLA ([CLA.md](CLA.md)) on your first pull request.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). The
`arkeep` name and logo are governed separately by the
[trademark policy](TRADEMARK.md): the license covers the code, not the
name.
