# Development

## Repository layout

```
cofferak/
  cofferak-core/   # lib: crypto, on-disk format, ACL, HostSeal - no process I/O beyond disk reads/writes
  cofferakd/       # daemon: Unix socket + TLS server mode, platform seal integration, audit log
  cofferak-cli/    # admin CLI: init/enroll-host/enroll-service/set/get/rm/list/rotate-dek/recover/audit tail
  sdk/             # client SDKs: rust, go, python, javascript (TypeScript)
  deployment/      # copy-and-edit systemd unit (Linux) and launchd plist (macOS)
  scripts/         # quickstart-check, sdk-smoke, server-mode-smoke, bench, gen-certs
  docs/            # SPEC.md, adr/, PROGRESS.md, deployment guide, recovery runbook,
                   # sample-integration/, assets/ (logo and icons)
  SDD.md           # the design/documentation practice this repo follows
```

## What's implemented

- **Envelope crypto** (`cofferak-core::crypto`, on AWS-LC):
  hardware-accelerated AES-256-GCM-SIV for entries, tokens and per-host
  DEK wraps, each bound to its context, a hybrid X25519 + ML-KEM-1024
  recovery wrap with HKDF-SHA-384, an armored, checksummed root private
  key, zeroize-on-drop key handling.
- **On-disk format** (`cofferak-core::format`): the `vault.cofferak` binary
  file and its `meta.json` sidecar, with corrupt/truncated input returned
  as a typed error rather than a panic or a silently fresh vault.
- **Path-prefix ACL** (`cofferak-core::acl`): per-service access tokens
  scoped to path prefixes and a permission level, with a traversal-safe
  prefix check.
- **`HostSeal` trait + both backends** (`cofferak-core::seal`): the one
  platform-dependent abstraction, with:
  - `SystemdCredsSeal` (Linux) - shells out to the real `systemd-creds`
    binary.
  - `KeychainSeal` (macOS) - stores/retrieves the key as a generic
    password in the Keychain via `security-framework`.

  Both map failures to the same `SealError::{Unavailable, Invalid, Io}`
  taxonomy, so callers (and tests) don't need to care which platform
  they're on.
- **`cofferakd`**: the daemon. Loads `vault.cofferak`, unseals its own host
  key, opens the append-only audit log, then serves `Get`/`Set`/`Rm`/`List`
  requests from service tokens over a Unix socket (newline-delimited
  JSON) and, in [server mode](server-mode.md), TLS/TCP too - the same
  protocol, same tokens, same `Daemon::handle_request` either way.
  Reads `COFFERAK_DATA_DIR` and `COFFERAK_SOCKET` at startup (falling back
  to a per-OS default - see [`docs/deployment.md`](deployment.md)),
  and refuses to start rather than silently creating an empty vault if
  `vault.cofferak` or the sealed host key is missing or unreadable.
- **Server mode** (`cofferakd::tls_server`): opt-in TLS/TCP listener
  alongside the Unix socket (`rustls` on AWS-LC): TLS 1.3 only,
  `TLS_AES_256_GCM_SHA384` only, ML-KEM-1024 key exchange preferred, and
  mandatory mutual TLS. See [Server mode](server-mode.md), ADR
  [0008](adr/0008-server-mode-rpc-over-tls.md) and
  [0011](adr/0011-cnsa-grade-crypto-and-hardened-transport.md).
- **`cofferak-cli`** (binary name `cofferak`): the admin CLI (see
  [Commands](commands.md) below) -
  vault/host bootstrap, service enrollment, `set`/`get`/`rm`/`list` over
  the daemon socket, DEK rotation, disaster recovery, and audit log
  inspection.
- **Deployment templates** (`deployment/`): a systemd unit for Linux and a
  launchd plist for macOS, documented end to end in
  [`docs/deployment.md`](deployment.md).
- **Audit log** (`cofferakd::audit`): an append-only JSON-lines log of
  every service request (`<ts> <service_id> <action> <path> <result>`),
  readable offline via `cofferak audit tail`.

## Building and testing

```bash
cargo build --workspace
cargo test --workspace
```

`cofferak-core`'s test suite includes real integration tests against the
platform's actual sealing facility - `tests/seal_linux.rs` (skips with a
clear message if `systemd-creds` isn't on `PATH`, e.g. off Linux) and
`tests/seal_macos.rs` (runs for real against a uniquely-named,
test-scoped Keychain item on macOS, and cleans it up afterward).

End-to-end scripts (all run in CI on Linux and macOS):

```bash
./scripts/quickstart-check.sh     # the Quickstart above, run as written
./scripts/sdk-smoke.sh            # real CLI + daemon + sealing, all four SDKs, restart durability
./scripts/server-mode-smoke.sh    # mutual TLS accept/reject in all four SDKs, downgrade refusals
./scripts/bench.sh                # performance numbers (docs/benchmarks.md)
./scripts/gen-certs.sh DIR NAME [CLIENT...]   # helper: P-384 CA, server and client certs (REUSE_CA=1 to add certs from an existing CA)
```

## Contributing

See [CONTRIBUTING.md](https://github.com/arkrwn/cofferak/blob/main/CONTRIBUTING.md). Contributions require accepting
the project's CLA ([CLA.md](https://github.com/arkrwn/cofferak/blob/main/CLA.md)) on your first pull request.

## Documentation site

The pages under `docs/` are built into a site with MkDocs Material:

```bash
pip install -r docs/requirements.txt
mkdocs serve                 # http://127.0.0.1:8000, reloads on save
mkdocs build --strict        # what CI runs: fails on any broken link
```

Design practice for contributors is in
[SDD.md](https://github.com/arkrwn/cofferak/blob/main/SDD.md).
