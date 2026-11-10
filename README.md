# cofferak

A small, dependency-free secrets vault for any service on Linux or macOS —
no HashiCorp Vault, no cloud KMS, no network service beyond a local Unix
socket. Clone it into a project as a `cofferak/` subdirectory, or run it
standalone.

> **Status: feature-complete.** The crypto/format/ACL core, both
> `HostSeal` backends, the daemon (`cofferakd`), the admin CLI
> (`cofferak-cli`), deployment templates, and an audit log are all
> implemented and tested. See [Commands](#commands) for the full CLI
> surface and [Quickstart](#quickstart) to stand up a vault end to end.

## Why

Most secrets-management setups either hand you a server to operate
(Vault, a cloud KMS) or a flat encrypted file with one shared passphrase.
cofferak is neither: it's an **envelope-encryption** vault where the key
that decrypts your secrets is itself sealed by the operating system's own
secure-storage primitive — `systemd-creds` on Linux, Keychain on macOS —
so the unseal key is never a plaintext file sitting next to the vault.

- **No external dependency.** No server to run, no account to create, no
  network call to any third-party KMS. The only two things on the wire
  are a local Unix socket and the files on disk.
- **One codebase, two platforms.** `cofferak-core` (crypto, on-disk
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

## Repository layout

```
cofferak/
  cofferak-core/   # lib: crypto, on-disk format, ACL, HostSeal — no process I/O beyond disk reads/writes
  cofferakd/       # daemon: Unix-socket API, platform seal integration, audit log
  cofferak-cli/    # admin CLI: init/enroll-host/enroll-service/set/get/rm/list/rotate-dek/recover/audit tail
  deployment/      # copy-and-edit systemd unit (Linux) and launchd plist (macOS)
  docs/            # SPEC.md, adr/, PROGRESS.md, deployment guide, recovery
                   # runbook, integration examples
SDD.md             # the design/documentation practice this repo follows
```

## What's implemented

- **Envelope crypto** (`cofferak-core::crypto`): AES-256-GCM-SIV DEK
  wrap/unwrap per host, X25519 ECIES wrap/unwrap for the offline root key,
  AEAD entry encryption, zeroize-on-drop key handling.
- **On-disk format** (`cofferak-core::format`): the `vault.cofferak` binary
  file and its `meta.json` sidecar, with corrupt/truncated input returned
  as a typed error rather than a panic or a silently fresh vault.
- **Path-prefix ACL** (`cofferak-core::acl`): per-service access tokens
  scoped to path prefixes and a permission level, with a traversal-safe
  prefix check.
- **`HostSeal` trait + both backends** (`cofferak-core::seal`): the one
  platform-dependent abstraction, with:
  - `SystemdCredsSeal` (Linux) — shells out to the real `systemd-creds`
    binary.
  - `KeychainSeal` (macOS) — stores/retrieves the key as a generic
    password in the Keychain via `security-framework`.

  Both map failures to the same `SealError::{Unavailable, Invalid, Io}`
  taxonomy, so callers (and tests) don't need to care which platform
  they're on.
- **`cofferakd`**: the daemon. Loads `vault.cofferak`, unseals its own host
  key, opens the append-only audit log, then serves `Get`/`Set`/`Rm`/`List`
  requests from service tokens over a Unix socket (newline-delimited JSON).
  Reads `COFFERAK_DATA_DIR` and `COFFERAK_SOCKET` at startup (falling back
  to a per-OS default — see [`docs/deployment.md`](docs/deployment.md)),
  and refuses to start rather than silently creating an empty vault if
  `vault.cofferak` or the sealed host key is missing or unreadable.
- **`cofferak-cli`** (binary name `cofferak`): the admin CLI (see
  [Commands](#commands) below) —
  vault/host bootstrap, service enrollment, `set`/`get`/`rm`/`list` over
  the daemon socket, DEK rotation, disaster recovery, and audit log
  inspection.
- **Deployment templates** (`deployment/`): a systemd unit for Linux and a
  launchd plist for macOS, documented end to end in
  [`docs/deployment.md`](docs/deployment.md).
- **Audit log** (`cofferakd::audit`): an append-only JSON-lines log of
  every service request (`<ts> <service_id> <action> <path> <result>`),
  readable offline via `cofferak audit tail`.

## Quickstart

Requires a stable Rust toolchain (MSRV 1.75, pinned in
`rust-toolchain.toml`).

```bash
# Build everything (library, daemon, CLI).
cargo build --workspace --release

# 1. Create a brand-new vault and its root keypair. The root private key
#    is printed to stdout exactly once — copy it offline (e.g. onto a
#    hardware token or a printed page) and never store it on a host that
#    runs the daemon. It is the only way to recover the vault if every
#    enrolled host is lost; see docs/recovery-runbook.md.
./target/release/cofferak init --root --data-dir ./data

# 2. Enroll this host. This generates the vault's DEK, wraps it for the
#    root key and for this host, and seals this host's own unseal key
#    with the platform HostSeal backend (systemd-creds on Linux, Keychain
#    on macOS).
./target/release/cofferak init --host myhost --data-dir ./data

# 3. Start the daemon (foreground, for a quickstart — see
#    docs/deployment.md to run it as a systemd/launchd service instead).
COFFERAK_DATA_DIR=./data COFFERAK_SOCKET=./data/cofferakd.sock \
  ./target/release/cofferakd &

# 4. Enroll a consuming service, scoped to a path prefix. The printed
#    token is shown exactly once — hand it to the service's own config.
./target/release/cofferak enroll-service myapp \
  --paths myapp/ --perm rw --data-dir ./data

# 5. Set and get a secret over the daemon's socket.
export COFFERAK_TOKEN=<token printed by step 4>
./target/release/cofferak set myapp/db-password 's3cr3t' \
  --socket ./data/cofferakd.sock
./target/release/cofferak get myapp/db-password \
  --socket ./data/cofferakd.sock
```

## Commands

All `cofferak-cli` subcommands accept `--data-dir <DIR>` (or
`$COFFERAK_DATA_DIR`), defaulting to the platform data directory
(`/var/lib/cofferak` on Linux, `~/Library/Application Support/cofferak`
on macOS). `set`/`get`/`rm`/`list` additionally accept `--socket <PATH>`
(or `$COFFERAK_SOCKET`) and a service token via `--token` (or
`$COFFERAK_TOKEN`).

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
| `rotate-dek --hosts <csv>` | Generate a fresh DEK, re-encrypt every entry/token, and re-wrap it for the root key and the given hosts. Operates on `vault.cofferak` directly, not over the socket. |
| `recover --root-key <path> --new-host <id>` | Disaster recovery: enroll a new host using the offline root private key, bypassing every enrolled host's own sealed blob. See [`docs/recovery-runbook.md`](docs/recovery-runbook.md). |
| `audit tail [--count N]` | Print the last `N` (default 20) entries of the daemon's audit log, read directly from `<data_dir>/audit.jsonl`. |

`cofferakd` itself takes no CLI flags; it reads `COFFERAK_DATA_DIR` and
`COFFERAK_SOCKET` from the environment (same per-OS defaults as above).
See [`docs/deployment.md`](docs/deployment.md) for running it as a
systemd service (Linux) or a launchd agent (macOS), including the
`systemd-creds`/Keychain host-key sealing steps and socket permissions.

## Building and testing

```bash
cargo build --workspace
cargo test --workspace
```

`cofferak-core`'s test suite includes real integration tests against the
platform's actual sealing facility — `tests/seal_linux.rs` (skips with a
clear message if `systemd-creds` isn't on `PATH`, e.g. off Linux) and
`tests/seal_macos.rs` (runs for real against a uniquely-named,
test-scoped Keychain item on macOS, and cleans it up afterward).

## Further reading

- [`docs/deployment.md`](docs/deployment.md) — running `cofferakd` as a
  systemd service or launchd agent, environment variables, socket
  permissions.
- [`docs/recovery-runbook.md`](docs/recovery-runbook.md) — disaster
  recovery with the offline root private key, for an operator who has
  never seen this project before.
- [`docs/integrations.md`](docs/integrations.md) — worked examples:
  systemd unit for a consuming service, shell examples for
  get/set/list, a minimal raw-socket Rust client.
- [`docs/SPEC.md`](docs/SPEC.md) — full design: on-disk format, the
  daemon's request protocol, and the disaster-recovery flow.
- [`docs/adr/`](docs/adr/) — numbered point decisions (why envelope
  encryption, why no external vault/KMS dependency, why the `HostSeal`
  abstraction, why `cofferakd` has a library target).
- [`docs/PROGRESS.md`](docs/PROGRESS.md) — implementation status, one row
  per area, each backed by what was actually run.
- [`SDD.md`](SDD.md) — the design/documentation practice this project
  follows; read it before making an architectural change.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions require accepting
the project's CLA ([CLA.md](CLA.md)) on your first pull request.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). The
`cofferak` name and logo are governed separately by the
[trademark policy](TRADEMARK.md): the license covers the code, not the
name.
