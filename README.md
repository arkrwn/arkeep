# mikvault

A small, dependency-free secrets vault for any service on Linux or macOS —
no HashiCorp Vault, no cloud KMS, no network service beyond a local Unix
socket. Clone it into a project as a `mikvault/` subdirectory, or run it
standalone.

> **Status: early development.** The crypto/format/ACL core and both
> `HostSeal` backends are implemented and tested. The daemon
> (`mikvaultd`) and admin CLI (`mikvault-cli`) are not built yet — see
> [Roadmap](#roadmap). Build and test instructions below apply to what
> exists today (`mikvault-core`).

## Why

Most secrets-management setups either hand you a server to operate
(Vault, a cloud KMS) or a flat encrypted file with one shared passphrase.
mikvault is neither: it's an **envelope-encryption** vault where the key
that decrypts your secrets is itself sealed by the operating system's own
secure-storage primitive — `systemd-creds` on Linux, Keychain on macOS —
so the unseal key is never a plaintext file sitting next to the vault.

- **No external dependency.** No server to run, no account to create, no
  network call to any third-party KMS. The only two things on the wire
  are a local Unix socket and the files on disk.
- **One codebase, two platforms.** `mikvault-core` (crypto, on-disk
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

See [`docs/superpowers/specs/2026-11-09-mikvault-design.md`](docs/superpowers/specs/2026-11-09-mikvault-design.md)
for the full design, including the on-disk format, the daemon's request
protocol, and the disaster-recovery flow.

## Repository layout

```
mikvault/
  mikvault-core/   # lib: crypto, on-disk format, ACL, HostSeal — no process I/O beyond disk reads/writes
  mikvaultd/       # daemon (planned): Unix-socket API, platform seal integration, audit log
  mikvault-cli/    # admin CLI (planned)
  docs/            # design spec and implementation plan
```

## What's implemented today

- **Envelope crypto** (`mikvault-core::crypto`): AES-256-GCM-SIV DEK
  wrap/unwrap per host, X25519 ECIES wrap/unwrap for the offline root key,
  AEAD entry encryption, zeroize-on-drop key handling.
- **On-disk format** (`mikvault-core::format`): the `vault.mika` binary
  file and its `meta.json` sidecar, with corrupt/truncated input returned
  as a typed error rather than a panic or a silently fresh vault.
- **Path-prefix ACL** (`mikvault-core::acl`): per-service access tokens
  scoped to path prefixes and a permission level, with a traversal-safe
  prefix check.
- **`HostSeal` trait + both backends** (`mikvault-core::seal`): the one
  platform-dependent abstraction, with:
  - `SystemdCredsSeal` (Linux) — shells out to the real `systemd-creds`
    binary.
  - `KeychainSeal` (macOS) — stores/retrieves the key as a generic
    password in the Keychain via `security-framework`.

  Both map failures to the same `SealError::{Unavailable, Invalid, Io}`
  taxonomy, so callers (and tests) don't need to care which platform
  they're on.

## Building and testing

Requires a stable Rust toolchain (MSRV 1.75, pinned in
`rust-toolchain.toml`).

```bash
cargo build --workspace
cargo test --workspace
```

`mikvault-core`'s test suite includes real integration tests against the
platform's actual sealing facility — `tests/seal_linux.rs` (skips with a
clear message if `systemd-creds` isn't on `PATH`, e.g. off Linux) and
`tests/seal_macos.rs` (runs for real against a uniquely-named,
test-scoped Keychain item on macOS, and cleans it up afterward).

## Roadmap

The remaining work (daemon request handling, admin CLI, audit log,
deployment templates, end-to-end lifecycle test, CI) is tracked in
[`docs/superpowers/plans/2026-11-09-mikvault.md`](docs/superpowers/plans/2026-11-09-mikvault.md).
Once the CLI lands, the quickstart here will cover: generating a root
keypair, enrolling the first host, enrolling a consuming service, and
`set`/`get` over the daemon's local socket.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions require accepting
the project's CLA ([CLA.md](CLA.md)) on your first pull request.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). The
`mikvault` name and logo are governed separately by the
[trademark policy](TRADEMARK.md): the license covers the code, not the
name.
