# Architecture decision records

One decision per file, numbered in the order they were made. ADRs are
history: when a later ADR changes part of an earlier one, the earlier
file keeps its text and gets an "Amended by ADR NNNN" note under its
Status line. Conventions are in [`SDD.md`](../../SDD.md#adr-conventions).

| ADR | Title | Status | Summary |
|---|---|---|---|
| [0001](0001-envelope-encryption-dual-wrapped-dek.md) | Envelope encryption with a dual-wrapped DEK | accepted, amended by 0011 | One DEK encrypts the vault; it is wrapped by each host's sealed key and by an offline root key. |
| [0002](0002-hostseal-trait-for-platform-sealing.md) | `HostSeal` trait isolates the one platform-dependent piece | accepted, amended by 0009 | A single `seal`/`unseal` trait with `systemd-creds` (Linux) and Keychain (macOS) backends. |
| [0003](0003-no-external-vault-dependency.md) | No external vault/KMS dependency | accepted | cofferak relies only on the local OS sealing primitive and a local file, no outside secret service. |
| [0004](0004-cofferakd-library-target.md) | `cofferakd` exposes a library target | accepted | `cofferakd` is also a library so the CLI and tests import its `protocol`, `daemon` and `audit` modules. |
| [0005](0005-multi-language-sdks-ci-proven.md) | Multi-language SDKs over the shared wire protocol, proven in CI | accepted | Hand-written Rust, Go, Python and TypeScript/JavaScript SDKs, each backed by a smoke test run in CI. |
| [0006](0006-real-token-loading-and-host-id.md) | Real per-host DEK reconstruction and token loading in `cofferakd` | accepted, amended by 0009 | The daemon unwraps the DEK for its host (`$COFFERAK_HOST_ID`) and loads service tokens at startup. |
| [0007](0007-macos-keychain-cross-process-limitation.md) | macOS Keychain cross-process access is an open limitation | proposed | `cofferakd` cannot read a Keychain item created by the CLI non-interactively; fix not yet chosen. |
| [0008](0008-server-mode-rpc-over-tls.md) | Server mode is RPC over TLS, reusing the existing wire protocol | accepted, amended by 0011 | Remote access reuses the newline-delimited JSON protocol over a rustls TLS 1.3 listener. |
| [0009](0009-linux-host-key-via-systemd-credentials.md) | On Linux, the daemon gets its host key from systemd, not from systemd-creds directly | accepted | Admin commands run as root; the unprivileged daemon gets its key via `LoadCredentialEncrypted=`. |
| [0010](0010-durable-writes-and-vault-locking.md) | Daemon writes are durable before they are acknowledged; one lock for all vault writers | accepted, amended by 0011 | Writes reach disk atomically before `ok`, under one advisory lock shared by the CLI and daemon. |
| [0011](0011-cnsa-grade-crypto-and-hardened-transport.md) | CNSA-grade cryptography, post-quantum recovery wrap, and a hardened, mutual-TLS-only transport | accepted | AES-256-GCM-SIV via AWS-LC with context binding, hybrid X25519 + ML-KEM-1024 root wrap, vault format v2, mandatory mTLS. |
