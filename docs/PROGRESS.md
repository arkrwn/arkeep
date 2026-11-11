# cofferak progress

Only the lead (the human maintainer, or whoever they delegate as lead for
a given work session) edits this file. A row is `done` only with proof
from a command or test that was actually run. States: `todo`, `doing`,
`done`, `blocked`.

| Area | State | Proof |
|---|---|---|
| Core crypto (envelope wrap/unwrap, AEAD entries, `KeyBytes` zeroize) | done | `cargo test -p cofferak-core crypto::` green; wrong-key/tampered-ciphertext paths return `Err`, never panic |
| On-disk format (`vault.cofferak`, `meta.json`) | done | `cargo test -p cofferak-core format::` + integration round-trip green; truncated-file load returns `Err`, never a fresh default vault |
| ACL / access tokens | done | `cargo test -p cofferak-core acl::` green; path-traversal and empty-path inputs denied, never panic |
| `HostSeal`: Linux (`systemd-creds`) | done | Real round trip + corrupted-blob rejection run **as root** in CI (fails if skipped) — this run caught that the backend was missing systemd-creds' mandatory `- -` arguments and had never worked (fixed). Host scope is root-only, so the daemon gets its key via `LoadCredentialEncrypted=` instead (ADR 0009) |
| `HostSeal`: macOS (Keychain) | done | Real Keychain round-trip test on macOS, cleans up its own test item, verified via `security dump-keychain` |
| `cofferakd` daemon core + ACL enforcement | done | `cargo test -p cofferakd` green, including an 8-thread concurrency test and a corrupted-vault-refuses-to-start test |
| Audit log | done | Append-only, survives reopen, skips malformed lines without losing other entries, partial-write-doesn't-corrupt-next-append regression test |
| `cofferakd` library target (ADR 0004) | done | `cargo test --workspace` green before/after; `cofferak-cli` depends on `cofferakd::audit` as a real crate dependency |
| Deployment templates (systemd unit, launchd plist) | done | Env var names and socket path verified against actual `main.rs` defaults; socket mode enforced in code (`0660`, `cofferak:cofferak`, not root-owned) |
| CLI: `init --root` / `init --host` | done | Root key printed once, never logged again; double-init and missing-vault paths return clean errors |
| CLI: `enroll-host` / `enroll-service` | done | Two-seal design verified correct (each seal only ever touches its own host's own sealed blob) |
| CLI: `set/get/rm/list` / `rotate-dek` | done | Real socket round-trip; `rotate-dek` is write-temp-then-rename, genuinely re-wraps (verified old DEK fails post-rotation) |
| CLI: `recover --root-key` | done | Wrong-key and missing-vault paths leave `vault.cofferak` byte-for-byte unchanged (verified, not assumed) |
| CLI: `audit tail` | done | 3/3 tests, real `cofferakd::audit` dependency |
| End-to-end lifecycle test | done | Real `Daemon`/`UnixListener` socket round-trip (not an in-process shortcut) for init → enroll → set/get → deny → audit |
| CI (fmt, clippy, test on ubuntu + macos, on every push and PR) | done | `.github/workflows/ci.yml`; `cargo fmt --all -- --check` / `cargo clippy --workspace --all-targets -- -D warnings` / `cargo test --workspace` all clean in a fresh clone |
| Packaging (README, LICENSE pack, recovery runbook) | done | Apache-2.0 + NOTICE/TRADEMARK/CLA; fresh `git clone` → `cargo build --workspace --release` → `cargo test --workspace` passed with no other context |
| Project name `cofferak` | done | Full workspace rebuild + `cargo test --workspace` + `cargo clippy -D warnings` green; binary names are `cofferak` (CLI) and `cofferakd` (daemon) |
| Real per-host DEK reconstruction + token loading in `cofferakd` (ADR 0006) | done | Was a real, previously-unexercised bug (daemon denied every request, always) — fixed; `./scripts/sdk-smoke.sh` (full mode, Linux) now runs the real `cofferak`/`cofferakd` binaries end to end and passes |
| SDK: Rust (`sdk/rust/cofferak-sdk`) | done | `sdk-smoke` passes locally and is wired into CI |
| SDK: Go (`sdk/go/cofferak`) | done | Same; required an explicit `[]int` conversion workaround for `encoding/json`'s base64 default on `[]byte` — see ADR 0005/`docs/SPEC.md` §6 |
| SDK: Python (`sdk/python/cofferak_sdk`) | done | Same, stdlib only |
| SDK: TypeScript/JavaScript (`sdk/javascript/cofferak-sdk`) | done | Same; smoke test runs against the compiled `dist/` output, proving the JS consumption path too |
| `sdk-smoke` CI job | done | `ubuntu-latest` runs "full" mode exactly like production: admin commands as root, ownership check, real `cofferakd` as a non-root transient systemd service with `LoadCredentialEncrypted=`, all four SDKs, then a write-restart-read durability check. `macos-latest` runs "dev" mode (see ADR 0007) |
| Server mode: TLS/TCP listener in `cofferakd` (ADR 0008) | done | `./scripts/server-mode-smoke.sh`: real self-signed CA/cert generated with `openssl`, real TLS handshake, real token auth over TLS, real denied-path check — all passing, for all four SDKs |
| Server mode: mutual TLS (`$COFFERAK_TLS_CLIENT_CA`) | done | Same script, for all four SDKs: a client with no cert, and separately a client with a cert signed by a *different, untrusted* CA, are both rejected; only a cert signed by the configured CA is accepted — all verified, not assumed |
| Server mode: hostname verification | done | Same script, for all four SDKs: connecting with the wrong expected server name against the real server cert is rejected (defends against a MITM presenting a different, even CA-signed, cert) |
| Server mode: Rust SDK TLS client (`Client::connect_tls`) | done | `sdk/rust/cofferak-sdk/examples/smoke_tls.rs`, run for real by `scripts/server-mode-smoke.sh` |
| Server mode: Go SDK TLS client (`ConnectTLS`, `crypto/tls`) | done | `sdk/go/cofferak/examples/smoke_tls/main.go`; TLS 1.3 pinned via `MinVersion`/`MaxVersion`, fresh `x509.NewCertPool()` (never `SystemCertPool()`) |
| Server mode: Python SDK TLS client (`Client.connect_tls`, `ssl`) | done | `sdk/python/cofferak_sdk/examples/smoke_tls.py`; `PROTOCOL_TLS_CLIENT`'s secure defaults kept, `load_default_certs()` never called |
| Server mode: TypeScript/JavaScript SDK TLS client (`Client.connectTls`, `node:tls`) | done | `sdk/javascript/cofferak-sdk/examples/smoke_tls.js`, run against the compiled `dist/` output; `rejectUnauthorized` never disabled |
| Server mode security hardening (post-review, both passes) | done | TLS 1.3-only in every SDK, not just the daemon; bounded request/response lines in the daemon *and* every SDK's own response reading (a hostile daemon could flood a client too); 30s per-connection I/O timeout on the daemon and every SDK's TLS client; no public-root-CA fallback in any SDK. See ADR 0008's "Security hardening applied" section |

| Durable daemon writes (ADR 0010) | done | Was a real data-loss bug: `set`/`rm` were memory-only and lost on restart while clients got `ok`. Now written through atomically under the vault lock before `ok`; `cofferakd/tests/daemon_persistence.rs` (6 tests incl. re-keyed vault, unwritable vault, concurrent CLI edit) + restart check in `sdk-smoke` |
| Atomic vault writes + single writer lock (ADR 0010) | done | `format.rs` tests: no temp files left, mode `0600`, lock excludes concurrent holders, oversized length prefix → `Corrupt` |
| Linux non-root daemon (ADR 0009) | done | Unit uses `LoadCredentialEncrypted=`; CLI chowns files back to the data-dir owner after root admin commands; proven by `sdk-smoke` full mode in CI |
| Id validation (host/service) | done | `acl::validate_id` in CLI and daemon; traversal/separator/option-like ids rejected (unit tests) |
| Server mode: connection limit | done | At most `$COFFERAK_TLS_MAX_CONNECTIONS` (default 256) concurrent TLS connections; extra connections are closed immediately (unit-tested limiter) |
| Crypto format v2: hybrid post-quantum recovery wrap (ADR 0011) | done | X25519 + ML-KEM-1024 (AWS-LC), HKDF-SHA-384 key derivation; unit tests: round trip, unwrap fails if either KEM half or the ciphertext is altered, wrong key rejected |
| Context-bound ciphertexts (ADR 0011) | done | Entries bound to their path, tokens to their service id, host wraps to their host id; `daemon_persistence.rs` proves a ciphertext moved to another path on disk is refused, not served |
| Armored root private key with checksum | done | `init --root` prints a `-----BEGIN COFFERAK ROOT PRIVATE KEY-----` block; `recover` reads it; truncation/typos rejected by the checksum (unit test) |
| Hardware-accelerated AES-256-GCM-SIV | done | AWS-LC AEAD; RFC 8452 interop test against RustCrypto in both directions; decrypt 64 B in 0.24 µs, ≈1.4 GB/s on 16 KB (docs/benchmarks.md) |
| Server mode: mandatory mTLS, TLS 1.3 / AES-256-GCM-SHA384 only, ML-KEM-1024 preferred | done | `server-mode-smoke.sh`: no-client-CA startup refused; no cert / untrusted CA / wrong hostname rejected in all four SDKs; TLS 1.2 and AES-128 refused; Rust negotiates `TLSv1_3 TLS13_AES_256_GCM_SHA384 MLKEM1024` |
| Benchmarks | done | `scripts/bench.sh`, run in CI on every build; results in `docs/benchmarks.md` |

## Known gaps / open items

- **No per-client rate limiting on server mode.** Concurrent connections
  are capped (`$COFFERAK_TLS_MAX_CONNECTIONS`) and every connection has a
  30s I/O timeout, but one client may use all slots. For an
  internet-facing deployment, keep a firewall or a proxy with per-IP
  limits in front of `$COFFERAK_TLS_ADDR` (mTLS already rejects
  unauthenticated peers at the handshake).
- **Token/DEK changes need a daemon restart.** `enroll-service`,
  `rotate-dek` and re-enrolling the daemon's own host take effect on
  restart; after `rotate-dek` the running daemon refuses writes (never
  writes under the stale DEK) until restarted. No hot reload yet.
- **macOS Keychain cross-process access (ADR 0007, open, not yet fixed).**
  `cofferakd` reading a sealed key that `cofferak init --host` (a different
  binary) created hangs waiting on an authorization step that can't
  render in a non-interactive session, rather than failing fast. Verified
  independent of this project's code (`security find-generic-password`
  itself hangs the same way). `scripts/sdk-smoke.sh` falls back to an
  in-memory dev daemon on macOS to still prove the SDKs for real; the
  authoritative full end-to-end proof runs in CI on `ubuntu-latest`
  (`systemd-creds` has no equivalent per-process ACL problem).
- One `cofferakd` process serves exactly one host (`$COFFERAK_HOST_ID`); it
  does not load-balance or proxy across multiple enrolled hosts.
  `enroll-host` correctly re-wraps the DEK for additional hosts on disk;
  nothing starts one daemon that serves more than one of those hosts at
  once (not currently a goal — see `docs/SPEC.md` §9).
- **TLS certificates are ECDSA P-384 (CNSA 1.0), not ML-DSA-87 (CNSA
  2.0).** rustls/AWS-LC and the Go/Python/Node TLS stacks don't support
  ML-DSA certificates yet. Key exchange and encryption are already at the
  CNSA 2.0 level (ADR 0011).
- **Python and Node SDKs fall back to P-384 key exchange** on systems
  whose OpenSSL is older than 3.5 (no ML-KEM); Go negotiates the
  X25519MLKEM768 hybrid; Rust negotiates ML-KEM-1024.
- A handful of intermediate key buffers (recovered DEK bytes before
  copying into a `[u8;32]`, in both `HostSeal` backends) are not wrapped
  in the `zeroize`-on-drop `KeyBytes` type. Low risk (short-lived,
  never logged), flagged for a later hardening pass.
