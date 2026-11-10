# mikavt progress

Only the lead (the human maintainer, or whoever they delegate as lead for
a given work session) edits this file. A row is `done` only with proof
from a command or test that was actually run. States: `todo`, `doing`,
`done`, `blocked`.

| Area | State | Proof |
|---|---|---|
| Core crypto (envelope wrap/unwrap, AEAD entries, `KeyBytes` zeroize) | done | `cargo test -p mikavt-core crypto::` green; wrong-key/tampered-ciphertext paths return `Err`, never panic |
| On-disk format (`vault.mika`, `meta.json`) | done | `cargo test -p mikavt-core format::` + integration round-trip green; truncated-file load returns `Err`, never a fresh default vault |
| ACL / access tokens | done | `cargo test -p mikavt-core acl::` green; path-traversal and empty-path inputs denied, never panic |
| `HostSeal`: Linux (`systemd-creds`) | done | Cross-compiled and clippy-checked for the real `x86_64-unknown-linux-gnu` target; round-trip test gated on `systemd-creds` availability |
| `HostSeal`: macOS (Keychain) | done | Real Keychain round-trip test on macOS, cleans up its own test item, verified via `security dump-keychain` |
| `mikavtd` daemon core + ACL enforcement | done | `cargo test -p mikavtd` green, including an 8-thread concurrency test and a corrupted-vault-refuses-to-start test |
| Audit log | done | Append-only, survives reopen, skips malformed lines without losing other entries, partial-write-doesn't-corrupt-next-append regression test |
| `mikavtd` library target (ADR 0004) | done | `cargo test --workspace` green before/after; `mikavt-cli` depends on `mikavtd::audit` as a real crate dependency |
| Deployment templates (systemd unit, launchd plist) | done | Env var names and socket path verified against actual `main.rs` defaults; socket mode enforced in code (`0660`, `mikavt:mikavt`, not root-owned) |
| CLI: `init --root` / `init --host` | done | Root key printed once, never logged again; double-init and missing-vault paths return clean errors |
| CLI: `enroll-host` / `enroll-service` | done | Two-seal design verified correct (each seal only ever touches its own host's own sealed blob) |
| CLI: `set/get/rm/list` / `rotate-dek` | done | Real socket round-trip; `rotate-dek` is write-temp-then-rename, genuinely re-wraps (verified old DEK fails post-rotation) |
| CLI: `recover --root-key` | done | Wrong-key and missing-vault paths leave `vault.mika` byte-for-byte unchanged (verified, not assumed) |
| CLI: `audit tail` | done | 3/3 tests, real `mikavtd::audit` dependency |
| End-to-end lifecycle test | done | Real `Daemon`/`UnixListener` socket round-trip (not an in-process shortcut) for init → enroll → set/get → deny → audit |
| CI (fmt, clippy, test on ubuntu + macos, on every push and PR) | done | `.github/workflows/ci.yml`; `cargo fmt --all -- --check` / `cargo clippy --workspace --all-targets -- -D warnings` / `cargo test --workspace` all clean in a fresh clone |
| Packaging (README, LICENSE pack, recovery runbook) | done | Apache-2.0 + NOTICE/TRADEMARK/CLA; fresh `git clone` → `cargo build --workspace --release` → `cargo test --workspace` passed with no other context |
| Rename `mikvault` → `mikavt` | done | Full workspace rebuild + `cargo test --workspace` + `cargo clippy -D warnings` green after the rename; binary name is `mikavt` |
| Real per-host DEK reconstruction + token loading in `mikavtd` (ADR 0006) | done | Was a real, previously-unexercised bug (daemon denied every request, always) — fixed; `./scripts/sdk-smoke.sh` (full mode, Linux) now runs the real `mikavt`/`mikavtd` binaries end to end and passes |
| SDK: Rust (`sdk/rust/mikavt-sdk`) | done | `sdk-smoke` passes locally and is wired into CI |
| SDK: Go (`sdk/go/mikavt`) | done | Same; required an explicit `[]int` conversion workaround for `encoding/json`'s base64 default on `[]byte` — see ADR 0005/`docs/SPEC.md` §6 |
| SDK: Python (`sdk/python/mikavt_sdk`) | done | Same, stdlib only |
| SDK: TypeScript/JavaScript (`sdk/javascript/mikavt-sdk`) | done | Same; smoke test runs against the compiled `dist/` output, proving the JS consumption path too |
| `sdk-smoke` CI job | done | Added to `.github/workflows/ci.yml`; `ubuntu-latest` runs "full" mode (real binaries + real `systemd-creds`), `macos-latest` runs "dev" mode (see ADR 0007) |
| Server mode: TLS/TCP listener in `mikavtd` (ADR 0008) | done | `./scripts/server-mode-smoke.sh`: real self-signed CA/cert generated with `openssl`, real TLS handshake, real token auth over TLS, real denied-path check — all passing, for all four SDKs |
| Server mode: mutual TLS (`$MIKAVT_TLS_CLIENT_CA`) | done | Same script, for all four SDKs: a client with no cert, and separately a client with a cert signed by a *different, untrusted* CA, are both rejected; only a cert signed by the configured CA is accepted — all verified, not assumed |
| Server mode: hostname verification | done | Same script, for all four SDKs: connecting with the wrong expected server name against the real server cert is rejected (defends against a MITM presenting a different, even CA-signed, cert) |
| Server mode: Rust SDK TLS client (`Client::connect_tls`) | done | `sdk/rust/mikavt-sdk/examples/smoke_tls.rs`, run for real by `scripts/server-mode-smoke.sh` |
| Server mode: Go SDK TLS client (`ConnectTLS`, `crypto/tls`) | done | `sdk/go/mikavt/examples/smoke_tls/main.go`; TLS 1.3 pinned via `MinVersion`/`MaxVersion`, fresh `x509.NewCertPool()` (never `SystemCertPool()`) |
| Server mode: Python SDK TLS client (`Client.connect_tls`, `ssl`) | done | `sdk/python/mikavt_sdk/examples/smoke_tls.py`; `PROTOCOL_TLS_CLIENT`'s secure defaults kept, `load_default_certs()` never called |
| Server mode: TypeScript/JavaScript SDK TLS client (`Client.connectTls`, `node:tls`) | done | `sdk/javascript/mikavt-sdk/examples/smoke_tls.js`, run against the compiled `dist/` output; `rejectUnauthorized` never disabled |
| Server mode security hardening (post-review, both passes) | done | TLS 1.3-only in every SDK, not just the daemon; bounded request/response lines in the daemon *and* every SDK's own response reading (a hostile daemon could flood a client too); 30s per-connection I/O timeout on the daemon and every SDK's TLS client; no public-root-CA fallback in any SDK. See ADR 0008's "Security hardening applied" section |

## Known gaps / open items

- **No connection-count/rate limiting on the server-mode TLS listener
  (ADR 0008, disclosed, not fixed).** The 30s per-connection I/O
  timeout bounds how long any one connection can hold a thread, but
  doesn't stop many parallel connections from exhausting threads for
  that duration. For an internet-facing deployment, put a reverse
  proxy/load balancer with connection limiting in front of
  `$MIKAVT_TLS_ADDR` rather than exposing it directly. A connection
  semaphore inside `mikavtd` itself would close this properly; not
  implemented yet.
- **macOS Keychain cross-process access (ADR 0007, open, not yet fixed).**
  `mikavtd` reading a sealed key that `mikavt init --host` (a different
  binary) created hangs waiting on an authorization step that can't
  render in a non-interactive session, rather than failing fast. Verified
  independent of this project's code (`security find-generic-password`
  itself hangs the same way). `scripts/sdk-smoke.sh` falls back to an
  in-memory dev daemon on macOS to still prove the SDKs for real; the
  authoritative full end-to-end proof runs in CI on `ubuntu-latest`
  (`systemd-creds` has no equivalent per-process ACL problem).
- One `mikavtd` process serves exactly one host (`$MIKAVT_HOST_ID`); it
  does not load-balance or proxy across multiple enrolled hosts.
  `enroll-host` correctly re-wraps the DEK for additional hosts on disk;
  nothing starts one daemon that serves more than one of those hosts at
  once (not currently a goal — see `docs/SPEC.md` §9).
- `mikavt-cli/src/main.rs` and a few of its test files reach `mikavtd`'s
  `protocol`/`daemon`/`audit` modules via `#[path]` rather than
  `mikavtd::...` directly (ADR 0004) — a scoped-out cleanup, not a defect.
- A handful of intermediate key buffers (recovered DEK bytes before
  copying into a `[u8;32]`, in both `HostSeal` backends) are not wrapped
  in the `zeroize`-on-drop `KeyBytes` type. Low risk (short-lived,
  never logged), flagged for a later hardening pass.
