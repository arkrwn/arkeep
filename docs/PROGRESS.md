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
| `HostSeal`: Linux (`systemd-creds`) | done | Cross-compiled and clippy-checked for the real `x86_64-unknown-linux-gnu` target; round-trip test gated on `systemd-creds` availability |
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
| Rename `cofferak` → `cofferak` | done | Full workspace rebuild + `cargo test --workspace` + `cargo clippy -D warnings` green after the rename; binary name is `cofferak` |

## Known gaps / open items

- No task currently wires multiple CLI-enrolled hosts into one running
  `cofferakd` process (the daemon only ever serves the single host whose
  sealed blob lives at the fixed per-host path it was started with).
  `enroll-host` correctly re-wraps the DEK for additional hosts on disk;
  nothing yet starts a daemon that reads more than one of those wraps.
- `cofferak-cli/src/main.rs` and a few of its test files reach `cofferakd`'s
  `protocol`/`daemon`/`audit` modules via `#[path]` rather than
  `cofferakd::...` directly (ADR 0004) — a scoped-out cleanup, not a defect.
- A handful of intermediate key buffers (recovered DEK bytes before
  copying into a `[u8;32]`, in both `HostSeal` backends) are not wrapped
  in the `zeroize`-on-drop `KeyBytes` type. Low risk (short-lived,
  never logged), flagged for a later hardening pass.
