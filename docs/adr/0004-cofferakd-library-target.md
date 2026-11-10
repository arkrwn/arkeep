# ADR 0004: `cofferakd` exposes a library target

Status: accepted

`cofferakd` was originally bin-only. Its own integration tests reached
`audit.rs`/`protocol.rs`/`daemon.rs` via `#[path]` inclusion, which works
within one crate's own test binaries but not across a crate boundary.
When `cofferak-cli` needed `cofferakd::audit::{AuditLog, AuditEntry}` for
`audit tail` (a different crate depending on another crate's modules), a
real library dependency was required.

`cofferakd/src/lib.rs` now declares `pub mod {protocol, audit, daemon};`
without moving the module files; `main.rs` became a thin binary using the
library crate. As a side effect, `cofferakd`'s own `audit_integration.rs`/
`daemon_integration.rs` tests were simplified to `use cofferakd::...` instead
of `#[path]`, which also removed duplicate test execution (each module's
own unit tests had previously been compiled and run twice — once via the
lib, once via each `#[path]`-including integration test binary).

`cofferak-cli/src/main.rs` and a few of its own test files still reach
`cofferakd`'s `protocol`/`daemon`/`audit` modules via `#[path]` rather than
`cofferakd::...` in every call site — a known, intentionally scoped-out
leftover (see `docs/PROGRESS.md`) from finishing this migration only as
far as the task that needed it required.
