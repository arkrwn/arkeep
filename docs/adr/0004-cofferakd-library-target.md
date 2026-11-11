# ADR 0004: `cofferakd` exposes a library target

Status: accepted

## Context

`cofferakd` was originally bin-only. Its own integration tests reached
`audit.rs`/`protocol.rs`/`daemon.rs` via `#[path]` inclusion, which works
within one crate's own test binaries but not across a crate boundary.
When `cofferak-cli` needed `cofferakd::audit::{AuditLog, AuditEntry}` for
`audit tail` (a different crate depending on another crate's modules), a
real library dependency was required.

## Decision

`cofferakd/src/lib.rs` declares `pub mod {protocol, audit, daemon};`
without moving the module files; `main.rs` became a thin binary using the
library crate.

## Consequences

`cofferakd`'s own `audit_integration.rs`/`daemon_integration.rs` tests
were simplified to `use cofferakd::...` instead of `#[path]`, which also
removed duplicate test execution (each module's own unit tests had
previously been compiled and run twice — once via the lib, once via each
`#[path]`-including integration test binary).

When this ADR was written, `cofferak-cli/src/main.rs` and a few of its
test files still reached `cofferakd`'s `protocol`/`daemon`/`audit`
modules via `#[path]`, a leftover scoped out of the original task.

**Update:** that migration is finished. `cofferak-cli` depends on the
`cofferakd` library crate, and the CLI source and its tests import
`cofferakd::protocol`, `cofferakd::daemon` and `cofferakd::audit` from
it directly. The only remaining
`#[path]` use is in `cofferak-cli/tests/`, which includes the CLI's own
`src/` files because `cofferak-cli` has no library target; no module is
shared across crates that way any more.
