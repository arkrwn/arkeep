//! `mikvaultd` library crate: exposes the daemon's internal modules
//! (`protocol`, `audit`, `daemon`) as a real library target so other
//! crates in this workspace — starting with `mikvault-cli`'s audit-tail
//! command (Task 15) — can depend on `mikvaultd::audit::{AuditLog,
//! AuditEntry}` directly, instead of pulling the source file in via a
//! `#[path]` attribute the way earlier tasks' integration tests had to
//! (a `#[path]` workaround from one crate's test into another crate's
//! `src/` is not viable across crate boundaries the way it is within a
//! single crate's own `tests/`).
//!
//! The module files themselves (`protocol.rs`, `audit.rs`, `daemon.rs`)
//! stay exactly where they are; this file only declares them `pub` so
//! Cargo's automatic lib+bin target split (triggered by this crate having
//! both `src/lib.rs` and `src/main.rs`) picks them up under the library
//! crate name `mikvaultd`. `main.rs` now reaches these modules through
//! `use mikvaultd::{protocol, audit, daemon};` instead of its own `mod`
//! declarations.

pub mod audit;
pub mod daemon;
pub mod protocol;
