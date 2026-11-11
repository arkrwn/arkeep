# ADR 0010: Daemon writes are durable before they are acknowledged; one lock for all vault writers

Status: accepted, amended by ADR 0011

> **Amended by [ADR 0011](0011-cnsa-grade-crypto-and-hardened-transport.md):**
> `vault.cofferak` is now format version 2. Point 5's statement that
> existing vaults load unchanged applied to format v1 at the time; since
> ADR 0011, `VaultFile::load` returns `UnsupportedVersion` for any file
> that is not version 2, so v1 vaults must be recreated. Everything else
> here (write-through, atomic writes, the vault lock, bounded decoding)
> is unchanged.

## Context

A production-readiness review found that `cofferakd` applied `set`/`rm`
only to its in-memory map. `Daemon::save_to` existed but nothing called
it, so every secret written through the daemon (Unix socket or server
mode) was silently lost on restart — while the client had been told
`ok`. Separately, `VaultFile::save` wrote `vault.cofferak` in place
(truncate + write), so a crash mid-write could corrupt the whole vault,
and nothing stopped the CLI and the daemon from read-modify-writing the
file at the same time and dropping each other's changes.

## Decision

1. **Write-through, acknowledge after disk.** A daemon built with
   `Daemon::with_persistence` (always, in `cofferakd`'s `main`) handles a
   `set`/`rm` by: taking the vault lock, re-reading `vault.cofferak`,
   applying exactly that one entry change, saving atomically, and only
   then updating memory and replying `ok`. On any failure it replies
   `Err`, logs the cause to stderr, writes an `error` audit entry, and
   leaves memory unchanged. A write is never acknowledged unless it is
   on disk. Re-reading and applying a single change (instead of dumping
   the daemon's view) means CLI changes to `hosts`/`services` made while
   the daemon runs are preserved.
2. **Stale-DEK detection.** The daemon remembers the host wrap it
   unsealed the DEK from. If the on-disk wrap for its host differs at
   write time (`rotate-dek` ran, or the host was re-enrolled), it refuses
   the write — encrypting under the old DEK would make that entry
   unreadable to everyone else. Reads keep working; restart to pick up
   the new DEK.
3. **Atomic, durable file writes** (`format::write_atomic`, used for
   `vault.cofferak` and `meta.json`): write a uniquely named `0600` temp file
   in the same directory (`create_new`, so a planted file or symlink is
   never followed), `fsync` it, `rename` over the target, `fsync` the
   directory. Readers see the old or the new vault, never a torn one.
4. **One exclusive lock** (`format::VaultLock`, an OS advisory lock on
   `vault.cofferak.lock` via `std::fs::File::lock`, released automatically
   if the process dies) taken by the daemon around each persisted write
   and by the CLI around every admin command. This raised the workspace
   MSRV to Rust 1.89, where `File::lock` was stabilized.
5. **Bounded decoding.** `VaultFile::load` rejects files over 256 MiB
   and decodes with a bincode size limit, so a corrupt or hostile length
   prefix fails as `Corrupt` instead of attempting a huge allocation.
   The encoding is byte-identical to before (fixed-int, little-endian),
   so existing vaults load unchanged.

## Not changed

The daemon still loads service tokens at startup, so
`enroll-service` needs a daemon restart to take effect (documented in
`docs/deployment.md`). Hot reload was deferred: restart is simple,
explicit and already required after `rotate-dek`.

## Proof

`cofferakd/tests/daemon_persistence.rs` (set is on disk before
`ok` and survives a restart; rm reaches disk; a re-keyed vault and an
unwritable vault both get `Err` with memory unchanged; concurrent CLI
changes are not clobbered), `format.rs` unit tests (atomic replace
leaves no temp files and mode `0600`; lock excludes concurrent holders;
oversized length prefix → `Corrupt`), and `scripts/sdk-smoke.sh` full
mode, which writes through the real daemon, restarts it, and reads the
value back.
