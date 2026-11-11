# ADR 0015: Vault integrity code and rollback protection

Status: accepted

## Context

`vault.cofferak` is a single file. Each value was encrypted and bound to
its path, but the file as a whole was not protected:

- Someone with write access to the data directory could remove entries,
  services, peers or the identity, or splice in an older ciphertext for a
  path, and cofferak would load it.
- Someone could put back an older copy of the file (an old backup, a sync
  conflict, a deliberate rollback) and bring back deleted secrets or
  revoked service tokens, without anything noticing.
- `rotate-dek` and `recover` wrote the new vault through a fixed temp
  file, `vault.cofferak.tmp`, with `std::fs::write`, which follows
  symlinks and uses default permissions. Run as root, a planted symlink
  could overwrite any file.

## Decision

### Integrity code

Vault format 4 adds two fields:

- `generation`: incremented on every write.
- `mac`: HMAC-SHA384 over the whole encoded vault (with `mac` empty),
  keyed with HKDF-SHA384(DEK, "cofferak/v2/vault-mac").

Every writer that holds the DEK (every write except `init --root`) calls
`VaultFile::seal` before saving: the daemon on `set`/`rm`, and the CLI on
`init --host`, `enroll-host`, `enroll-service`, `rotate-dek` (under the new
DEK), `recover`, `import`, `identity` and `peer`. Any change made without
the DEK fails `VaultFile::verify`. A vault that was never sealed
(generation 0, no code, as created by `init --root` or upgraded from
format 2 or 3) is accepted only while the host has no anchor above 0, so
stripping the code from a sealed vault is caught.

### Anchor

Each host keeps `hosts/<host_id>.anchor`: the newest generation it has
written or accepted, with an HMAC-SHA384 tag (HKDF-SHA384(DEK,
"cofferak/v2/anchor"), bound to the host id), written atomically with
mode 0600. A vault whose generation is below the anchor is an older copy.

- **Daemon startup:** refuses to start on a failed integrity code, an
  edited anchor, or a generation below the anchor, and says how to accept
  an intentional restore.
- **Daemon at run time:** it also keeps the newest generation it has seen
  in memory. When the file changes on disk it verifies the code and the
  generation before reloading. On failure it logs an `ALERT`, keeps
  serving the last verified state, and refuses writes.
- **Admin commands:** verify before changing anything.
- **`cofferak accept-restore`:** after restoring a backup on purpose,
  accepts the vault on disk as the newest valid one, but only if its
  integrity code verifies (it must be an authentic copy of this vault). It
  reports how far it rolls back. The daemon is restarted afterwards.

### Safe writes everywhere

`rotate-dek` and `recover` now write through the same atomic writer as
every other path (unique temp file, `O_EXCL`, mode 0600, fsync, rename,
fsync directory).

## Limits

The anchor lives next to the vault. Someone who can replace **both** the
vault and the anchor with an older matching pair (for example, from a full
backup of the data directory) can still roll back without being detected
at startup. Protecting against that needs a monotonic counter outside the
attacker's reach (TPM2 NV storage, or a remote witness such as a paired
coffer), that is future work. A running daemon catches it regardless,
because it keeps the newest generation in memory.

Update: ADR 0017 keeps a second copy of each anchor outside the data
directory (the Keychain on macOS, `/var/lib/cofferak-anchor` on Linux),
so restoring the data directory from a backup is detected too.

## Proof

- `cofferak-core/src/format.rs` tests: sealed vaults verify, and removing
  entries or services, editing the generation, stripping the code or using
  another DEK are detected. Older copies are reported as rollback. Anchors
  round-trip and reject edits or a different host id. Format 3 vaults load
  and upgrade.
- `cofferakd/tests/daemon_persistence.rs`: daemon writes seal and advance
  the anchor. A tampered file is not loaded and blocks writes. An older
  copy put back is refused, live and at the next start.
- End to end with the real binaries: rollback while running, rollback at
  restart, a single flipped byte, and `accept-restore`.
