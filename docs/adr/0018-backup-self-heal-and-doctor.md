# ADR 0018: Backups, self-healing on deletion, and `cofferak doctor`

Status: accepted

## Context

A database-backed vault such as HashiCorp Vault keeps its data where a
single `rm` can't remove it. cofferak's vault is one file. Deleting it
exposes nothing, because it is encrypted, but it does make the secrets
unavailable. Operators need a simple way to keep copies, to be told when
something is wrong, and to lose nothing when the file is removed by
mistake.

## Decision

### `cofferak backup`

- Default: copy `vault.cofferak` into `--dir` as
  `cofferak-vault-<UTC time>.cofferak`, mode 0600, written atomically,
  after checking that the file decodes (a damaged file never replaces good
  backups). Keep the newest `--keep` copies (default 14). Only files
  matching that name pattern are counted or deleted.
- The copy is already encrypted, so making it needs **no key**. It runs
  from a timer as the unprivileged `cofferak` user on Linux, and without
  a Touch ID prompt on macOS.
- `--passphrase-file FILE` or `--to PEER` make a portable bundle
  (`cofferak-bundle-<UTC time>.cfk`) instead, through the export code.
  These need this host's key.
- Templates: `deployment/linux/cofferak-backup.{service,timer}` (daily,
  hardened, runs `doctor` afterwards) and
  `deployment/macos/com.cofferak.backup.plist` (daily at 03:15).

### Self-healing when the file is deleted

The daemon keeps the exact bytes of the newest vault it verified or wrote.
If `vault.cofferak` is missing on the next request or write, it writes
those bytes back under the vault lock and logs an `ALERT`. The copy is
authentic and current, so nothing is lost and the rollback anchor still
matches. The documentation says to stop the daemon before removing a vault
on purpose.

### `cofferak doctor`

Checks that need no key: the data directory and its mode, the vault file
(present, decodes, mode 0600, format, generation, counts, integrity code),
hosts enrolled from this machine and their anchors, whether the daemon is
reachable, and, with `--backup-dir`, the age of the newest backup
(`--max-backup-age-hours`, default 26). Exit code 0 = healthy, 1 =
warnings, 2 = a problem.

## Alternatives considered

- **Backing up decrypted data:** never. Backups stay encrypted.
- **Bundles only:** they need the host key, so a timer would need root on
  Linux and a Touch ID prompt on macOS. A raw copy needs neither, and the
  root key restores it anywhere.
- **No self-healing, only an alert:** an alert still leaves the service
  down until someone acts. Writing back the verified copy is safe, since
  it is exactly what the daemon was already serving.

## Proof

- `cofferak-cli/tests/cli_backup.rs`: copies are exact and 0600, retention
  keeps the newest N and never touches other files, same-second backups
  don't collide, missing or damaged vaults are reported and the existing
  backups kept, a backup restores to a loadable vault, and `doctor`
  reports missing vaults and stale or missing backups with the right
  severity.
- `cofferakd/tests/daemon_persistence.rs`: a deleted vault is restored
  byte for byte on the next read, and on the next write.
- `scripts/quickstart-check.sh` (CI, Linux and macOS): backups with
  retention, `doctor` against a running daemon, and an accidental `rm` of
  the vault that the daemon repairs.
