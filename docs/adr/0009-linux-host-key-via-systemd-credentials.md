# ADR 0009: On Linux, the daemon gets its host key from systemd, not from systemd-creds directly

Status: accepted

The Linux `HostSeal` backend (ADR 0002) seals each host's 32-byte key
with `systemd-creds encrypt --name=arkeep-<id> - -`. The first time this
ran on a real CI runner, both `seal_linux` and the full-mode SDK smoke
test failed with `host seal backend rejected input`. Capturing
`systemd-creds`' stderr exposed two separate problems:

1. The backend invoked `systemd-creds encrypt|decrypt --name=<n>` without
   the mandatory input/output positional arguments (`- -`), so it exited
   with "Too few arguments." — the Linux backend had never actually
   worked. Fixed; the CI root run of `seal_linux` now proves the real
   round trip.
2. systemd-creds' default **host scope** encrypts against
   `/var/lib/systemd/credential.secret` (and the TPM2 when present),
   which is readable only by root. The alternative user scope (`--uid=`)
   exists only in systemd ≥ 256; Ubuntu 24.04 ships 255. So an
   unprivileged `arkeepd` — which is how the unit always ran it
   (`User=arkeep`) — could never unseal its own key.

Every earlier "works on Linux" claim had only been checked by
cross-compiling or in skip paths. The rest of this ADR addresses (2).

Options considered:

1. **Run `arkeepd` as root.** Rejected: a network-reachable secrets
   daemon (server mode, ADR 0008) must not run with full privileges.
2. **Make `credential.secret` group-readable.** Rejected: it weakens
   every other credential on the host, not just arkeep's.
3. **Require systemd ≥ 256 and use `--uid=` user scope.** Rejected for
   now: excludes current Ubuntu LTS / Debian stable.
4. **Let systemd decrypt it for the daemon.** Accepted.

**Decision:**

- **Admin commands run as root on Linux** (`sudo arkeep init --host`,
  `enroll-host`, `enroll-service`, `rotate-dek`, `recover`): they are the
  only code that calls `systemd-creds` directly. After each admin
  command, the CLI `lchown`s any vault file not owned by the data
  directory's owner back to that owner (never following symlinks), so the
  unprivileged daemon can still read and write `vault.arkeep`.
- **The daemon stays unprivileged.** The unit declares
  `LoadCredentialEncrypted=arkeep-<id>:<data_dir>/hosts/<id>.seal`.
  systemd (PID 1, root) decrypts the blob at service start and exposes
  the plaintext only to that unit at `$CREDENTIALS_DIRECTORY/arkeep-<id>`
  (a private, non-swappable ramfs/tmpfs mount). `arkeepd` reads exactly
  32 bytes from there, unwraps the DEK, and drops (zeroizes) the host
  key. The credential name is bound into the blob by `--name=`, so
  systemd refuses to load a blob under a different name.
- **Fallback:** without `$CREDENTIALS_DIRECTORY`, the daemon unseals
  `hosts/<id>.seal` through `HostSeal` itself (the macOS path, and a
  root-only manual path on Linux), with an error message pointing at
  `LoadCredentialEncrypted=` when it fails.
- Host and service ids are now validated (`acl::validate_id`:
  `[A-Za-z0-9._-]{1,64}`, not starting with `.`/`-`) in both the CLI and
  the daemon, since ids become file paths and credential names.

**Proof, not a claim:** CI re-runs the real `seal_linux` round trip as
root (and fails if it skips), and `scripts/sdk-smoke.sh` full mode runs
the whole production layout on every Linux build — root admin commands,
a check that no vault file is left root-owned, and the real `arkeepd`
running as the non-root runner user inside a transient systemd service
with `LoadCredentialEncrypted=`, serving all four SDKs.

**Consequences:** Linux operators need root for admin commands (they
already needed it to install the unit). Normal secret reads/writes
through the daemon need no privileges. A host with TPM2 gets TPM-bound
sealing automatically from systemd-creds; nothing in arkeep changes.
