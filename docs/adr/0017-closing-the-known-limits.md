# ADR 0017: Closing the known limits from ADR 0015 and ADR 0016

Status: accepted

## Context

ADR 0015 and ADR 0016 listed risks that were documented but not fixed.
This ADR fixes them.

## Decisions

### macOS: user presence for admin commands

The Keychain item that holds a host key trusts the cofferak binary, so any
process running as the same user could run `cofferak export` (or
`enroll-service`) and read the vault.

- A host created on macOS now requires **user presence** for every admin
  command that uses its key: Touch ID, or the login password, through
  LocalAuthentication (`LAPolicyDeviceOwnerAuthentication`). It is asked at
  most once per command.
- The requirement is stored **in the Keychain item itself** (one flag byte
  after the key). Only cofferak can write that item, and the data
  directory, which the same user can edit, holds no copy of the flag.
- It fails closed: no GUI session, cancel, or no answer within 2 minutes
  all refuse.
- The daemon never asks. It only serves requests that carry a valid
  service token.
- For CI and headless Macs, create the host with
  `init --host ID --no-user-presence` (or `COFFERAK_NO_USER_PRESENCE=1`).
  This only applies to hosts being created, so setting it later can't
  remove the requirement from an existing host.
- Hosts created before this change have no flag. Re-create them
  (`enroll-host` a new id, then remove the old one) to get the protection.

### Tokens never on the command line

`--token VALUE` is refused, because `ps` shows it to every local user.
The token comes from `COFFERAK_TOKEN` or from `--token-file FILE` (`-` for
stdin).

### Memory

- The daemon wipes plaintext after each request: the request line, the
  encoded response, the value in a `set`, and the value in a `get`
  response.
- `cofferakd` and the CLI disable core dumps at startup (`RLIMIT_CORE` 0).
  On Linux the process is also marked not dumpable, which blocks `ptrace`
  and `/proc/<pid>/mem` from other processes of the same user. On macOS
  debugger attachment is denied (`PT_DENY_ATTACH`). `cofferak run` skips
  this so the program it starts behaves as usual.
- Memory is not locked (`mlock`): with a limited `RLIMIT_MEMLOCK` that
  would make allocations fail. macOS encrypts swap. On Linux, use
  encrypted swap or none on a host that runs the daemon.

### TLS: certificates bound to services, and revocation

- A token is accepted over TLS only together with a client certificate
  whose CN or a DNS SAN equals that token's service id. A leaked token
  without the service's certificate gets nothing, and neither does one
  service's certificate used with another service's token.
  `COFFERAK_TLS_BIND_SERVICE=0` turns this off for setups that can't
  name certificates after services.
- `COFFERAK_TLS_CRL` takes PEM revocation lists. A revoked client
  certificate fails the handshake.

### Peer transfers: replay protection

- Each trusted peer's encrypted record also stores the time and SHA-256
  of the newest transfer accepted from it. The same transfer again, or an
  older one, is refused.
- Transfers made more than 30 days ago are refused unless
  `import --allow-old`.
- Transfers pinned with `--from` (no stored peer) only get the age check.

### Rollback of both the vault and its anchor

Each host's anchor is now also kept outside the data directory:

- macOS: in the Keychain (service `cofferak-anchor`).
- Linux: in `/var/lib/cofferak-anchor` (the systemd unit creates it with
  `StateDirectory=`), or `$COFFERAK_ANCHOR_DIR`.

The newest of the two copies counts. Restoring the data directory from a
backup, anchor file included, is detected. `accept-restore` updates both.
Someone who can write both locations (the daemon account itself, or root)
can still roll back. A hardware monotonic counter (TPM2 NV) is the only
complete answer, and it stays future work.

## Remaining limits

- An attacker who controls the daemon account or root can still read
  secrets from a running daemon.
- On a Mac where a host was created with `--no-user-presence`, same-user
  processes can still use admin commands.
- Rollback by someone who can write both the data directory and the
  anchor mirror.

## Proof

- `cofferak-core/tests/seal_macos.rs`: the presence flag is stored with
  the key and doesn't change it.
- `cofferak-core/src/format.rs`: a mirrored anchor survives restoring the
  data directory, and an edited mirror is tampering.
- `cofferakd/src/hardening.rs`: core dumps are disabled.
- `cofferak-cli/tests/cli_transfer.rs`: importing the same peer transfer
  twice is refused, with the vault unchanged.
- `scripts/server-mode-smoke.sh` (CI): for every SDK, a valid certificate
  for another service and a revoked certificate are both rejected.
- `scripts/quickstart-check.sh` (CI): replayed transfers are refused, an
  older vault put back is refused while running, and `accept-restore`
  accepts it.
- End to end with the real binaries: `--token` on argv is refused,
  `--token-file` works, and restoring the whole data directory from a
  backup is refused at startup.
