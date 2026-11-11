# ADR 0007: macOS Keychain cross-process access: run the daemon from the binary that sealed the key

Status: accepted (resolved: the daemon runs as `cofferak daemon` on macOS)

> **Resolution (2026-11-11):** option 4 below. The daemon's code moved into
> the `cofferakd` library (`cofferakd::server::run`), and the CLI gained a
> `cofferak daemon` subcommand that calls it. On macOS the daemon runs as
> `cofferak daemon`, the same binary that created the Keychain item, so the
> Keychain returns the key without an authorization prompt. The launchd
> template, `docs/deployment.md` and the README use it, and
> `scripts/sdk-smoke.sh` now runs the full real path on macOS in CI
> (real Keychain-sealed host key, `cofferak daemon`, all four SDKs, and a
> restart-durability check). The sections below are the original problem
> statement and options.

## Context

`KeychainSeal` stores a host's unseal key as a generic password with no
explicit access-control-list configured, so macOS defaults to trusting
only the application that created the item. `cofferak init --host` (the
`cofferak` CLI binary) creates the item; `cofferakd` (a different binary)
later tries to read it. Verified directly, independent of this
project's Rust code: even the `security find-generic-password` CLI tool,
run as a third process, hangs (no error, no prompt visible, just blocks)
trying to read an item created by a different application in this
non-interactive environment, rather than failing fast or prompting
visibly.

## Impact

On macOS, `scripts/sdk-smoke.sh` cannot currently prove the full real
`cofferak init --host` → `cofferakd` → real Keychain path end to end
from a non-interactive shell, it falls back to
`cofferakd/examples/dev-daemon.rs` (an in-memory daemon with no sealing
involved) to still prove every SDK's wire-protocol client code for real.
The Linux path (`systemd-creds`, host/TPM-bound rather than
per-process-ACL-bound) does not have this problem and is the
authoritative "full" proof, run in CI on `ubuntu-latest`.

## Options (not yet decided)

Candidates for the real fix, for whoever picks this up:

1. Explicitly set the Keychain item's access control list at seal-time
   to trust both the `cofferak` and `cofferakd` binaries by path/code
   signature (`SecAccessCreate` + `SecTrustedApplicationCreateFromPath`,
   lower-level APIs than the `security-framework` crate's high-level
   `passwords` module currently used).
2. Sign both binaries with a shared keychain-access-group entitlement and
   use that group instead of per-application trust (requires a
   provisioning/signing setup this project doesn't have yet).
3. Accept the limitation and document that the very first read after
   `init --host` needs an interactive session where the user approves
   the one-time Keychain prompt, with every subsequent `cofferakd`
   restart then working headlessly (untested - would need to be
   verified, not assumed).

4. **Run the daemon from the same binary that seals the key.** No ACL
   or signing changes: a `cofferak daemon` subcommand runs the daemon
   code, so the reader *is* the creating application. Verified on macOS:
   `cofferakd` reading a CLI-created item blocks on an authorization
   prompt, while `cofferak daemon` (and the CLI's own admin commands)
   read it silently. **Chosen.** Remaining caveat: the Keychain ties the
   trust to the binary's code identity, so after installing a new build
   macOS may ask once to allow it ("Always Allow").
