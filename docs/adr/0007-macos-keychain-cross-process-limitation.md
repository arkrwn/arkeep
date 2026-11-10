# ADR 0007: macOS Keychain cross-process access is an open limitation

Status: proposed (documents a known gap, not a decision taken yet)

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

**Impact:** on macOS, `scripts/sdk-smoke.sh` cannot currently prove the
full real `cofferak init --host` → `cofferakd` → real Keychain path end to
end from a non-interactive shell; it falls back to `cofferakd/examples/
dev-daemon.rs` (an in-memory daemon with no sealing involved) to still
prove every SDK's wire-protocol client code for real. The Linux path
(`systemd-creds`, host/TPM-bound rather than per-process-ACL-bound) does
not have this problem and is the authoritative "full" proof, run in CI
on `ubuntu-latest`.

**Not yet decided:** the real fix. Candidates, for whoever picks this
up: (a) explicitly set the Keychain item's access control list at
seal-time to trust both the `cofferak` and `cofferakd` binaries by path/code
signature (`SecAccessCreate` + `SecTrustedApplicationCreateFromPath`,
lower-level APIs than the `security-framework` crate's high-level
`passwords` module currently used); (b) sign both binaries with a shared
keychain-access-group entitlement and use that group instead of
per-application trust (requires a provisioning/signing setup this
project doesn't have yet); (c) accept the limitation and document that
the very first read after `init --host` needs an interactive session
where the user approves the one-time Keychain prompt, with every
subsequent `cofferakd` restart then working headlessly (untested — would
need to be verified, not assumed).

Tracked in `docs/PROGRESS.md`'s "Known gaps" until resolved.
