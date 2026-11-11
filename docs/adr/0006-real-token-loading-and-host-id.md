# ADR 0006: Real per-host DEK reconstruction and token loading in `cofferakd`

Status: accepted, amended by ADR 0009

> **Amended by [ADR 0009](0009-linux-host-key-via-systemd-credentials.md):**
> on Linux the daemon now reads its host key from
> `$CREDENTIALS_DIRECTORY/cofferak-<id>`, decrypted by systemd
> (`LoadCredentialEncrypted=`), and only falls back to unsealing
> `hosts/<id>.seal` through `HostSeal` itself when that directory is not
> set. Host id resolution and token loading described here are unchanged.

## Context

Before this fix, `cofferakd`'s `main()` had two real bugs, both uncovered
only when `scripts/sdk-smoke.sh` tried to run the actual compiled daemon
binary against a vault the real CLI had bootstrapped — every prior test
(including the Task 16-era end-to-end test) constructed `Daemon`
directly in-process rather than running `main()`, so neither bug had
ever been exercised:

1. **The DEK was never actually reconstructed.** `main()` unsealed the
   host's own unseal key and used it directly *as* the DEK, skipping the
   `unwrap_dek_for_host(&vault.hosts[host_id], &host_key)` step entirely.
   This "worked" only because no prior test ran the real binary against
   a vault the real CLI had written.
2. **Service tokens were never loaded.** `main()` started with a
   hardcoded empty token map, so the real daemon denied every request
   from every enrolled service, always — a self-contained vault that
   could never actually serve a legitimate client.

## Decision

`main()` now unwraps the DEK from its host's entry in `vault.hosts` and
loads every enrolled service token. Fixing this required introducing `$COFFERAK_HOST_ID` (resolved
automatically when the vault has exactly one host) so the daemon knows
which host's sealed key and `vault.hosts` entry to use, and a
`load_tokens` step that decrypts and deserializes every `vault.services`
entry into an `AccessToken`, keyed by `token_key(&secret)` for
`Daemon`'s lookup.

Also fixed in the same pass: the daemon's sealed-key path and
`HostSeal` identity (`SystemdCredsSeal { name }` / `KeychainSeal
{ service, account }`) now match `cofferak-cli`'s `current_host_seal`
exactly — they were previously a fixed, daemon-wide identity unrelated
to any specific enrolled host, which could never line up with what the
CLI had sealed per-host.

## Consequences

This was a real, user-facing correctness gap, not a style nit — recorded
here rather than silently fixed because it changes `cofferakd`'s startup
contract (a new required/inferred env var) and because any fork or
in-progress deployment of this daemon before this fix was non-functional
for real service traffic.
