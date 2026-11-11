# ADR 0002: `HostSeal` trait isolates the one platform-dependent piece

Status: accepted, amended by ADR 0009

> **Amended by [ADR 0009](0009-linux-host-key-via-systemd-credentials.md):**
> on Linux the daemon normally does not call `systemd-creds` itself.
> systemd decrypts the sealed blob at service start
> (`LoadCredentialEncrypted=`) and exposes the key only to the unit in
> `$CREDENTIALS_DIRECTORY`. `HostSeal` is used by the admin commands (run
> as root) and as the daemon's fallback path.

## Context

Linux (`systemd-creds`, TPM-bound when present) and macOS (Keychain, a
generic-password item, not Secure Enclave-backed) have no common native
sealing primitive.

## Decision

A `HostSeal` trait (`seal`/`unseal` over a 32-byte key,
`cofferak-core/src/seal/mod.rs`) is the only platform-dependent surface
in the codebase. Both backends satisfy the same guarantee: the raw key
exists unsealed only in `cofferakd`'s own memory, zeroized on exit,
delivered by the OS's own credential mechanism.

## Consequences

This keeps `cofferak-core`'s crypto/format/ACL logic, and every test for
it, platform-agnostic. Each backend is tested for real on its own OS (a
real Keychain round-trip on macOS CI, a real `systemd-creds` round-trip
on Linux CI, run as root per ADR 0009) rather than mocked.
