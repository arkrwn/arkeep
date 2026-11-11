# ADR 0002: `HostSeal` trait isolates the one platform-dependent piece

Status: accepted

Linux (`systemd-creds`, TPM-bound when present) and macOS (Keychain,
Secure-Enclave-backed) have no common native sealing primitive. A
`HostSeal` trait (`seal`/`unseal` over a 32-byte key, `arkeep-core/src/seal/
mod.rs`) is the only platform-dependent surface in the codebase; both
backends satisfy the same guarantee: the raw key exists unsealed only in
`arkeepd`'s own memory, zeroized on exit, delivered by the OS's own
credential mechanism.

This keeps `arkeep-core`'s crypto/format/ACL logic, and every test for it,
platform-agnostic. Each backend is tested for real on its own OS (a real
Keychain round-trip on macOS CI, a real `systemd-creds` round-trip on
Linux CI) rather than mocked.
