# ADR 0001: Envelope encryption with a dual-wrapped DEK

Status: accepted, amended by ADR 0011

> **Amended by [ADR 0011](0011-cnsa-grade-crypto-and-hardened-transport.md):**
> the root wrap is no longer X25519 alone with the raw shared secret used
> directly as the AES key. The root key is now an X25519 key plus an
> ML-KEM-1024 key (hybrid), and the wrapping key is derived with
> HKDF-SHA-384. Every ciphertext is also bound to its context through
> AEAD associated data. The dual-wrap structure decided here is unchanged.

## Decision

A Data Encryption Key (DEK) encrypts the actual secrets store
(AES-256-GCM-SIV). The DEK is wrapped twice: once by a host unseal key
(sealed by `systemd-creds` on Linux, TPM2-bound when a TPM is present,
or stored in the macOS Keychain) for automatic unlock on every boot with
no human involved, and once by the creator's X25519 root public key,
needed only to mint a new host's unseal key or recover from a lost host
key.

## Alternatives considered

- Shamir threshold shares: built for multi-operator orgs, adds quorum
  overhead with no benefit for a single creator.
- A single symmetric key with an offline backup copy: the "creator's
  key" would just be a spare copy of the same key the host already has,
  so compromising the host is exactly as bad as compromising the backup.

## Consequences

The dual-wrap keeps the root key cryptographically distinct from every
host key, so a leaked host never exposes the root, and the root can't be
reconstructed from a host breach.
