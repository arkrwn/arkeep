# ADR 0001: Envelope encryption with a dual-wrapped DEK

Status: accepted

A Data Encryption Key (DEK) encrypts the actual secrets store
(AES-256-GCM-SIV). The DEK is wrapped twice: once by a host unseal key
(systemd-creds/Keychain, TPM/Secure-Enclave-bound when available) for
automatic unlock on every boot with no human involved, and once by the
creator's X25519 root public key, needed only to mint a new host's unseal
key or recover from a lost host key.

Considered and rejected: Shamir threshold shares (built for multi-operator
orgs, adds quorum overhead with no benefit for a single creator); a single
symmetric key with an offline backup copy (the "creator's key" would just
be a spare copy of the same key the host already has — compromising the
host is exactly as bad as compromising the backup). The dual-wrap keeps the
root key cryptographically distinct from every host key, so a leaked host
never exposes the root, and the root can't be reconstructed from a host
breach.
