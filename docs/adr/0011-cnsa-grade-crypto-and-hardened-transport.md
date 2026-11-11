# ADR 0011: CNSA-grade cryptography, post-quantum recovery wrap, and a hardened, mutual-TLS-only transport

Status: accepted (supersedes the root-wrap construction in ADR 0001 and
the optional-mTLS / cipher choices in ADR 0008)

## Context

The project's goal is a secrets store that is secure first and fast
second, with both claims backed by tests and measurements rather than
adjectives. A review of crypto format v1 against that goal found:

1. **The recovery (root) wrap was quantum-vulnerable and had no KDF.**
   It used X25519 alone, and the raw Diffie-Hellman output was used
   directly as the AES key. Anyone who copies `vault.cofferak` today could
   decrypt the DEK once a large quantum computer exists ("harvest now,
   decrypt later"), and skipping a KDF is poor practice.
2. **Ciphertexts were not bound to their context.** Entries, service
   tokens and host wraps were encrypted without associated data. Someone
   able to edit `vault.cofferak` could copy one entry's ciphertext over
   another path, and the daemon would serve secret A when asked for B.
3. **Server mode allowed plain server-authenticated TLS.** mTLS was
   optional, and the TLS 1.3 cipher-suite and key-exchange lists were the
   library defaults (including AES-128 and classical-only groups).
4. **AES ran in software on arm64.** The RustCrypto AES-GCM-SIV build
   used did not enable the ARMv8 crypto extensions, so encryption
   managed about 180 MB/s on an Apple M3 Pro.

## Decision

### Algorithms (CNSA 2.0 where it names one)

| Purpose | Algorithm | CNSA 2.0 |
|---|---|---|
| Entry, token and host-wrap encryption | AES-256-GCM-SIV (RFC 8452) | AES-256 ✔ |
| Recovery-key encapsulation | ML-KEM-1024 (FIPS 203) **+** X25519, hybrid | ML-KEM-1024 ✔ (+ classical layer) |
| Key derivation for the recovery wrap | HKDF-SHA-384 | SHA-384 ✔ |
| TLS cipher suite | TLS_AES_256_GCM_SHA384 only | AES-256, SHA-384 ✔ |
| TLS key exchange | ML-KEM-1024 → X25519MLKEM768 → P-384 | ML-KEM-1024 ✔; the hybrid uses ML-KEM-768, which CNSA 2.0 does not accept, so it ranks second; P-384 is CNSA 1.0 |
| Certificates in tests and docs | ECDSA P-384, SHA-384 | CNSA 1.0 (CNSA 2.0 calls for ML-DSA-87, which the TLS libraries used here do not support yet) |

AES-256-GCM-SIV is kept for data at rest because it is nonce-misuse
resistant: a repeated random nonce, however unlikely, reveals only that
two equal plaintexts were encrypted rather than breaking confidentiality,
which plain GCM would do.

### Implementation: AWS-LC

All asymmetric crypto, the AEAD, and TLS run on **AWS-LC** (`aws-lc-rs`),
whose cryptographic module is FIPS 140-3 validated and uses the CPU's AES
and carry-less-multiply instructions on x86-64 and arm64. RustCrypto's
`ml-kem` was evaluated and rejected because its README states it has
never been independently audited. RustCrypto's NCC-audited
`aes-gcm-siv` remains as a **test-only** dependency: a unit test checks
that AWS-LC's output is byte-identical standard RFC 8452 in both
directions.

### Crypto format v2 (`vault.cofferak` version 2)

- **Hybrid recovery wrap.** The root key is an X25519 key plus an
  ML-KEM-1024 key. Wrapping the DEK performs an ephemeral X25519
  exchange *and* an ML-KEM-1024 encapsulation. The wrapping key is
  `HKDF-SHA-384(ikm = x25519_ss || mlkem_ss, info = "cofferak/v2/root-wrap-kek"
  || ephemeral_pub || root_x25519_pub || mlkem_ciphertext || root_mlkem_pub)`.
  An attacker must break both X25519 and ML-KEM-1024. Low-order X25519
  points are rejected (`was_contributory`).
- **Context binding.** Every AEAD call carries associated data
  `cofferak/v2/<kind>\0<id>`: `entry` + path, `service-token` + service id,
  `host-wrap` + host id, `root-wrap`. A ciphertext moved to another
  context fails to decrypt (tested end to end in `daemon_persistence.rs`).
- **Root private key export.** 3,201 bytes (version, X25519 32 bytes,
  ML-KEM-1024 3,168 bytes) plus a 4-byte SHA-256 checksum, printed once
  by `init --root` as an ASCII-armored base64 block
  (`-----BEGIN COFFERAK ROOT PRIVATE KEY-----`). `recover --root-key`
  reads that file. The checksum rejects a truncated or mistyped key
  before any decryption is attempted.
- **Fingerprint** = SHA-256 over a domain label and both public keys.
- **Version check.** `VaultFile::load` reads the version field first and
  returns `UnsupportedVersion` for anything but 2. There is no migration
  from v1: the project is pre-1.0 with no v1 deployments to carry, and a
  migration path would have kept the weak construction alive in code.

### Transport

- **mTLS is mandatory.** `cofferakd` refuses to start server mode unless
  `COFFERAK_TLS_CLIENT_CA` is set; a peer without a certificate signed by
  that CA fails the handshake before it can send a request. The
  per-service token is still checked on every request.
- TLS 1.3 only (TLS 1.3 is the newest TLS version; there is nothing
  stronger to pin to), cipher suite TLS_AES_256_GCM_SHA384 only,
  key-exchange groups ML-KEM-1024, X25519MLKEM768, P-384 in that order.
  ML-KEM-1024 comes first because it is the only ML-KEM parameter set
  CNSA 2.0 approves; the X25519MLKEM768 hybrid stays second because it is
  what Go 1.24+ and OpenSSL 3.5+ clients offer.
  The Rust, Go and Node SDKs pin the same preferences on the client side;
  Python's `ssl` cannot restrict TLS 1.3 suites, which the server enforces
  anyway.
- **Why not ML-KEM-1024 only:** most deployed Python and Node builds
  still link OpenSSL 3.0, which has no ML-KEM, and Go offers only the
  hybrid, so the fallbacks keep every SDK working. P-384 is still CNSA 1.0
  grade.

## Proof

- `cofferak-core` unit tests: hybrid wrap round trip; unwrap fails when
  either KEM half or the ciphertext is altered; armor round trip and
  checksum rejection; path/context binding; RFC 8452 interop.
- `cofferakd/tests/daemon_persistence.rs`: a ciphertext copied to another
  path on disk is refused by the daemon, not served.
- `scripts/server-mode-smoke.sh` (CI): server mode without a client CA
  refuses to start; all four SDKs are rejected without a client
  certificate, with a certificate from an untrusted CA, or with the wrong
  hostname; TLS 1.2 and AES-128-only clients are refused; the Rust SDK
  reports `TLSv1_3 TLS13_AES_256_GCM_SHA384 MLKEM1024`.
- `scripts/bench.sh` (CI, informational) and `docs/benchmarks.md`: on an
  Apple M3 Pro, decrypting a 64-byte secret takes 0.24 µs, 16 KB values
  run at about 1.4 GB/s, the hybrid recovery wrap takes about 60 µs, and
  an end-to-end `get` over the Unix socket has an 84 µs median latency.

## Consequences

- Vaults created before this change (format v1) do not load; recreate
  them with `init --root` / `init --host` and re-enroll services.
- The root private key is longer (an armored block of about 70 lines
  instead of 64 hex characters). Store it as a file on offline media;
  see `docs/key-security.md`.
- Server-mode clients always need a client certificate.
- The AWS-LC build needs a C compiler (present on every supported
  platform and CI runner); no CMake or Go toolchain is required.
