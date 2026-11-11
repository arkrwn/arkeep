# ADR 0013: Coffer identities and signed, encrypted transfers between coffers

Status: accepted

## Context

ADR 0012 added passphrase-encrypted bundles for moving secrets between
machines. A passphrase is shared knowledge: whoever learns it can open
the file, and nothing proves who made the file. For routine moves between
your own coffers (a laptop and a server, in either direction), the user
wants transfers that:

- only the intended coffer can open (needs that coffer's key);
- the receiving coffer can verify came from a coffer it trusts;
- end up encrypted under the receiving coffer's own master key, so every
  coffer still has exactly one master key (its DEK);
- work across machines and between Linux and macOS, for the whole vault
  or just some paths, without a passphrase to manage.

## Decision

### Identity

Each coffer can have one identity, created on first use (`cofferak
identity`):

- encryption keys: X25519 + ML-KEM-1024 (hybrid);
- signing keys: ECDSA P-384 + ML-DSA-87 (hybrid; both signatures must
  verify; ML-DSA-87 is the CNSA 2.0 signature algorithm).

All from AWS-LC (stable APIs). The private half is stored in
`vault.cofferak` as `identity`, encrypted under the coffer's DEK with
associated data `cofferak/v2/identity`. It is re-encrypted by
`rotate-dek` like everything else, never printed, and never leaves the
vault. The public half is shared as a one-line text file
`COFFERAK-IDENTITY-1:<base64>` with a readable fingerprint (SHA-256,
first 128 bits shown in groups of four hex digits).

### Peers (trust)

`cofferak peer add NAME FILE` records another coffer's public identity as
trusted, like SSH `known_hosts`. Peers are stored in `vault.cofferak` as
`peers`, each encrypted under the DEK with associated data
`cofferak/v2/peer\0NAME`. An attacker who can write the vault file
therefore can't add a peer without the DEK. Adding your own identity, or
the same identity under two names, is refused, and names are validated
like host and service ids. Users are told to compare fingerprints over a
channel they trust.

### Transfers

`cofferak export --to PEER [--prefix P]... [--with-tokens] -o FILE` builds
a bundle (the ADR 0012 payload) and seals it for the peer. The file starts
with magic `CFKEXPT2`, a version, and the recipient's fingerprint. It
embeds the sender's public identity, an ephemeral X25519 key, an
ML-KEM-1024 ciphertext and a nonce, then the ciphertext, then both
signatures over every preceding byte:

- key = HKDF-SHA-384(X25519 secret ‖ ML-KEM secret, info = label ‖
  recipient fingerprint ‖ sender fingerprint ‖ ephemeral key ‖ ML-KEM
  ciphertext);
- payload encrypted with AES-256-GCM-SIV; the header (everything up to
  the nonce) is its associated data.

`cofferak import FILE` recognizes the magic and:

1. refuses a bundle addressed to another coffer;
2. verifies both signatures with the embedded sender identity (any
   modification, truncation or swapped sender key fails);
3. decrypts with this coffer's identity;
4. accepts the contents only if the sender's fingerprint is a stored peer
   (or matches `--from IDENTITY_FILE`), and reports which peer it was;
5. re-encrypts every secret and token under this coffer's DEK, keeping
   existing paths unless `--overwrite`.

`--prefix` moves or appends part of a vault. Tokens are included for a
whole-vault export and left out of a `--prefix` export unless
`--with-tokens`, so a partial move doesn't overwrite the receiver's app
tokens by surprise. Passphrase bundles (`CFKEXPT1`) keep working, and
`import` detects which kind it was given.

### Vault format 3

`identity` and `peers` are new fields, so `vault.cofferak` is now format
version 3. Format 2 files are read and upgraded in memory; the next save
writes format 3. Format 1 is still rejected.

## Alternatives considered

- **Sharing one coffer's master key with another:** violates "one master
  key per coffer"; a compromise of either would expose both.
- **Using the root key for transfers:** the root key is offline by design
  (recovery only) and must not be needed for routine moves.
- **Encryption without signatures:** anyone with the receiver's public
  identity could inject secrets; signatures plus the peer list prevent
  that.
- **Classical-only signatures:** ML-DSA-87 is available in AWS-LC's
  stable API, so the transfer is post-quantum for both confidentiality
  and authenticity.

## Proof

- `cofferak-core/src/identity.rs` tests: round trip; only the recipient
  can open; any byte flip or truncation is rejected; a forger gets only
  their own identity verified, and swapping in a trusted sender's public
  key breaks the signature; identity text and secret encoding round trip.
- `cofferak-cli/tests/cli_transfer.rs`: Mac ↔ server both ways with
  `--prefix`, values readable only under the receiver's key; untrusted
  sender and wrong recipient refused with the vault unchanged; identity
  and peers survive `rotate-dek`; peer-name validation and duplicate/self
  trust refused.
- `cofferak-core/src/format.rs`: format 2 vaults load and upgrade.
- `scripts/quickstart-check.sh` (CI, Linux and macOS): two coffers paired,
  transfers both ways, wrong-recipient and untrusted-sender refusals.
