# cofferak specification

cofferak is a standalone, dependency-free secrets vault for any service on
Linux or macOS. No external vault/KMS dependency (no HashiCorp Vault, no
cloud KMS) - it is self-contained and meant to be dropped into another
project with `git clone` into a `cofferak/` subdirectory, or run standalone.

The contracts are `cofferak-core/src/{crypto,format,acl,seal}.rs`,
`cofferakd/src/{protocol,daemon,audit}.rs`, and the CLI commands under
`cofferak-cli/src/commands/`. If this file disagrees with them, stop and
record it in `docs/PROGRESS.md`.

## 1. Threat model

Protects against: a leaked disk image/backup/repo (no plaintext on disk),
another local user or process reading the vault or a credential file
directly, one compromised host exposing other hosts' trust, a service
reading secrets outside its enrolled path prefix.

Does not protect against: root on an already-unsealed live host reading
process memory, loss or disclosure of the creator's offline root private
key, the daemon account or root reading a running daemon's memory, or, on
a Mac host created with `--no-user-presence`, another process running as
the same user (hosts created normally need Touch ID or the login password
for admin commands, ADR 0017).

Integrity (ADR 0015): the whole vault carries an HMAC-SHA384 keyed from
the DEK and a generation counter, and each host keeps an authenticated
anchor of the newest generation it has seen, so edits made without the DEK
and older copies are refused. Limit: replacing both the vault and the
anchor with an older matching pair is only caught by a running daemon.

Not secret by design: secret *paths* (e.g. `myapp/DB_PASSWORD`), service
and host ids, value sizes and timestamps. They are the vault's index and
appear in `vault.cofferak`, `meta.json` and the audit log, only values
(and service tokens) are encrypted. Don't put secrets in path names.

## 2. Key hierarchy (envelope encryption - ADR 0001, crypto v2 ADR 0011)

- **Root keypair** (X25519 + ML-KEM-1024): generated once (`cofferak init
  --root`), the private half is printed once as an armored block and kept
  offline by the operator, never retained on any host.
- **Per-host unseal key**: sealed via the platform `HostSeal` backend (ADR
  0002) - `systemd-creds` (Linux) or Keychain (macOS).
- **DEK** (256-bit): encrypts the vault's entries and service tokens with
  AES-256-GCM-SIV, each ciphertext's associated data binds it to its
  context (`cofferak/v2/entry\0<path>`, `.../service-token\0<id>`). Stored
  wrapped per host (AES-256-GCM-SIV under the host key, bound to the host
  id, daily auto-unlock) and once for the root key (`VaultFile.root_wrap`,
  recovery only) with a hybrid KEM: ephemeral X25519 + ML-KEM-1024
  encapsulation, wrapping key = HKDF-SHA-384 over both shared secrets and
  the transcript.
- **Service access token**: capability `{service_id, prefixes,
  permission}`, delivered to the consuming service the same sealed way.

## 3. On-disk format

`vault.cofferak` (binary, `bincode`, format version 2, other versions are
rejected with `UnsupportedVersion`): header, `root_pubkey: {x25519,
mlkem1024}`, `hosts: BTreeMap<host_id,
DekWrapHost>`, `services: BTreeMap<service_id, EncryptedEntry>`,
`entries: BTreeMap<path, VaultEntry>`, `root_wrap: Option<DekWrapRoot>`.
`meta.json` (non-secret, informational): version, root pubkey fingerprint,
host/service IDs - safe to read without unsealing.

Both are written atomically (unique `0600` temp file → fsync → rename →
fsync directory), so a crash leaves the old or the new file, never a torn
one. Every writer - the daemon persisting a `set`/`rm`, and every CLI
admin command - holds an exclusive advisory lock on `vault.cofferak.lock`
while it reads-modifies-writes. Loading rejects files over 256 MiB and
decodes with a size limit. Host and service ids are restricted to
`[A-Za-z0-9._-]{1,64}`, not starting with `.`/`-`, since they become file
paths and credential names. (ADR 0010.)

## 4. Crates

```
cofferak-core/   # crypto (envelope wrap/unwrap, AEAD entries), on-disk
               # format, ACL/access-token model, HostSeal trait + backends
cofferakd/       # daemon: Unix-socket protocol, request handling + ACL
               # enforcement, append-only audit log. Has a lib.rs
               # (see ADR 0004) consumed by cofferak-cli.
cofferak-cli/    # `cofferak` binary: init, enroll-host, enroll-service, set,
               # get, rm, list, rotate-dek, recover, audit tail
```

## 5. Daily operation

Boot → OS delivers the host's unseal key (on Linux: systemd decrypts it
as root via `LoadCredentialEncrypted=` into `$CREDENTIALS_DIRECTORY`, so
the unprivileged daemon never needs systemd-creds itself - ADR 0009) →
`cofferakd` unwraps the DEK → decrypts the entry table into memory → serves requests over a
local Unix socket, and over TLS/TCP if server mode (§6a) is on,
enforcing each token's path-prefix ACL, until shutdown (DEK zeroized).
Every acknowledged `set`/`rm` is already durable in `vault.cofferak`, a write
that cannot be persisted is answered with `Err` and not applied. If the
vault on disk was re-keyed since startup (`rotate-dek`), writes are
refused until restart (ADR 0010).
No creator/root-private-key interaction on any normal boot, restart,
read, or write.

`cofferakd` needs `$COFFERAK_HOST_ID` to know which enrolled host it is
running as whenever the vault has more than one (default: the single
host, if there's only one). It reads that host's key from
`$CREDENTIALS_DIRECTORY/cofferak-<id>` if present, else unseals
`hosts/<id>.seal` itself, unwraps the DEK from `vault.hosts[id]`, and decrypts
every `vault.services` entry into an `AccessToken` keyed by the hex of
its own `secret` (matching the wire `token` string clients send) before
serving any request (see ADR 0006 - this token-loading step was
missing for a while and is now fixed and real).

## 6. Wire protocol

Newline-delimited JSON over the Unix socket at `$COFFERAK_SOCKET`
(`cofferakd/src/protocol.rs`'s `Request`/`Response`, serde's default
externally-tagged enum encoding - every SDK in §8 implements this
exactly):

```
Request  → {"Get":{"token":"<hex>","path":"a/b"}}
          | {"Set":{"token":"<hex>","path":"a/b","value":[1,2,3]}}
          | {"Rm":{"token":"<hex>","path":"a/b"}}
          | {"List":{"token":"<hex>","prefix":"a"}}

Response → {"Value":[1,2,3]} | {"Listed":["a/b","a/c"]}
          | "Ok" | "Denied" | "NotFound" | {"Err":"message"}
```

`value`/`Value` are plain JSON arrays of byte values (`Vec<u8>`'s
default `serde_json` encoding) - **not** base64. This has bitten one SDK
already (Go's `encoding/json` base64-encodes `[]byte` by default, see
`sdk/go/cofferak/cofferak.go`'s explicit `[]int` conversion) - any future
SDK must convert explicitly too, not rely on its language's default
byte-array JSON encoding.

## 6a. Server mode (ADR 0008)

Opt-in: `$COFFERAK_TLS_ADDR` plus `$COFFERAK_TLS_CERT`/`$COFFERAK_TLS_KEY`
and the **required** `$COFFERAK_TLS_CLIENT_CA` starts a second listener,
TLS-wrapped TCP, serving the *exact same* §6 wire protocol and the *exact
same* `Daemon::handle_request` as the Unix socket - not a separate API.
Mutual TLS is mandatory: without a client CA the daemon refuses to start
server mode. TLS is `rustls` on AWS-LC, locked to TLS 1.3,
`TLS_AES_256_GCM_SHA384`, and key exchange ML-KEM-1024 > X25519MLKEM768 >
P-384 (ADR 0011). The per-service access token (§2) is still checked on
every request, the client certificate is an additional transport-level
check, never a substitute for the token. Proven by
`scripts/server-mode-smoke.sh`, including every reject path and the
negotiated parameters.

## 7. CLI surface (current)

`init --root|--host`, `enroll-host`, `enroll-service`, `set|get|rm|list`
(over the socket; `set` takes the value from `--stdin`, `--from-file` or an
argument, `get -o` writes exact bytes to a `0600` file), `rotate-dek`
(direct file, atomic write-temp-then-rename), `recover --root-key`
(disaster recovery, zero-side-effect on failure), `audit tail`, and
`daemon` (runs the daemon in the foreground, the same code as `cofferakd`,
used on macOS so the Keychain serves the host key to the binary that sealed
it, ADR 0007). Values are limited to 1 MiB, enforced by the daemon. The service token
comes from `$COFFERAK_TOKEN` or `--token-file FILE`, never from the command
line, where `ps` would show it (ADR 0017). Admin commands run under the vault lock, on Linux the ones
that touch a host key need root, and they hand created files back to the
data directory's owner. The daemon reloads secrets and tokens when
`vault.cofferak` changes on disk (ADR 0012), so `enroll-service` and
`import` apply live, restart it after `rotate-dek` or re-enrolling its own
host (its DEK is loaded at startup). Moving data: `import-env` /
`export-env` (`.env` files, via the daemon with a token), `run` (exec a
command with secrets as environment variables; `COFFERAK_TOKEN` removed
from its environment), and `export` / `import` (admin): passphrase
bundles (PBKDF2-HMAC-SHA384 + AES-256-GCM-SIV), or with `export --to PEER`
transfers encrypted to a paired coffer's identity (X25519 + ML-KEM-1024)
and signed (ECDSA P-384 + ML-DSA-87), accepted only from trusted peers
(`identity`, `peer add|list|rm`, ADR 0013). `vault.cofferak` format 3
stores the coffer identity and peers, encrypted under the DEK, format 2 is
read and upgraded. See `cofferak-cli/src/main.rs` for exact flags - this spec
does not restate flag syntax.

## 8. SDKs

Client SDKs implementing §6's wire protocol exist for Rust, Go, Python,
and TypeScript/JavaScript (`sdk/<lang>/...`), each with a smoke test
(`sdk/<lang>/.../examples/smoke.*`) proven against a real daemon by
`scripts/sdk-smoke.sh`, wired into CI as the `sdk-smoke` job. See ADR
0005 and `docs/sample-integration/` for usage. All four also support
the §6a TLS/mTLS transport, each via its own language's TLS standard
library (no third-party TLS dependency anywhere) - proven, including
the adversarial reject cases, by `scripts/server-mode-smoke.sh`. See
ADR 0008. Planned: C, C++, Perl, Ruby
(`docs/sample-integration/roadmap.md`).

## 9. What's deliberately out of scope

No multi-operator/quorum (no Shamir shares) - single creator, single root
trust. No general config templating. No clustering/load-balancing across
multiple `cofferakd` instances - one process serves exactly one host
(`$COFFERAK_HOST_ID`), whether over the Unix socket, TLS, or both.
