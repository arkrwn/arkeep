# mikavt specification

mikavt is a standalone, dependency-free secrets vault for any service on
Linux or macOS. No external vault/KMS dependency (no HashiCorp Vault, no
cloud KMS) — it is self-contained and meant to be dropped into another
project with `git clone` into a `mikavt/` subdirectory, or run standalone.

The contracts are `mikavt-core/src/{crypto,format,acl,seal}.rs`,
`mikavtd/src/{protocol,daemon,audit}.rs`, and the CLI commands under
`mikavt-cli/src/commands/`. If this file disagrees with them, stop and
record it in `docs/PROGRESS.md`.

## 1. Threat model

Protects against: a leaked disk image/backup/repo (no plaintext on disk),
another local user or process reading the vault or a credential file
directly, one compromised host exposing other hosts' trust, a service
reading secrets outside its enrolled path prefix.

Does not protect against: root on an already-unsealed live host reading
process memory, or loss/disclosure of the creator's offline root private
key.

## 2. Key hierarchy (envelope encryption — see ADR 0001)

- **Root keypair** (X25519): generated once (`mikavt init --root`), private
  half exported offline by the operator, never retained on any host.
- **Per-host unseal key**: sealed via the platform `HostSeal` backend (ADR
  0002) — `systemd-creds` (Linux) or Keychain (macOS).
- **DEK**: encrypts the vault's entries (AES-256-GCM-SIV). Stored wrapped
  per-host (daily auto-unlock) and once under the root public key
  (`VaultFile.root_wrap`, recovery/new-host-enrollment only).
- **Service access token**: capability `{service_id, prefixes,
  permission}`, delivered to the consuming service the same sealed way.

## 3. On-disk format

`vault.mika` (binary, `bincode`): header, `hosts: BTreeMap<host_id,
DekWrapHost>`, `services: BTreeMap<service_id, EncryptedEntry>`,
`entries: BTreeMap<path, VaultEntry>`, `root_wrap: Option<DekWrapRoot>`.
`meta.json` (non-secret, informational): version, root pubkey fingerprint,
host/service IDs — safe to read without unsealing.

## 4. Crates

```
mikavt-core/   # crypto (envelope wrap/unwrap, AEAD entries), on-disk
               # format, ACL/access-token model, HostSeal trait + backends
mikavtd/       # daemon: Unix-socket protocol, request handling + ACL
               # enforcement, append-only audit log. Has a lib.rs
               # (see ADR 0004) consumed by mikavt-cli.
mikavt-cli/    # `mikavt` binary: init, enroll-host, enroll-service, set,
               # get, rm, list, rotate-dek, recover, audit tail
```

## 5. Daily operation

Boot → OS delivers the host's sealed unseal key → `mikavtd` unseals the
DEK → decrypts the entry table into memory → serves requests over a local
Unix socket, enforcing each token's path-prefix ACL, until shutdown (DEK
zeroized). No creator/root-private-key interaction on any normal boot,
restart, read, or write.

`mikavtd` needs `$MIKAVT_HOST_ID` to know which enrolled host it is
running as whenever the vault has more than one (default: the single
host, if there's only one). It reads that host's sealed key from
`hosts/<id>.seal`, unwraps the DEK from `vault.hosts[id]`, and decrypts
every `vault.services` entry into an `AccessToken` keyed by the hex of
its own `secret` (matching the wire `token` string clients send) before
serving any request (see ADR 0006 — this token-loading step was
missing for a while and is now fixed and real).

## 6. Wire protocol

Newline-delimited JSON over the Unix socket at `$MIKAVT_SOCKET`
(`mikavtd/src/protocol.rs`'s `Request`/`Response`, serde's default
externally-tagged enum encoding — every SDK in §8 implements this
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
default `serde_json` encoding) — **not** base64. This has bitten one SDK
already (Go's `encoding/json` base64-encodes `[]byte` by default; see
`sdk/go/mikavt/mikavt.go`'s explicit `[]int` conversion) — any future
SDK must convert explicitly too, not rely on its language's default
byte-array JSON encoding.

## 7. CLI surface (current)

`init --root|--host`, `enroll-host`, `enroll-service`, `set|get|rm|list`
(over the socket), `rotate-dek` (direct file, atomic write-temp-then-rename),
`recover --root-key` (disaster recovery, zero-side-effect on failure),
`audit tail`. See `mikavt-cli/src/main.rs` for exact flags — this spec
does not restate flag syntax.

## 8. SDKs

Client SDKs implementing §6's wire protocol exist for Rust, Go, Python,
and TypeScript/JavaScript (`sdk/<lang>/...`), each with a smoke test
(`sdk/<lang>/.../examples/smoke.*`) proven against a real daemon by
`scripts/sdk-smoke.sh`, wired into CI as the `sdk-smoke` job. See ADR
0005 and `docs/sample-integration/` for usage. Planned: C, C++, Perl,
Ruby (`docs/sample-integration/roadmap.md`).

## 9. What's deliberately out of scope

No multi-operator/quorum (no Shamir shares) — single creator, single root
trust. No general config templating. No remote/clustered mode. One
`mikavtd` process serves exactly one host (`$MIKAVT_HOST_ID`) — nothing
load-balances or proxies across multiple enrolled hosts' daemons.
