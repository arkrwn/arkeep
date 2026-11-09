# cofferak — design spec

Status: approved for planning (2026-11-09)

## Purpose

A standalone, self-contained secrets vault, written in Rust, with no
dependency on any external vault service (no HashiCorp Vault, no cloud KMS).
It is built to be reused by any service on any host — not myapp-specific —
and to be dropped into another project with `git clone` into a `cofferak/`
subdirectory.

Target platforms: Linux (any distro with systemd) and macOS. The same
`cofferak-core` crate and on-disk format are used on both; only the
host-sealing mechanism differs per OS (see §4).

## Non-goals

- Not a multi-operator / quorum system (no Shamir shares). Single creator,
  single root trust.
- Not a general config-management or secret-templating system — it stores
  and serves secrets; consumers fetch them explicitly.
- Not a network service exposed beyond localhost; no remote/clustered mode
  in this scope.

## Threat model

Protects against:
- A leaked disk image, backup, or repo — `vault.cofferak` never holds plaintext.
- Another local user or unrelated process reading the vault file or a
  service's credential file directly.
- A single enrolled host being compromised: its unseal key only unwraps the
  DEK for *that* host; it does not expose the root private key, and does not
  by itself let the attacker re-derive trust for other hosts.
- A consuming service reading secrets outside its enrolled path prefix.

Does not protect against:
- Root (or an attacker with root) on a live, already-unsealed host reading
  `cofferakd`'s process memory.
- Loss or disclosure of the creator's offline root private key.

## 1. Repo / crate layout

```
cofferak/
  cofferak-core/     # lib: crypto, envelope format, storage, ACL — no process I/O beyond disk reads/writes
  cofferakd/         # daemon: Unix-socket API, platform seal integration, audit log
  cofferak-cli/      # `cofferak` admin CLI
  deployment/
    linux/cofferakd.service        # systemd unit template
    macos/com.cofferak.cofferakd.plist  # launchd template
  docs/
  README.md
  LICENSE
```

Workspace `Cargo.toml` at the root ties the three crates together. No
Python, no non-Rust runtime dependency.

## 2. Key hierarchy & crypto

- **Root keypair** (X25519): generated once via `cofferak init --root`. The
  private half is written to stdout/a temp file for the operator to move
  off-machine immediately (encrypted USB, paper, offline store) and is never
  retained on any host that runs `cofferakd`. The public half is stored in
  vault metadata.
- **Per-host unseal key** (random 256-bit symmetric key): generated at
  `cofferak init --host` / `cofferak enroll-host`. Sealed by the
  platform-specific `HostSeal` backend (§4) so it only becomes readable
  inside the `cofferakd` process on that specific host.
- **DEK (Data Encryption Key)**: one random 256-bit key per vault, encrypts
  the secrets store with AES-256-GCM. Never stored unwrapped. Stored as:
  - `wrapped_by_host[host_id]` — DEK wrapped (AES-256-GCM-SIV) under each
    enrolled host's unseal key.
  - `wrapped_by_root` — DEK wrapped under the root public key (ECIES over
    X25519 + AES-256-GCM).
- **Service access token**: a capability token per enrolled consuming
  service, `{service_id, allowed_path_prefixes, permissions}`, generated at
  `cofferak enroll-service` and delivered to that service via the same
  platform seal mechanism as a host unseal key (never written in plaintext
  to that service's own config).

Enrolling a new host when at least one live host already holds the DEK:
that live host re-wraps the DEK under the new host's key — no root key
needed, this is routine ops. Enrolling a host with **no** live vault
available (disaster recovery) requires the creator to unwrap
`wrapped_by_root` with the offline root private key via
`cofferak recover --root-key <path>`, done on the creator's own offline
machine, producing a one-time enrollment blob to carry to the new host.

## 3. On-disk format

Single file `vault.cofferak`:
- Header: format version, creation time, root public key.
- Host table: `host_id → wrapped_by_host DEK, HostSeal backend tag`.
- Service table: `service_id → wrapped access token`.
- Entries: AEAD-encrypted `(path, value, version, updated_at)` records,
  e.g. path `myapp/OPENAI_API_KEY`. Each entry individually encrypted
  under the DEK so rotation/versioning doesn't require rewriting the whole
  file.

Companion `meta.json` (non-secret, informational): format version, root
public key fingerprint, list of enrolled host/service IDs — safe to read
without unsealing, useful for ops tooling.

No plaintext secret or key material is ever written to disk outside the
brief operator-controlled export of the root private key at `init --root`.

## 4. Platform host-sealing (`HostSeal` trait)

`cofferak-core` defines:
```rust
trait HostSeal {
    fn seal(&self, key: &[u8; 32]) -> SealedBlob;
    fn unseal(&self, blob: &SealedBlob) -> Result<[u8; 32]>;
}
```

- **Linux backend**: shells out to `systemd-creds encrypt` (TPM-bound when
  a TPM is present, else host-key-bound) to produce the sealed credential
  file; `cofferakd` receives the unsealed key at runtime via
  `$CREDENTIALS_DIRECTORY/cofferak_host_key`, delivered by
  `LoadCredentialEncrypted=` in the systemd unit. Never touches disk
  unsealed; lives only in the unit's private tmpfs.
- **macOS backend**: uses Keychain Services (`Security.framework` via the
  `security-framework` crate) to store the host key in the login or System
  keychain with an ACL restricted to the `cofferakd` binary's code
  signature, backed by the Secure Enclave when available. `cofferakd` runs
  as a `launchd` daemon (`com.cofferak.cofferakd.plist`) and retrieves the
  key from Keychain at startup — same "no plaintext key file" property as
  the Linux path, via the OS's own secure-storage primitive instead of
  systemd.

Both backends satisfy the same guarantee: the raw host unseal key exists
unsealed only in `cofferakd`'s own memory, delivered by the OS's own
credential mechanism, zeroized on process exit.

## 5. Service access model

- `cofferakd` listens on a local Unix domain socket:
  - Linux: `/run/cofferak/cofferak.sock`, mode `0600`, owner `root:cofferak`.
  - macOS: `/var/run/cofferak/cofferak.sock` (or per-user
    `~/Library/Application Support/cofferak/cofferak.sock` for a
    user-level install), same permission discipline.
- Every request carries the requesting service's access token (delivered to
  that service the same way as a host key — sealed, OS-native delivery).
  `cofferakd` checks the token's path-prefix ACL and permission (`read` /
  `write`) before serving the request.
- Every request (allowed or denied) is appended to a local audit log:
  `{timestamp, service_id, path, action, result}`. The log is append-only
  (opened `O_APPEND`, never truncated by `cofferakd`).

## 6. Daily operation

Boot (either platform) → OS delivers the host's sealed unseal key →
`cofferakd` unseals it → unwraps the DEK from `wrapped_by_host[this_host]`
→ decrypts the entry table into memory → serves requests over the socket
until shutdown, at which point the DEK and all decrypted values are
zeroized. No creator / root-private-key interaction on any normal boot,
restart, secret read, or secret write.

## 7. CLI (`cofferak`)

- `cofferak init --root` — generate root keypair, print private key once
  for offline export, store public key.
- `cofferak init --host` — generate this host's unseal key, seal it via the
  platform backend, wrap the DEK for it (bootstrap case: first host).
- `cofferak enroll-host <new_host_id>` — run on an existing live host; wraps
  the DEK for a newly generated key on the new host.
- `cofferak enroll-service <service_id> --paths <prefix,...> --perm ro|rw` —
  create and seal a scoped access token for a consuming service.
- `cofferak set <path>` / `get <path>` / `rm <path>` / `list [prefix]` —
  admin operations over the local socket (require local root / admin
  group membership).
- `cofferak rotate-dek` — generate a new DEK, re-wrap for all enrolled
  hosts, re-encrypt all entries.
- `cofferak recover --root-key <path>` — offline-machine-only command: given
  the exported root private key and the `vault.cofferak` file, unwrap the DEK
  and produce a fresh host-enrollment blob.
- `cofferak audit tail` — follow the audit log.

## 8. Testing strategy

- `cofferak-core`: unit tests for envelope wrap/unwrap round-trips, AEAD
  entry encryption, ACL prefix matching, format (de)serialization —
  property-tested where it's cheap (random paths/keys).
- `HostSeal` backends: Linux tested against a real `systemd-creds` in CI
  (container with systemd); macOS tested against Keychain in CI on a macOS
  runner. Both behind the same trait so core logic tests don't depend on
  either.
- `cofferakd`: integration tests driving the Unix socket protocol directly
  (enroll, set, get, denied-path, audit log assertions).
- End-to-end: a scripted "fresh host" test — init, enroll a fake service,
  fetch a secret as that service, confirm a secret outside its path prefix
  is denied, confirm the audit log recorded both.

## 9. Packaging for public reuse

- README written generically: "a small, dependency-free secrets vault for
  any service on Linux or macOS" — no reference to myapp, the creator's
  personal setup, or any specific deployment.
- `deployment/linux/cofferakd.service` and
  `deployment/macos/com.cofferak.cofferakd.plist` ship as copy-and-edit
  templates.
- A `docs/recovery-runbook.md` documents the `recover --root-key` disaster
  path step by step.
- License: MIT (default choice; swap later if the creator prefers
  otherwise).
- No AI attribution anywhere — no co-author trailers, no "generated with"
  text, in commits, code comments, or docs.

## 10. Later integration into myapp (out of scope here)

Once myapp's own Rust rewrite exists, it becomes just another enrolled
service: `cofferak enroll-service myapp --paths myapp/* --perm ro`, and
myapp's systemd/launchd unit receives its token the same way any other
service does. That migration, and removing the current Python
`secrets.py` / `master.key` flow, is a separate later work cycle and is not
part of this spec.
