# ADR 0012: Import, export and migration; the daemon reloads vault changes live

Status: accepted

## Context

Moving secrets into and out of cofferak meant a hand-written shell loop
for `.env` files (which mishandled quotes, `export`, inline comments and
multi-line values) and no supported way at all to move a vault to another
machine except copying the data directory and running `recover` with the
offline root key. Every `enroll-service` also needed a daemon restart,
because tokens were loaded only at startup.

cofferak has no database: the whole state is `vault.cofferak` (plus the
optional `audit.jsonl`), so "migrating the database" means moving that
file's contents safely.

## Decision

### `.env` files and environment variables (service-token commands)

- `cofferak import-env FILE --prefix P [--dry-run] [--overwrite]` parses a
  `.env` file with `cofferak_core::dotenv` and stores each variable as
  `P/KEY` through the daemon. Existing paths are kept unless `--overwrite`.
- `cofferak export-env --prefix P -o FILE|-` writes the direct children of
  `P` as a `.env` file (mode 0600, never overwriting without `--force`),
  every value double-quoted and escaped; binary values, nested paths and
  names that aren't valid variable names are skipped and reported.
- `cofferak run --prefix P [--prefix Q] -- CMD` executes `CMD` with those
  variables in its environment (later prefixes override earlier ones),
  writing nothing to disk. `COFFERAK_TOKEN` is removed from the child's
  environment unless `--keep-token`: the app gets its secrets, not the
  credential that reads them.

These go through the daemon with a service token, so the token's path
prefixes and read/write permission apply and every access is audited.

Parsing rules (documented in the module): blank lines and `#` comments
skipped; optional `export `; `KEY=VALUE` with optional spaces; unquoted
values end at ` #`; single quotes are literal; double quotes understand
`\n \r \t \" \\ \$`; both may span lines; a UTF-8 BOM and CRLF are
accepted; `${VAR}` is **not** expanded (values are stored as written).
Keys must match `[A-Za-z_][A-Za-z0-9_]*`; errors name the line.
`parse(format(x)) == x` is tested for arbitrary text.

### Whole-vault bundles (admin commands)

- `cofferak export -o FILE` writes every secret (value, version,
  timestamp) and every service token into one file, encrypted with a
  passphrase (prompted twice with echo off, or `--passphrase-file`).
- `cofferak import FILE [--dry-run] [--overwrite]` restores it into an
  initialized vault on any machine or OS, re-encrypting everything under
  that vault's DEK. Service tokens keep their secrets, so apps keep working
  with the tokens they already have.

Bundle format (`cofferak_core::bundle`): magic `CFKEXPT1`, version, KDF id,
iteration count, 32-byte salt and 96-bit nonce, then AES-256-GCM-SIV over
the bincode payload with the whole header as associated data. The key is
PBKDF2-HMAC-SHA384 with 600,000 iterations (AWS-LC). PBKDF2 was chosen
over Argon2id because it is FIPS-approved and available in the validated
module already used for everything else; the passphrase minimum is 14
bytes, the FIPS PBKDF2 minimum. Opening rejects an iteration count outside
100,000–50,000,000, and any change to the header or ciphertext fails
authentication. Bundles never contain host keys or the root key, so they
are machine- and OS-independent.

When `export` runs as root via `sudo` (Linux admin commands), the bundle
file is handed back to the invoking user (`SUDO_UID`/`SUDO_GID`).

### Live reload

The daemon records the identity of `vault.cofferak` (device, inode,
modification time, length) when it loads or writes it. Before each
request it checks the file; if another process replaced it (every write is
an atomic rename, so the inode changes), it reloads the secrets and
service tokens. New services work immediately, and a service removed from
the vault is denied immediately. If the vault was re-keyed (`rotate-dek`),
the daemon keeps its last state and refuses writes until restarted, as
before (ADR 0010). The check is one `stat` per request.

## Alternatives considered

- **Argon2id for the bundle KDF:** stronger against GPU attacks per unit
  of time, but not FIPS-approved and would add an unaudited dependency;
  PBKDF2 at 600k iterations with a 14-byte minimum passphrase is the
  conservative choice.
- **Encrypting bundles to the destination's public key** (no passphrase):
  stronger, but needs the destination set up first and an extra key
  exchange step; may be added later as an option.
- **A database backend:** not needed; a single atomically written file is
  simpler to back up, move and audit.

## Proof

- `cofferak-core/src/dotenv.rs`, `cofferak-core/src/bundle.rs` unit tests.
- `cofferak-cli/tests/cli_transfer.rs`: bundles between two vaults
  (overwrite, dry run, wrong passphrase leave the vault unchanged), `.env`
  import/export over a real daemon socket, prefix merging.
- `cofferakd/tests/daemon_persistence.rs`: live reload, immediate
  revocation.
- `scripts/quickstart-check.sh` (CI, Linux and macOS): `import-env`, `run`,
  `export-env`, `export` and `import --dry-run` against the real daemon.
