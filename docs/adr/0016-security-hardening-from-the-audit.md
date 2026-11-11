# ADR 0016: Security hardening after the internal audit

Status: accepted

## Context

An adversarial review of the whole code base looked for ways to break,
bypass or dump cofferak. This ADR records what was fixed, how, and what is
still a known limit.

## Fixed

| Finding | Fix |
|---|---|
| Root `lchown` after admin commands followed a symlinked `hosts/` folder, so the daemon account (which owns the data directory) could make root chown any file, for example in `/etc` | The data directory and `hosts/` are opened with `O_NOFOLLOW`, ownership changes use `fchownat(..., AT_SYMLINK_NOFOLLOW)` relative to those open directories, and only known file names are touched. Nothing runs unless the effective user is root. |
| `rotate-dek` and `recover` wrote a fixed `vault.cofferak.tmp` with a symlink-following, umask-dependent write | They use the atomic writer (ADR 0015). |
| The vault lock file was opened with create, following symlinks | Opened with `O_NOFOLLOW`. |
| A bundle or peer transfer could add service tokens chosen by the sender, giving it access to the vault | Tokens are imported only with `import --with-tokens`. Without it they are listed and skipped. Every imported path, service id and token prefix is validated, and a bundle with any invalid one is rejected whole. |
| `root_pubkey` in the vault was not authenticated, so a swapped root key could receive the next DEK | The whole vault is covered by the integrity code (ADR 0015), and `rotate-dek` verifies it before wrapping the new DEK. |
| `get -o` and `identity -o` wrote into an existing file (keeping its permissions) or through a symlink | Both use the atomic writer: a new 0600 file renamed into place. |
| `cofferak run` would set any variable, so anyone able to write the prefix could set `LD_PRELOAD`, `NODE_OPTIONS`, `PATH` and similar | Variables that change how programs load or run code are refused unless named with `--allow-env NAME`. |
| `export-env` did not escape backticks, so sourcing the file in a shell could run a command | Backticks are escaped. A test sources the output in `sh` and checks that nothing runs. |
| Unbounded connections on the Unix socket, 16 MiB lines, and TLS handshakes that could trickle forever | A connection cap on the socket too (256), a hard 30 second deadline per connection on both transports (covering the TLS handshake), and an 8 MiB line limit. |
| No value size limit in the daemon, so one write token could fill the vault and block every write | The daemon refuses values over 1 MiB. |
| Client-supplied paths went into the audit log raw, so a request without a valid token could add huge lines or forge lines and terminal escapes | Paths are escaped and capped at 256 characters in the daemon, and `audit tail` escapes control characters on output too. |
| A panic while holding the daemon lock would have stopped all later requests | Lock poisoning is recovered. |
| Token lookup compared the client's string against stored tokens | The daemon stores and looks up tokens by SHA-256 digest. |
| `systemd-creds` was found through `PATH` | It is run from its absolute path. |
| `gen-certs.sh` silently reused any `ca.key` already in the output directory | It refuses unless `REUSE_CA=1` is set, and never uses a symlinked key or one owned by someone else. |

## Known limits (documented, not fixed here)

- **macOS, same user:** the Keychain item trusts the cofferak binary, so
  any process running as the same macOS user can run `cofferak export`
  and read the vault without a prompt. On a shared login or a compromised
  user account, treat the vault as readable by that user. Requiring user
  presence (Touch ID) for export, import and identity is planned.
- **Token on the command line:** `--token` is visible in `ps` to other
  local users. Use `COFFERAK_TOKEN` or the SDKs instead.
- **Memory:** plaintext values are not wiped from daemon memory after a
  response, and memory is not locked. The systemd unit disables core dumps,
  but macOS and manual runs do not.
- **TLS client certificates** are not bound to a specific token. A client
  needs both a valid certificate and a valid token. There is no CRL
  support yet: revoke by rotating the CA or the token.
- **Peer transfers** have no replay protection: re-importing an older
  transfer from a trusted peer adds only what is missing unless
  `--overwrite` is given.
- **Rollback of both the vault and its anchor** together (ADR 0015).

## Proof

- `cofferak-core`: lock refuses a symlinked lock file, dotenv output is
  safe to source in a shell.
- `cofferakd`: connection deadline closes a stalled client and leaves a
  finished one alone, audit paths are escaped and capped, oversized values
  are refused.
- `cofferak-cli/tests/cli_transfer.rs`: tokens are withheld without
  `--with-tokens`, bundles with invalid paths or ids are rejected with the
  vault unchanged.
- End to end with the real binaries: `run` refuses `PATH` from the vault,
  `get -o` through a planted symlink leaves the target untouched and
  writes a 0600 file, a 2 MiB value is refused, a bundle's tokens are
  listed and withheld.
