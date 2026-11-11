# Deploying arkeepd

This document covers running `arkeepd` as a background service on Linux
(systemd) and macOS (launchd). Two copy-and-edit templates ship in
`deployment/`:

| Platform | Template | Installed to |
|----------|----------|--------------|
| Linux (systemd) | `deployment/linux/arkeepd.service` | `/etc/systemd/system/arkeepd.service` |
| macOS (launchd) | `deployment/macos/com.arkeep.arkeepd.plist` | `~/Library/LaunchAgents/com.arkeep.arkeepd.plist` |

The templates are starting points. Adjust paths, user names and the binary
location to match your machine before installing them.

## Environment variables

`arkeepd` reads these at startup. `ARKEEP_DATA_DIR` and `ARKEEP_SOCKET`
are optional; if unset, the daemon falls back to the per-OS default
shown below. `ARKEEP_HOST_ID` is optional only when the vault has
exactly one enrolled host.

| Variable | Purpose | Linux default | macOS default |
|----------|---------|---------------|---------------|
| `ARKEEP_DATA_DIR` | Directory holding `vault.arkeep`, `hosts/<id>.seal` and `audit.jsonl` | `/var/lib/arkeep` | `~/Library/Application Support/arkeep` |
| `ARKEEP_SOCKET` | Path of the Unix socket the daemon listens on | `/run/arkeep/arkeepd.sock` | `~/Library/Application Support/arkeep/arkeepd.sock` |
| `ARKEEP_HOST_ID` | Which enrolled host this process runs as | — (required if more than one host is enrolled) | — (same) |
| `ARKEEP_TLS_ADDR`, `ARKEEP_TLS_CERT`, `ARKEEP_TLS_KEY`, `ARKEEP_TLS_CLIENT_CA` | Server mode (ADR 0008); off unless `ARKEEP_TLS_ADDR` is set | — | — |
| `ARKEEP_TLS_MAX_CONNECTIONS` | Cap on concurrent TLS connections; extra connections are closed | `256` | `256` |

The templates set `ARKEEP_DATA_DIR`/`ARKEEP_SOCKET` explicitly, using the
same socket filename (`arkeepd.sock`) as the built-in fallback. When you
change the socket path, change the matching client configuration too. The
Linux unit always sets `ARKEEP_HOST_ID` (its credential name depends on
it); on macOS add it to the plist if the vault has more than one host.

The daemon will refuse to start if `vault.arkeep` is missing or corrupt, if
this host's key cannot be obtained (see below) or does not unwrap the
vault's DEK, if `ARKEEP_HOST_ID` is not a valid id, or if this host's id
isn't actually enrolled in `vault.arkeep`. It never creates an empty vault.

## Writes are durable; restart after admin commands

Every `set`/`rm` the daemon acknowledges is already on disk: it is
written through to `vault.arkeep` atomically (temp file, fsync, rename,
fsync directory) under an exclusive lock on `vault.arkeep.lock` before the
client gets `ok` ([ADR 0010](adr/0010-durable-writes-and-vault-locking.md)).
If the write can't be persisted, the client gets an error and nothing
changes. CLI admin commands (`init`, `enroll-host`, `enroll-service`,
`rotate-dek`, `recover`) take the same lock, so they never interleave
with daemon writes.

The daemon loads service tokens and the DEK **at startup**. After any of
these, restart it:

| Command | Why a restart is needed |
|---------|-------------------------|
| `enroll-service` | the new service's token is only loaded at startup |
| `rotate-dek` | the daemon's in-memory DEK is stale; it **refuses all writes** (clients get an error) until restarted, rather than writing entries under the old key |
| `enroll-host`, `recover` | if they re-enrolled *this* host, same as `rotate-dek` |

```sh
sudo systemctl restart arkeepd        # Linux
launchctl kickstart -k gui/$(id -u)/com.arkeep.arkeepd   # macOS
```

## Linux (systemd)

The unit template:

- runs `arkeepd` as an unprivileged `arkeep` user with no capabilities;
- receives this host's key through `LoadCredentialEncrypted=` (below);
- sets `ARKEEP_HOST_ID`, `ARKEEP_DATA_DIR` and `ARKEEP_SOCKET`;
- uses `RuntimeDirectory=arkeep` to create `/run/arkeep` for the socket,
  and `StateDirectory=arkeep` (mode `0700`) for the data;
- disables core dumps and applies systemd sandboxing (`ProtectSystem=strict`,
  `NoNewPrivileges`, a system-call filter, and more — see the file).

### How the daemon gets its host key (ADR 0009)

`arkeep init --host <id>` seals this host's 32-byte key with
`systemd-creds encrypt --name=arkeep-<id> - -` into
`$ARKEEP_DATA_DIR/hosts/<id>.seal`. systemd-creds' host scope encrypts
against `/var/lib/systemd/credential.secret` (and the TPM2 if present),
which only root can use — so **admin commands that seal or unseal a host
key must run as root** (`sudo arkeep ...`). They hand any file they create
back to the data directory's owner afterwards, so the daemon can still
read and write the vault.

The daemon itself never runs as root and never calls `systemd-creds`.
Instead the unit's

```ini
LoadCredentialEncrypted=arkeep-<id>:/var/lib/arkeep/hosts/<id>.seal
```

has systemd decrypt the blob as root at service start and place the
plaintext key in `$CREDENTIALS_DIRECTORY/arkeep-<id>` — a private,
non-swappable mount visible only to this unit. `arkeepd` reads it, unwraps
the DEK, and zeroizes the key. The credential name must be exactly
`arkeep-<id>`: it is bound into the sealed blob, and systemd rejects a
mismatch. (Without `$CREDENTIALS_DIRECTORY` the daemon falls back to
unsealing the file itself, which on Linux only works as root.)

### Install

1. Build and install both binaries:

   ```sh
   cargo build --release
   sudo install -m 0755 target/release/arkeepd /usr/local/bin/arkeepd
   sudo install -m 0755 target/release/arkeep  /usr/local/bin/arkeep
   ```

2. Create the service account and the data directory:

   ```sh
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin arkeep
   sudo install -d -m 0700 -o arkeep -g arkeep /var/lib/arkeep
   ```

3. Bootstrap the vault and this host, **as root** (see above). Store the
   root private key `init --root` prints offline, never on this host
   ([key security](key-security.md)):

   ```sh
   HOST_ID="$(hostname -s)"
   sudo arkeep init --root --data-dir /var/lib/arkeep
   sudo arkeep init --host "$HOST_ID" --data-dir /var/lib/arkeep
   ```

4. Install the unit with your host id filled in, and start it:

   ```sh
   sed "s/REPLACE_WITH_HOST_ID/$HOST_ID/g" deployment/linux/arkeepd.service \
     | sudo tee /etc/systemd/system/arkeepd.service >/dev/null
   sudo systemctl daemon-reload
   sudo systemctl enable --now arkeepd
   systemctl status arkeepd
   journalctl -u arkeepd -n 50
   ```

5. Enroll each consuming service (as root, since it unseals the host key),
   then restart the daemon so it loads the new token:

   ```sh
   sudo arkeep enroll-service my-app --paths my-app --perm ro --data-dir /var/lib/arkeep
   sudo systemctl restart arkeepd
   ```

Always provision hosts through `arkeep init --host` / `arkeep enroll-host`
rather than running `systemd-creds encrypt` by hand: the CLI also adds the
matching `vault.hosts` entry, and the daemon refuses to start without it.

This exact layout — root admin commands, a non-root daemon under a real
systemd service receiving its key via `LoadCredentialEncrypted=`, and a
write surviving a daemon restart — is what `scripts/sdk-smoke.sh` runs on
every CI build (Linux).

## macOS (launchd)

The plist template runs `arkeepd` as a per-user LaunchAgent. It is a user
agent, not a system daemon, because the host key is stored in the user's
Keychain (service `arkeep`, account = the host's id — matching
`arkeep init --host`/`enroll-host` exactly), which is only available
inside a user session.

**Known limitation:** macOS Keychain's default access control list only
trusts the application that *created* an item. `arkeep init --host`
(run from the `arkeep` CLI binary) and `arkeepd` (a different binary)
are different applications by that ACL's definition, so `arkeepd`
reading a key the CLI sealed can hang waiting on an authorization prompt
that never renders in a non-interactive/headless session, rather than
failing fast. This is tracked in [`docs/PROGRESS.md`](PROGRESS.md)'s
"Known gaps" — until it's resolved (likely via an explicit shared ACL/
trusted-application list set at seal time), treat the macOS path as
needing a real interactive login session the first time a sealed item
is read by a different binary than the one that created it.

The template sets `RunAtLoad` so the daemon starts at login, and
`KeepAlive` so launchd restarts it if it exits.

### Install

1. Build and install the binary:

   ```sh
   cargo build --release
   sudo install -m 0755 target/release/arkeepd /usr/local/bin/arkeepd
   ```

2. Create the data directory and bootstrap the vault and this host:

   ```sh
   mkdir -p "$HOME/Library/Application Support/arkeep"
   arkeep init --root --data-dir "$HOME/Library/Application Support/arkeep"
   arkeep init --host "$(hostname -s)" --data-dir "$HOME/Library/Application Support/arkeep"
   ```

3. Copy the plist and replace every `REPLACE_WITH_USER` with your macOS
   account name. launchd does not expand `~` or `$HOME` inside plist files,
   so the paths must be absolute:

   ```sh
   cp deployment/macos/com.arkeep.arkeepd.plist ~/Library/LaunchAgents/
   open -e ~/Library/LaunchAgents/com.arkeep.arkeepd.plist
   ```

4. Validate the file and load it:

   ```sh
   plutil -lint ~/Library/LaunchAgents/com.arkeep.arkeepd.plist
   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.arkeep.arkeepd.plist
   ```

5. Check that the daemon is running:

   ```sh
   launchctl print gui/$(id -u)/com.arkeep.arkeepd
   ```

To stop and remove the agent:

```sh
launchctl bootout gui/$(id -u)/com.arkeep.arkeepd
```

## Socket permissions

The daemon runs as the unprivileged `arkeep` user, so the socket it creates
is owned by `arkeep:arkeep` with mode `0660`. `arkeepd` enforces this
mode in code after binding. A service that needs access must run as a user in
the `arkeep` group, which the unit's `RuntimeDirectoryMode=0750` allows:

```sh
sudo usermod -aG arkeep <consuming-service-user>
```

Do not make the socket root-owned. The daemon cannot create a root-owned
socket while running as `arkeep`.
