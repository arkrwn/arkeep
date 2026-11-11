# Deploying cofferakd

This document covers running `cofferakd` as a background service on Linux
(systemd) and macOS (launchd). Two copy-and-edit templates ship in
`deployment/`:

| Platform | Template | Installed to |
|----------|----------|--------------|
| Linux (systemd) | `deployment/linux/cofferakd.service` | `/etc/systemd/system/cofferakd.service` |
| macOS (launchd) | `deployment/macos/com.cofferak.cofferakd.plist` | `~/Library/LaunchAgents/com.cofferak.cofferakd.plist` |

The templates are starting points. Adjust paths, user names and the binary
location to match your machine before installing them.

## Environment variables

`cofferakd` reads these at startup. `COFFERAK_DATA_DIR` and `COFFERAK_SOCKET`
are optional; if unset, the daemon falls back to the per-OS default
shown below. `COFFERAK_HOST_ID` is optional only when the vault has
exactly one enrolled host.

| Variable | Purpose | Linux default | macOS default |
|----------|---------|---------------|---------------|
| `COFFERAK_DATA_DIR` | Directory holding `vault.cofferak`, `hosts/<id>.seal` and `audit.jsonl` | `/var/lib/cofferak` | `~/Library/Application Support/cofferak` |
| `COFFERAK_SOCKET` | Path of the Unix socket the daemon listens on | `/run/cofferak/cofferakd.sock` | `~/Library/Application Support/cofferak/cofferakd.sock` |
| `COFFERAK_HOST_ID` | Which enrolled host this process runs as | — (required if more than one host is enrolled) | — (same) |
| `COFFERAK_TLS_ADDR`, `COFFERAK_TLS_CERT`, `COFFERAK_TLS_KEY`, `COFFERAK_TLS_CLIENT_CA` | Server mode (ADR 0008); off unless `COFFERAK_TLS_ADDR` is set | — | — |
| `COFFERAK_TLS_MAX_CONNECTIONS` | Cap on concurrent TLS connections; extra connections are closed | `256` | `256` |

The templates set `COFFERAK_DATA_DIR`/`COFFERAK_SOCKET` explicitly, using the
same socket filename (`cofferakd.sock`) as the built-in fallback. When you
change the socket path, change the matching client configuration too. The
Linux unit always sets `COFFERAK_HOST_ID` (its credential name depends on
it); on macOS add it to the plist if the vault has more than one host.

The daemon will refuse to start if `vault.cofferak` is missing or corrupt, if
this host's key cannot be obtained (see below) or does not unwrap the
vault's DEK, if `COFFERAK_HOST_ID` is not a valid id, or if this host's id
isn't actually enrolled in `vault.cofferak`. It never creates an empty vault.

## Writes are durable; restart after admin commands

Every `set`/`rm` the daemon acknowledges is already on disk: it is
written through to `vault.cofferak` atomically (temp file, fsync, rename,
fsync directory) under an exclusive lock on `vault.cofferak.lock` before the
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
sudo systemctl restart cofferakd        # Linux
launchctl kickstart -k gui/$(id -u)/com.cofferak.cofferakd   # macOS
```

## Linux (systemd)

The unit template:

- runs `cofferakd` as an unprivileged `cofferak` user with no capabilities;
- receives this host's key through `LoadCredentialEncrypted=` (below);
- sets `COFFERAK_HOST_ID`, `COFFERAK_DATA_DIR` and `COFFERAK_SOCKET`;
- uses `RuntimeDirectory=cofferak` to create `/run/cofferak` for the socket,
  and `StateDirectory=cofferak` (mode `0700`) for the data;
- disables core dumps and applies systemd sandboxing (`ProtectSystem=strict`,
  `NoNewPrivileges`, a system-call filter, and more — see the file).

### How the daemon gets its host key (ADR 0009)

`cofferak init --host <id>` seals this host's 32-byte key with
`systemd-creds encrypt --name=cofferak-<id> - -` into
`$COFFERAK_DATA_DIR/hosts/<id>.seal`. systemd-creds' host scope encrypts
against `/var/lib/systemd/credential.secret` (and the TPM2 if present),
which only root can use — so **admin commands that seal or unseal a host
key must run as root** (`sudo cofferak ...`). They hand any file they create
back to the data directory's owner afterwards, so the daemon can still
read and write the vault.

The daemon itself never runs as root and never calls `systemd-creds`.
Instead the unit's

```ini
LoadCredentialEncrypted=cofferak-<id>:/var/lib/cofferak/hosts/<id>.seal
```

has systemd decrypt the blob as root at service start and place the
plaintext key in `$CREDENTIALS_DIRECTORY/cofferak-<id>` — a private,
non-swappable mount visible only to this unit. `cofferakd` reads it, unwraps
the DEK, and zeroizes the key. The credential name must be exactly
`cofferak-<id>`: it is bound into the sealed blob, and systemd rejects a
mismatch. (Without `$CREDENTIALS_DIRECTORY` the daemon falls back to
unsealing the file itself, which on Linux only works as root.)

### Install

1. Build and install both binaries:

   ```sh
   cargo build --release
   sudo install -m 0755 target/release/cofferakd /usr/local/bin/cofferakd
   sudo install -m 0755 target/release/cofferak  /usr/local/bin/cofferak
   ```

2. Create the service account and the data directory:

   ```sh
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin cofferak
   sudo install -d -m 0700 -o cofferak -g cofferak /var/lib/cofferak
   ```

3. Bootstrap the vault and this host, **as root** (see above). Store the
   root private key `init --root` prints offline, never on this host
   ([key security](key-security.md)):

   ```sh
   HOST_ID="$(hostname -s)"
   sudo cofferak init --root --data-dir /var/lib/cofferak
   sudo cofferak init --host "$HOST_ID" --data-dir /var/lib/cofferak
   ```

4. Install the unit with your host id filled in, and start it:

   ```sh
   sed "s/REPLACE_WITH_HOST_ID/$HOST_ID/g" deployment/linux/cofferakd.service \
     | sudo tee /etc/systemd/system/cofferakd.service >/dev/null
   sudo systemctl daemon-reload
   sudo systemctl enable --now cofferakd
   systemctl status cofferakd
   journalctl -u cofferakd -n 50
   ```

5. Enroll each consuming service (as root, since it unseals the host key),
   then restart the daemon so it loads the new token:

   ```sh
   sudo cofferak enroll-service my-app --paths my-app --perm ro --data-dir /var/lib/cofferak
   sudo systemctl restart cofferakd
   ```

Always provision hosts through `cofferak init --host` / `cofferak enroll-host`
rather than running `systemd-creds encrypt` by hand: the CLI also adds the
matching `vault.hosts` entry, and the daemon refuses to start without it.

This exact layout — root admin commands, a non-root daemon under a real
systemd service receiving its key via `LoadCredentialEncrypted=`, and a
write surviving a daemon restart — is what `scripts/sdk-smoke.sh` runs on
every CI build (Linux).

## macOS (launchd)

The plist template runs `cofferakd` as a per-user LaunchAgent. It is a user
agent, not a system daemon, because the host key is stored in the user's
Keychain (service `cofferak`, account = the host's id — matching
`cofferak init --host`/`enroll-host` exactly), which is only available
inside a user session.

**Known limitation:** macOS Keychain's default access control list only
trusts the application that *created* an item. `cofferak init --host`
(run from the `cofferak` CLI binary) and `cofferakd` (a different binary)
are different applications by that ACL's definition, so `cofferakd`
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
   sudo install -m 0755 target/release/cofferakd /usr/local/bin/cofferakd
   ```

2. Create the data directory and bootstrap the vault and this host:

   ```sh
   mkdir -p "$HOME/Library/Application Support/cofferak"
   cofferak init --root --data-dir "$HOME/Library/Application Support/cofferak"
   cofferak init --host "$(hostname -s)" --data-dir "$HOME/Library/Application Support/cofferak"
   ```

3. Copy the plist and replace every `REPLACE_WITH_USER` with your macOS
   account name. launchd does not expand `~` or `$HOME` inside plist files,
   so the paths must be absolute:

   ```sh
   cp deployment/macos/com.cofferak.cofferakd.plist ~/Library/LaunchAgents/
   open -e ~/Library/LaunchAgents/com.cofferak.cofferakd.plist
   ```

4. Validate the file and load it:

   ```sh
   plutil -lint ~/Library/LaunchAgents/com.cofferak.cofferakd.plist
   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.cofferak.cofferakd.plist
   ```

5. Check that the daemon is running:

   ```sh
   launchctl print gui/$(id -u)/com.cofferak.cofferakd
   ```

To stop and remove the agent:

```sh
launchctl bootout gui/$(id -u)/com.cofferak.cofferakd
```

## Socket permissions

The daemon runs as the unprivileged `cofferak` user, so the socket it creates
is owned by `cofferak:cofferak` with mode `0660`. `cofferakd` enforces this
mode in code after binding. A service that needs access must run as a user in
the `cofferak` group, which the unit's `RuntimeDirectoryMode=0750` allows:

```sh
sudo usermod -aG cofferak <consuming-service-user>
```

Do not make the socket root-owned. The daemon cannot create a root-owned
socket while running as `cofferak`.
