# Deploying mikvaultd

This document covers running `mikvaultd` as a background service on Linux
(systemd) and macOS (launchd). Two copy-and-edit templates ship in
`deployment/`:

| Platform | Template | Installed to |
|----------|----------|--------------|
| Linux (systemd) | `deployment/linux/mikvaultd.service` | `/etc/systemd/system/mikvaultd.service` |
| macOS (launchd) | `deployment/macos/com.mikvault.mikvaultd.plist` | `~/Library/LaunchAgents/com.mikvault.mikvaultd.plist` |

The templates are starting points. Adjust paths, user names and the binary
location to match your machine before installing them.

## Environment variables

`mikvaultd` reads two environment variables at startup. Both are optional;
if they are unset, the daemon falls back to the per-OS default shown below.

| Variable | Purpose | Linux default | macOS default |
|----------|---------|---------------|---------------|
| `MIKVAULT_DATA_DIR` | Directory holding `vault.mika`, `host.seal` and `audit.jsonl` | `/var/lib/mikvault` | `~/Library/Application Support/mikvault` |
| `MIKVAULT_SOCKET` | Path of the Unix socket the daemon listens on | `/run/mikvault/mikvaultd.sock` | `~/Library/Application Support/mikvault/mikvaultd.sock` |

The templates set both variables explicitly. The Linux template uses
`/run/mikvault/mikvault.sock`, which differs from the built-in fallback
(`/run/mikvault/mikvaultd.sock`). When you change one, change the matching
client configuration too.

The daemon will refuse to start if `vault.mika` is missing or corrupt, and
if `host.seal` is missing or cannot be unsealed. It does not create an empty
vault in either case.

## Linux (systemd)

The unit template:

- runs `mikvaultd` as an unprivileged `mikvault` user;
- sets `MIKVAULT_DATA_DIR` and `MIKVAULT_SOCKET`;
- uses `RuntimeDirectory=mikvault` to create `/run/mikvault` for the socket,
  and `StateDirectory=mikvault` to create `/var/lib/mikvault` for the data;
- loads the sealed host key with `LoadCredentialEncrypted=`;
- restarts the daemon on failure and applies basic hardening.

### Install

1. Build and install the binary:

   ```sh
   cargo build --release
   sudo install -m 0755 target/release/mikvaultd /usr/local/bin/mikvaultd
   ```

2. Create the service account:

   ```sh
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin mikvault
   ```

3. Install the unit and reload systemd:

   ```sh
   sudo install -m 0644 deployment/linux/mikvaultd.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

4. Place the vault files in the data directory (`/var/lib/mikvault`) and make
   them owned by `mikvault`. Keep `host.seal` and `vault.mika` in this
   directory.

5. Start the service and check its status:

   ```sh
   sudo systemctl enable --now mikvaultd
   systemctl status mikvaultd
   journalctl -u mikvaultd -n 50
   ```

### Sealed host key

The host key is sealed with `systemd-creds` and delivered through
`LoadCredentialEncrypted=mikvault_host_key:/etc/mikvault/host.cred`.
Create the sealed file once on the target host, for example:

```sh
sudo install -d -m 0700 /etc/mikvault
sudo systemd-creds encrypt --name=mikvault_host_key - /etc/mikvault/host.cred
```

Read the caveat in [Known gaps](#known-gaps) before relying on this path.

## macOS (launchd)

The plist template runs `mikvaultd` as a per-user LaunchAgent. It is a user
agent, not a system daemon, because the host key is stored in the user's
Keychain, which is only available inside a user session.

The template sets `RunAtLoad` so the daemon starts at login, and
`KeepAlive` so launchd restarts it if it exits.

### Install

1. Build and install the binary:

   ```sh
   cargo build --release
   sudo install -m 0755 target/release/mikvaultd /usr/local/bin/mikvaultd
   ```

2. Create the data directory:

   ```sh
   mkdir -p "$HOME/Library/Application Support/mikvault"
   ```

3. Copy the plist and replace every `REPLACE_WITH_USER` with your macOS
   account name. launchd does not expand `~` or `$HOME` inside plist files,
   so the paths must be absolute:

   ```sh
   cp deployment/macos/com.mikvault.mikvaultd.plist ~/Library/LaunchAgents/
   open -e ~/Library/LaunchAgents/com.mikvault.mikvaultd.plist
   ```

4. Validate the file and load it:

   ```sh
   plutil -lint ~/Library/LaunchAgents/com.mikvault.mikvaultd.plist
   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.mikvault.mikvaultd.plist
   ```

5. Check that the daemon is running:

   ```sh
   launchctl print gui/$(id -u)/com.mikvault.mikvaultd
   ```

To stop and remove the agent:

```sh
launchctl bootout gui/$(id -u)/com.mikvault.mikvaultd
```

## Known gaps

- **Linux credential delivery is not yet wired into the daemon.** The Linux
  seal backend (`mikvault-core`, `SystemdCredsSeal`) reads the sealed
  `host.seal` file from `MIKVAULT_DATA_DIR` and calls
  `systemd-creds decrypt --name=mikvaultd`. It does not read
  `$CREDENTIALS_DIRECTORY/mikvault_host_key`. The `LoadCredentialEncrypted=`
  line in the unit therefore does not feed the daemon yet, and the credential
  name in the unit (`mikvault_host_key`) does not match the name the daemon
  binds into the seal (`mikvaultd`). Until this is reconciled, the unit will
  start the daemon, but unsealing will fail unless `host.seal` was produced
  with the name the daemon expects.
- **Socket permissions are not set by the daemon.** The design calls for mode
  `0600`, owner `root:mikvault` on Linux. `mikvaultd` binds the socket with
  the default umask, so restrict access through the unit's `UMask=` or the
  data and runtime directory modes until the daemon sets them itself.
