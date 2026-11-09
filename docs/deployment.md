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

The templates set both variables explicitly, using the same socket filename
(`mikvaultd.sock`) as the built-in fallback. When you change the socket path,
change the matching client configuration too.

The daemon will refuse to start if `vault.mika` is missing or corrupt, and
if `host.seal` is missing or cannot be unsealed. It does not create an empty
vault in either case.

## Linux (systemd)

The unit template:

- runs `mikvaultd` as an unprivileged `mikvault` user;
- sets `MIKVAULT_DATA_DIR` and `MIKVAULT_SOCKET`;
- uses `RuntimeDirectory=mikvault` to create `/run/mikvault` for the socket,
  and `StateDirectory=mikvault` to create `/var/lib/mikvault` for the data;
- restarts the daemon on failure and applies basic hardening.

The daemon reads the sealed host key directly from `$MIKVAULT_DATA_DIR/host.seal`.
The unit does not deliver the key itself.

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

4. Create the sealed host key and the vault files in the data directory
   (`/var/lib/mikvault`). See [Sealed host key](#sealed-host-key). Make the
   directory and its contents owned by `mikvault`:

   ```sh
   sudo chown -R mikvault:mikvault /var/lib/mikvault
   ```

5. Start the service and check its status:

   ```sh
   sudo systemctl enable --now mikvaultd
   systemctl status mikvaultd
   journalctl -u mikvaultd -n 50
   ```

### Sealed host key

The host unseal key is sealed with `systemd-creds` and stored as
`$MIKVAULT_DATA_DIR/host.seal`. `mikvaultd` reads that file and unseals it with
`systemd-creds decrypt --name=mikvaultd`, so the seal must be created with the
same name. Create it once on the target host, with the data directory in place:

```sh
sudo systemd-creds encrypt --name=mikvaultd - /var/lib/mikvault/host.seal
```

The `--name=mikvaultd` value must match the `name` that `mikvaultd`'s
Linux seal uses (`SystemdCredsSeal { name: "mikvaultd" }` in
`mikvaultd/src/main.rs`). A different name makes unsealing fail.

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

## Socket permissions

The daemon runs as the unprivileged `mikvault` user, so the socket it creates
is owned by `mikvault:mikvault` with mode `0660`. `mikvaultd` enforces this
mode in code after binding. A service that needs access must run as a user in
the `mikvault` group, which the unit's `RuntimeDirectoryMode=0750` allows:

```sh
sudo usermod -aG mikvault <consuming-service-user>
```

Do not make the socket root-owned. The daemon cannot create a root-owned
socket while running as `mikvault`.
