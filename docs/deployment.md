# Deploying mikavtd

This document covers running `mikavtd` as a background service on Linux
(systemd) and macOS (launchd). Two copy-and-edit templates ship in
`deployment/`:

| Platform | Template | Installed to |
|----------|----------|--------------|
| Linux (systemd) | `deployment/linux/mikavtd.service` | `/etc/systemd/system/mikavtd.service` |
| macOS (launchd) | `deployment/macos/com.mikavt.mikavtd.plist` | `~/Library/LaunchAgents/com.mikavt.mikavtd.plist` |

The templates are starting points. Adjust paths, user names and the binary
location to match your machine before installing them.

## Environment variables

`mikavtd` reads two environment variables at startup. Both are optional;
if they are unset, the daemon falls back to the per-OS default shown below.

| Variable | Purpose | Linux default | macOS default |
|----------|---------|---------------|---------------|
| `MIKAVT_DATA_DIR` | Directory holding `vault.mika`, `host.seal` and `audit.jsonl` | `/var/lib/mikavt` | `~/Library/Application Support/mikavt` |
| `MIKAVT_SOCKET` | Path of the Unix socket the daemon listens on | `/run/mikavt/mikavtd.sock` | `~/Library/Application Support/mikavt/mikavtd.sock` |

The templates set both variables explicitly, using the same socket filename
(`mikavtd.sock`) as the built-in fallback. When you change the socket path,
change the matching client configuration too.

The daemon will refuse to start if `vault.mika` is missing or corrupt, and
if `host.seal` is missing or cannot be unsealed. It does not create an empty
vault in either case.

## Linux (systemd)

The unit template:

- runs `mikavtd` as an unprivileged `mikavt` user;
- sets `MIKAVT_DATA_DIR` and `MIKAVT_SOCKET`;
- uses `RuntimeDirectory=mikavt` to create `/run/mikavt` for the socket,
  and `StateDirectory=mikavt` to create `/var/lib/mikavt` for the data;
- restarts the daemon on failure and applies basic hardening.

The daemon reads the sealed host key directly from `$MIKAVT_DATA_DIR/host.seal`.
The unit does not deliver the key itself.

### Install

1. Build and install the binary:

   ```sh
   cargo build --release
   sudo install -m 0755 target/release/mikavtd /usr/local/bin/mikavtd
   ```

2. Create the service account:

   ```sh
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin mikavt
   ```

3. Install the unit and reload systemd:

   ```sh
   sudo install -m 0644 deployment/linux/mikavtd.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

4. Create the sealed host key and the vault files in the data directory
   (`/var/lib/mikavt`). See [Sealed host key](#sealed-host-key). Make the
   directory and its contents owned by `mikavt`:

   ```sh
   sudo chown -R mikavt:mikavt /var/lib/mikavt
   ```

5. Start the service and check its status:

   ```sh
   sudo systemctl enable --now mikavtd
   systemctl status mikavtd
   journalctl -u mikavtd -n 50
   ```

### Sealed host key

The host unseal key is sealed with `systemd-creds` and stored as
`$MIKAVT_DATA_DIR/host.seal`. `mikavtd` reads that file and unseals it with
`systemd-creds decrypt --name=mikavtd`, so the seal must be created with the
same name. Create it once on the target host, with the data directory in place:

```sh
sudo systemd-creds encrypt --name=mikavtd - /var/lib/mikavt/host.seal
```

The `--name=mikavtd` value must match the `name` that `mikavtd`'s
Linux seal uses (`SystemdCredsSeal { name: "mikavtd" }` in
`mikavtd/src/main.rs`). A different name makes unsealing fail.

## macOS (launchd)

The plist template runs `mikavtd` as a per-user LaunchAgent. It is a user
agent, not a system daemon, because the host key is stored in the user's
Keychain, which is only available inside a user session.

The template sets `RunAtLoad` so the daemon starts at login, and
`KeepAlive` so launchd restarts it if it exits.

### Install

1. Build and install the binary:

   ```sh
   cargo build --release
   sudo install -m 0755 target/release/mikavtd /usr/local/bin/mikavtd
   ```

2. Create the data directory:

   ```sh
   mkdir -p "$HOME/Library/Application Support/mikavt"
   ```

3. Copy the plist and replace every `REPLACE_WITH_USER` with your macOS
   account name. launchd does not expand `~` or `$HOME` inside plist files,
   so the paths must be absolute:

   ```sh
   cp deployment/macos/com.mikavt.mikavtd.plist ~/Library/LaunchAgents/
   open -e ~/Library/LaunchAgents/com.mikavt.mikavtd.plist
   ```

4. Validate the file and load it:

   ```sh
   plutil -lint ~/Library/LaunchAgents/com.mikavt.mikavtd.plist
   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.mikavt.mikavtd.plist
   ```

5. Check that the daemon is running:

   ```sh
   launchctl print gui/$(id -u)/com.mikavt.mikavtd
   ```

To stop and remove the agent:

```sh
launchctl bootout gui/$(id -u)/com.mikavt.mikavtd
```

## Socket permissions

The daemon runs as the unprivileged `mikavt` user, so the socket it creates
is owned by `mikavt:mikavt` with mode `0660`. `mikavtd` enforces this
mode in code after binding. A service that needs access must run as a user in
the `mikavt` group, which the unit's `RuntimeDirectoryMode=0750` allows:

```sh
sudo usermod -aG mikavt <consuming-service-user>
```

Do not make the socket root-owned. The daemon cannot create a root-owned
socket while running as `mikavt`.
