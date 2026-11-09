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

`cofferakd` reads two environment variables at startup. Both are optional;
if they are unset, the daemon falls back to the per-OS default shown below.

| Variable | Purpose | Linux default | macOS default |
|----------|---------|---------------|---------------|
| `COFFERAK_DATA_DIR` | Directory holding `vault.cofferak`, `host.seal` and `audit.jsonl` | `/var/lib/cofferak` | `~/Library/Application Support/cofferak` |
| `COFFERAK_SOCKET` | Path of the Unix socket the daemon listens on | `/run/cofferak/cofferakd.sock` | `~/Library/Application Support/cofferak/cofferakd.sock` |

The templates set both variables explicitly, using the same socket filename
(`cofferakd.sock`) as the built-in fallback. When you change the socket path,
change the matching client configuration too.

The daemon will refuse to start if `vault.cofferak` is missing or corrupt, and
if `host.seal` is missing or cannot be unsealed. It does not create an empty
vault in either case.

## Linux (systemd)

The unit template:

- runs `cofferakd` as an unprivileged `cofferak` user;
- sets `COFFERAK_DATA_DIR` and `COFFERAK_SOCKET`;
- uses `RuntimeDirectory=cofferak` to create `/run/cofferak` for the socket,
  and `StateDirectory=cofferak` to create `/var/lib/cofferak` for the data;
- restarts the daemon on failure and applies basic hardening.

The daemon reads the sealed host key directly from `$COFFERAK_DATA_DIR/host.seal`.
The unit does not deliver the key itself.

### Install

1. Build and install the binary:

   ```sh
   cargo build --release
   sudo install -m 0755 target/release/cofferakd /usr/local/bin/cofferakd
   ```

2. Create the service account:

   ```sh
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin cofferak
   ```

3. Install the unit and reload systemd:

   ```sh
   sudo install -m 0644 deployment/linux/cofferakd.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

4. Create the sealed host key and the vault files in the data directory
   (`/var/lib/cofferak`). See [Sealed host key](#sealed-host-key). Make the
   directory and its contents owned by `cofferak`:

   ```sh
   sudo chown -R cofferak:cofferak /var/lib/cofferak
   ```

5. Start the service and check its status:

   ```sh
   sudo systemctl enable --now cofferakd
   systemctl status cofferakd
   journalctl -u cofferakd -n 50
   ```

### Sealed host key

The host unseal key is sealed with `systemd-creds` and stored as
`$COFFERAK_DATA_DIR/host.seal`. `cofferakd` reads that file and unseals it with
`systemd-creds decrypt --name=cofferakd`, so the seal must be created with the
same name. Create it once on the target host, with the data directory in place:

```sh
sudo systemd-creds encrypt --name=cofferakd - /var/lib/cofferak/host.seal
```

The `--name=cofferakd` value must match the `name` that `cofferakd`'s
Linux seal uses (`SystemdCredsSeal { name: "cofferakd" }` in
`cofferakd/src/main.rs`). A different name makes unsealing fail.

## macOS (launchd)

The plist template runs `cofferakd` as a per-user LaunchAgent. It is a user
agent, not a system daemon, because the host key is stored in the user's
Keychain, which is only available inside a user session.

The template sets `RunAtLoad` so the daemon starts at login, and
`KeepAlive` so launchd restarts it if it exits.

### Install

1. Build and install the binary:

   ```sh
   cargo build --release
   sudo install -m 0755 target/release/cofferakd /usr/local/bin/cofferakd
   ```

2. Create the data directory:

   ```sh
   mkdir -p "$HOME/Library/Application Support/cofferak"
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
