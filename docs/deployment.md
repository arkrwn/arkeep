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

The templates set `COFFERAK_DATA_DIR`/`COFFERAK_SOCKET` explicitly, using the
same socket filename (`cofferakd.sock`) as the built-in fallback. When you
change the socket path, change the matching client configuration too. If
you enroll more than one host into the same vault (`cofferak enroll-host`),
add `Environment=COFFERAK_HOST_ID=<id>` to the unit/plist as well.

The daemon will refuse to start if `vault.cofferak` is missing or corrupt, if
this host's sealed key file under `hosts/` is missing or cannot be
unsealed, or if this host's `id` isn't actually enrolled in `vault.cofferak`
(a sealed file existing on disk with no matching `vault.hosts` entry is
treated as an error, not ignored). It does not create an empty vault in
any of these cases.

## Linux (systemd)

The unit template:

- runs `cofferakd` as an unprivileged `cofferak` user;
- sets `COFFERAK_DATA_DIR` and `COFFERAK_SOCKET`;
- uses `RuntimeDirectory=cofferak` to create `/run/cofferak` for the socket,
  and `StateDirectory=cofferak` to create `/var/lib/cofferak` for the data;
- restarts the daemon on failure and applies basic hardening.

The daemon reads the sealed host key directly from
`$COFFERAK_DATA_DIR/hosts/<host-id>.seal` (produced by `cofferak init --host`
or `cofferak enroll-host` — see [Sealed host key](#sealed-host-key)). The
unit does not deliver the key itself.

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

4. Create the data directory and its ownership first — `cofferak init`
   needs somewhere to write — then bootstrap the vault and this host
   (see [Sealed host key](#sealed-host-key) for what this actually does):

   ```sh
   sudo mkdir -p /var/lib/cofferak
   sudo chown -R cofferak:cofferak /var/lib/cofferak
   sudo -u cofferak cofferak init --root --data-dir /var/lib/cofferak
   sudo -u cofferak cofferak init --host "$(hostname)" --data-dir /var/lib/cofferak
   ```

5. Start the service and check its status:

   ```sh
   sudo systemctl enable --now cofferakd
   systemctl status cofferakd
   journalctl -u cofferakd -n 50
   ```

### Sealed host key

`cofferak init --host <id>` (step 4 above) does two things together, and
both are required: it seals this host's unseal key with `systemd-creds`
under `$COFFERAK_DATA_DIR/hosts/<id>.seal`, named `systemd-creds
--name=cofferak-<id>` internally, *and* it adds a matching entry for `<id>`
to `vault.hosts`. `cofferakd` needs both — a sealed file with no matching
`vault.hosts` entry (or vice versa) fails to start, by design (see the
Environment variables section above). This is why there's no standalone
"just run `systemd-creds encrypt` by hand" step here: always provision a
host through `cofferak init --host`/`cofferak enroll-host`, never
`systemd-creds` directly.

If you do need to inspect or re-create the raw seal manually for
debugging, the exact command `cofferak init --host` runs is:

```sh
sudo systemd-creds encrypt --name="cofferak-<id>" - "/var/lib/cofferak/hosts/<id>.seal"
```

— but note this alone does **not** add the matching `vault.hosts` entry;
use the CLI for real provisioning.

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
