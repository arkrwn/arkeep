# Getting started

A hands-on walkthrough: build cofferak, create a vault, store secrets
(including whole files like SSH keys), read them from the shell and from
each SDK, and see the safety checks work. Everything runs on your own
machine in a throwaway directory. Takes about 15 minutes.

For a permanent installation (systemd unit, launchd agent) see
[deployment.md](deployment.md).

## 0. Requirements

- macOS, or Linux with systemd 250+ (`systemd-creds --version`).
- Rust 1.89+ (`rustup update stable`).
- For the SDK samples: Go 1.24+, Python 3.9+, Node 20+ (any you want to try).

## 1. Build and set up a demo environment

```bash
git clone https://github.com/arkrwn/cofferak && cd cofferak
cargo build --release
export REPO="$PWD"
export PATH="$REPO/target/release:$PATH"
export COFFERAK_DATA_DIR="$HOME/.cofferak-demo"
export COFFERAK_SOCKET="$COFFERAK_DATA_DIR/cofferakd.sock"
mkdir -p "$COFFERAK_DATA_DIR" && chmod 700 "$COFFERAK_DATA_DIR"
```

These `export`s live only in this terminal. Nothing secret goes in
`~/.zshrc`, `~/.bashrc` or any config file: `COFFERAK_DATA_DIR` and
`COFFERAK_SOCKET` are just paths.

Admin commands (`init`, `enroll-*`, `rotate-dek`, `recover`) seal or
unseal the host key. On Linux that needs root (`systemd-creds`); the
files they create are handed back to you automatically. `sudo` drops your
environment and `PATH` (and newer `sudo` versions ignore `-E`), so the
Linux form passes the data directory and the binary's full path
explicitly. Set this once:

```bash
ADMIN=cofferak                              # macOS
ADMIN="sudo env COFFERAK_DATA_DIR=$COFFERAK_DATA_DIR $(command -v cofferak)"   # Linux
```

## 2. Create the vault, enroll this machine and an app

```bash
$ADMIN init --root
```

This prints a block starting with `-----BEGIN COFFERAK ROOT PRIVATE KEY-----`.
It is the **recovery key** for this vault, shown once. For a demo you can
ignore it; for a real vault save the whole block to offline media
([key-security.md](key-security.md)).

```bash
$ADMIN init --host demo
$ADMIN enroll-service myapp --paths myapp --perm rw
```

`init --host` seals this machine's key in the macOS Keychain or with
`systemd-creds`. `enroll-service` prints **myapp's access token** once.
The token lets its holder read and write only paths under `myapp/`.

## 3. Start the daemon

Open a second terminal, repeat the `export` lines from step 1, then:

```bash
# macOS
cofferak daemon
```

```bash
# Linux: the daemon runs as you; systemd decrypts the host key for it
sudo systemd-run --unit=cofferak-demo --uid="$(id -u)" --gid="$(id -g)" \
  -p "LoadCredentialEncrypted=cofferak-demo:$COFFERAK_DATA_DIR/hosts/demo.seal" \
  --setenv=COFFERAK_DATA_DIR="$COFFERAK_DATA_DIR" --setenv=COFFERAK_SOCKET="$COFFERAK_SOCKET" \
  --setenv=COFFERAK_HOST_ID=demo "$(command -v cofferak)" daemon
journalctl -u cofferak-demo -n 5     # check it started
```

Later admin changes (`enroll-service`, `import`) are picked up by the
running daemon automatically; only `rotate-dek` needs a restart.

## 4. Store and read secrets from the shell

Back in the first terminal, give this shell the app's token (it stays in
this shell only):

```bash
read -rs -p "myapp token: " COFFERAK_TOKEN && export COFFERAK_TOKEN; echo
```

**Ways to store a value**, safest first:

```bash
# Typed, hidden: never on screen, in argv or in shell history
read -rs -p "DB password: " V && printf %s "$V" | cofferak set myapp/DB_PASSWORD --stdin; unset V; echo

# From a file, byte for byte (keys, certificates, JSON credentials, .env contents)
cofferak set myapp/ssh/id_ed25519 --from-file ~/.ssh/id_ed25519
cofferak set myapp/gcp-service-account.json --from-file ./service-account.json

# Piped from another command
op read "op://vault/item/password" | cofferak set myapp/OTHER --stdin

# As an argument: only for non-secret test values (visible in `ps` and history)
cofferak set myapp/LOG_LEVEL debug
```

**Reading:**

```bash
cofferak get myapp/DB_PASSWORD                      # print it
cofferak get myapp/ssh/id_ed25519 -o /tmp/key       # write exact bytes to a 0600 file
cofferak get myapp/ssh/id_ed25519 | ssh-add -       # load an SSH key straight into the agent
cofferak list myapp                                 # list paths, never values
cofferak rm myapp/LOG_LEVEL
```

When stdout is a terminal, `get` adds a newline for readability; when
piped or redirected it writes the stored bytes exactly.

Values are encrypted; **path names are not** (they're the vault's index
and appear in the audit log), so never put a secret in a path. Values can
be up to 3 MiB.

## 5. Replace `.env` files and secrets in config

Pass a secret to a program for a single run:

```bash
DB_PASSWORD="$(cofferak get myapp/DB_PASSWORD)" ./your-app
```

Move an existing `.env` file into the vault (quotes, `export`, inline
comments and multi-line values are all understood; `--dry-run` previews):

```bash
cofferak import-env .env --prefix myapp/env
cofferak list myapp/env                     # check, then delete the plaintext file
rm -P .env 2>/dev/null || shred -u .env
```

…and run the app with them, without writing a file (`COFFERAK_TOKEN` is
not passed on to the app):

```bash
cofferak run --prefix myapp/env -- ./your-app
```

Need a `.env` file for a tool that insists on one?
`cofferak export-env --prefix myapp/env -o app.env` (mode 0600).

Use an SSH key that never sits in `~/.ssh` as a file:

```bash
cofferak set myapp/ssh/github --from-file ~/.ssh/id_ed25519_github
cofferak get myapp/ssh/github | ssh-add -     # then delete the file from ~/.ssh
ssh -T git@github.com
```

## 6. Read secrets from code (SDKs)

The SDKs aren't published to package registries yet; use them from the
cloned repo as shown. Each sample reads `COFFERAK_SOCKET` and
`COFFERAK_TOKEN` from the environment, writes a value, reads it back, and
shows that a path outside the token's prefix is denied.

### Python

```python
# app.py — run: PYTHONPATH="$REPO/sdk/python/cofferak_sdk/src" python3 app.py
import os
from cofferak_sdk import Client, DeniedError

client = Client(os.environ["COFFERAK_SOCKET"])
token = os.environ["COFFERAK_TOKEN"]

client.set(token, "myapp/python/API_KEY", b"py-secret-123")
print("python got:", client.get(token, "myapp/python/API_KEY").decode())
print("python list:", client.list(token, "myapp"))
try:
    client.get(token, "other/SECRET")
except DeniedError:
    print("python: other/SECRET correctly denied")
```

### Go

```bash
mkdir demo-go && cd demo-go
cat > go.mod <<EOF
module example.com/cofferak-demo

go 1.24

require github.com/arkrwn/cofferak/sdk/go/cofferak v0.0.0

replace github.com/arkrwn/cofferak/sdk/go/cofferak => $REPO/sdk/go/cofferak
EOF
```

```go
// main.go — run: go run .
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/arkrwn/cofferak/sdk/go/cofferak"
)

func main() {
	client := cofferak.Connect(os.Getenv("COFFERAK_SOCKET"))
	token := os.Getenv("COFFERAK_TOKEN")

	if err := client.Set(token, "myapp/go/API_KEY", []byte("go-secret-123")); err != nil {
		panic(err)
	}
	value, err := client.Get(token, "myapp/go/API_KEY")
	if err != nil {
		panic(err)
	}
	fmt.Println("go got:", string(value))

	_, err = client.Get(token, "other/SECRET")
	var denied cofferak.DeniedError
	if errors.As(err, &denied) {
		fmt.Println("go: other/SECRET correctly denied")
	}
}
```

### Node.js (JavaScript / TypeScript)

```bash
(cd "$REPO/sdk/javascript/cofferak-sdk" && npm install && npm run build)
```

```js
// app.js — run: node app.js
const { Client, DeniedError } = require(process.env.REPO + "/sdk/javascript/cofferak-sdk/dist");

(async () => {
  const client = new Client(process.env.COFFERAK_SOCKET);
  const token = process.env.COFFERAK_TOKEN;

  await client.set(token, "myapp/node/API_KEY", Buffer.from("node-secret-123"));
  console.log("node got:", (await client.get(token, "myapp/node/API_KEY")).toString());
  try {
    await client.get(token, "other/SECRET");
  } catch (e) {
    if (e instanceof DeniedError) console.log("node: other/SECRET correctly denied");
  }
})();
```

### Rust

```toml
# Cargo.toml
[package]
name = "cofferak-demo"
version = "0.1.0"
edition = "2021"

[dependencies]
cofferak-sdk = { path = "/path/to/cofferak/sdk/rust/cofferak-sdk" }
```

```rust
// src/main.rs — run: cargo run
use cofferak_sdk::{Client, SdkError};

fn main() {
    let client = Client::connect(std::env::var("COFFERAK_SOCKET").unwrap());
    let token = std::env::var("COFFERAK_TOKEN").unwrap();

    client.set(&token, "myapp/rust/API_KEY", b"rust-secret-123").unwrap();
    let value = client.get(&token, "myapp/rust/API_KEY").unwrap();
    println!("rust got: {}", String::from_utf8_lossy(&value));

    if let Err(SdkError::Denied) = client.get(&token, "other/SECRET") {
        println!("rust: other/SECRET correctly denied");
    }
}
```

Expected output for each: `<lang> got: <lang>-secret-123` and
`<lang>: other/SECRET correctly denied`. For remote access over mutual
TLS, see each SDK's page under [sample-integration/](sample-integration/).

## 7. Move everything to another machine

```bash
$ADMIN export -o backup.cfk       # asks for a passphrase (14+ characters), twice
# on the new machine, after steps 1–3 there:
$ADMIN import backup.cfk          # secrets and app tokens restored; the daemon picks them up live
```

Works between Linux and macOS. For regular moves between your own
coffers without a passphrase, pair them once (`cofferak identity`,
`cofferak peer add`) and use `cofferak export --to <peer>`. Details,
backups and moving from HashiCorp Vault: [migration.md](migration.md).

## 8. Read-only tokens

Give a deployed app only what it needs:

```bash
$ADMIN enroll-service myapp-prod --paths myapp --perm ro     # live immediately
COFFERAK_TOKEN=<ro token> cofferak get myapp/DB_PASSWORD      # works
COFFERAK_TOKEN=<ro token> cofferak set myapp/X --stdin <<<"x" # access denied
```

## 9. Audit log

```bash
cofferak audit tail --count 20
```

Every request is recorded with its time, service, action, path and
result (`ok`, `denied`, `not_found`). Values are never logged.

## 10. Clean up

```bash
# stop the daemon: Ctrl-C (macOS) or `sudo systemctl stop cofferak-demo` (Linux)
rm -rf "$HOME/.cofferak-demo"
security delete-generic-password -s cofferak -a demo   # macOS only
```

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `could not connect to daemon at ...` | The daemon isn't running, or `COFFERAK_SOCKET` differs between the two terminals. |
| `path must be shorter than SUN_LEN` | Unix socket paths are limited to ~104 characters on macOS; use a shorter `COFFERAK_SOCKET`. |
| `access denied` | Wrong token, path outside the token's prefixes, or a write with a read-only token. |
| Daemon hangs at startup on macOS | You ran `cofferakd` instead of `cofferak daemon`; the Keychain only serves the key silently to the binary that created it ([ADR 0007](adr/0007-macos-keychain-cross-process-limitation.md)). After installing a new build, macOS may ask once: choose Always Allow. |
| `host seal backend rejected input` on Linux | Admin command run without root; use `$ADMIN` as set in step 1. |
| `write could not be persisted` after `rotate-dek` | The daemon still holds the old key; restart it. |
