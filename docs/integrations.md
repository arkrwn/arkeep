# Integration examples

Working examples of consuming mikavt from a service. All flags here match
`mikavt-cli/src/main.rs` exactly — see `mikavt --help` / `mikavt
<command> --help` if this drifts.

## 1. One-time setup: root key, first host, a consuming service

```bash
# Once, by the creator, on their own machine or the first host:
mikavt init --root --data-dir /var/lib/mikavt
# prints the root private key ONCE — copy it offline now, it is never shown again

mikavt init --host --host my-server-01 --data-dir /var/lib/mikavt

# Enroll a consuming service and capture its one-time token:
mikavt enroll-service azmika --paths azmika --perm rw --data-dir /var/lib/mikavt
# prints a hex token ONCE — deliver it to that service the same sealed
# way you deliver the host unseal key (systemd LoadCredentialEncrypted /
# launchd + Keychain), never as a plaintext env var in a committed file.
```

## 2. A consuming service's systemd unit

The service never talks to mikavt as a library — it's a CLI/socket
client. A typical unit delivers the token via a sealed credential and
reads it at startup:

```ini
[Service]
LoadCredentialEncrypted=azmika_mikavt_token:/etc/azmika/mikavt-token.cred
Environment=MIKAVT_SOCKET=/run/mikavt/mikavtd.sock
ExecStart=/usr/local/bin/azmika-start-wrapper.sh
```

```bash
#!/usr/bin/env bash
# azmika-start-wrapper.sh
set -euo pipefail
export MIKAVT_TOKEN="$(cat "$CREDENTIALS_DIRECTORY/azmika_mikavt_token")"
exec /usr/local/bin/azmika
```

## 3. Reading a secret from a shell script

```bash
export MIKAVT_TOKEN="<the enrolled service's token>"
export MIKAVT_SOCKET="/run/mikavt/mikavtd.sock"

OPENAI_API_KEY="$(mikavt get azmika/OPENAI_API_KEY)"
```

## 4. Writing a secret (admin operation, same token model)

```bash
mikavt set azmika/OPENAI_API_KEY "sk-..." --token "$MIKAVT_TOKEN"
```

A token's `--perm ro` grant will reject a `set`/`rm` with
`Err(CliError::Denied)` — grant `--perm rw` at enrollment time if the
service needs to write, not just read.

## 5. Listing what a token can see

```bash
mikavt list azmika --token "$MIKAVT_TOKEN"
```

## 6. Minimal Rust client (raw socket, no SDK crate yet)

There is no published client library crate today — `mikavt-cli`'s own
`mikavt-cli/src/client.rs` is the reference implementation (newline-
delimited JSON over a Unix socket; see `mikavtd/src/protocol.rs` for the
wire types). A service that wants to talk to mikavt from Rust directly,
rather than shelling out to the `mikavt` binary, can copy that pattern:

```rust
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

fn get_secret(socket_path: &str, token: &str, path: &str) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(socket_path)?;
    let request = serde_json::json!({
        "Get": { "token": token, "path": path }
    });
    writeln!(stream, "{request}")?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let response: serde_json::Value = serde_json::from_str(&line)?;
    // response is one of: {"Value": [..bytes..]}, "Denied", "NotFound", {"Err": "..."}
    Ok(line)
}
```

For anything beyond a quick prototype, shell out to the `mikavt` binary
instead (examples 3-5) — it's the maintained, tested path.

## 7. Disaster recovery (new host, lost host key)

```bash
# On the creator's own offline machine, with the exported root private key:
mikavt recover --root-key ./root.key --new-host my-server-02 --data-dir /var/lib/mikavt
```

Any failure here (wrong key, missing vault) leaves `vault.mika`
byte-for-byte unchanged — safe to retry.

## 8. Checking what happened (audit)

```bash
mikavt audit tail --count 50 --data-dir /var/lib/mikavt
```
