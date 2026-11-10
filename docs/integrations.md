# Integration examples

Working examples of consuming cofferak from a service. All flags here match
`cofferak-cli/src/main.rs` exactly — see `cofferak --help` / `cofferak
<command> --help` if this drifts.

## 1. One-time setup: root key, first host, a consuming service

```bash
# Once, by the creator, on their own machine or the first host:
cofferak init --root --data-dir /var/lib/cofferak
# prints the root private key ONCE — copy it offline now, it is never shown again

cofferak init --host --host my-server-01 --data-dir /var/lib/cofferak

# Enroll a consuming service and capture its one-time token:
cofferak enroll-service myapp --paths myapp --perm rw --data-dir /var/lib/cofferak
# prints a hex token ONCE — deliver it to that service the same sealed
# way you deliver the host unseal key (systemd LoadCredentialEncrypted /
# launchd + Keychain), never as a plaintext env var in a committed file.
```

## 2. A consuming service's systemd unit

The service never talks to cofferak as a library — it's a CLI/socket
client. A typical unit delivers the token via a sealed credential and
reads it at startup:

```ini
[Service]
LoadCredentialEncrypted=myapp_cofferak_token:/etc/myapp/cofferak-token.cred
Environment=COFFERAK_SOCKET=/run/cofferak/cofferakd.sock
ExecStart=/usr/local/bin/myapp-start-wrapper.sh
```

```bash
#!/usr/bin/env bash
# myapp-start-wrapper.sh
set -euo pipefail
export COFFERAK_TOKEN="$(cat "$CREDENTIALS_DIRECTORY/myapp_cofferak_token")"
exec /usr/local/bin/myapp
```

## 3. Reading a secret from a shell script

```bash
export COFFERAK_TOKEN="<the enrolled service's token>"
export COFFERAK_SOCKET="/run/cofferak/cofferakd.sock"

OPENAI_API_KEY="$(cofferak get myapp/OPENAI_API_KEY)"
```

## 4. Writing a secret (admin operation, same token model)

```bash
cofferak set myapp/OPENAI_API_KEY "sk-..." --token "$COFFERAK_TOKEN"
```

A token's `--perm ro` grant will reject a `set`/`rm` with
`Err(CliError::Denied)` — grant `--perm rw` at enrollment time if the
service needs to write, not just read.

## 5. Listing what a token can see

```bash
cofferak list myapp --token "$COFFERAK_TOKEN"
```

## 6. Minimal Rust client (raw socket, no SDK crate yet)

There is no published client library crate today — `cofferak-cli`'s own
`cofferak-cli/src/client.rs` is the reference implementation (newline-
delimited JSON over a Unix socket; see `cofferakd/src/protocol.rs` for the
wire types). A service that wants to talk to cofferak from Rust directly,
rather than shelling out to the `cofferak` binary, can copy that pattern:

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

For anything beyond a quick prototype, shell out to the `cofferak` binary
instead (examples 3-5) — it's the maintained, tested path.

## 7. Disaster recovery (new host, lost host key)

```bash
# On the creator's own offline machine, with the exported root private key:
cofferak recover --root-key ./root.key --new-host my-server-02 --data-dir /var/lib/cofferak
```

Any failure here (wrong key, missing vault) leaves `vault.cofferak`
byte-for-byte unchanged — safe to retry.

## 8. Checking what happened (audit)

```bash
cofferak audit tail --count 50 --data-dir /var/lib/cofferak
```
