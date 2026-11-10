# Sample integration: shell / CLI

## 1. One-time setup: root key, first host, a consuming service

```bash
# Once, by the creator, on their own machine or the first host:
mikavt init --root --data-dir /var/lib/mikavt
# prints the root private key ONCE — copy it offline now, it is never shown again

mikavt init --host my-server-01 --data-dir /var/lib/mikavt

# Enroll a consuming service and capture its one-time token:
mikavt enroll-service azmika --paths azmika --perm rw --data-dir /var/lib/mikavt
# prints a hex token ONCE — deliver it to that service the same sealed
# way you deliver the host unseal key (systemd LoadCredentialEncrypted /
# launchd + Keychain), never as a plaintext env var in a committed file.
```

If the vault has more than one enrolled host, `mikavtd` needs
`$MIKAVT_HOST_ID` set to know which host's sealed key to use — see
[`docs/deployment.md`](../deployment.md).

## 2. A consuming service's systemd unit

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

## 4. Writing a secret

```bash
mikavt set azmika/OPENAI_API_KEY "sk-..." --token "$MIKAVT_TOKEN"
```

A `--perm ro` token rejects `set`/`rm` with `Err(CliError::Denied)` —
grant `--perm rw` at enrollment time if the service needs to write.

## 5. Listing what a token can see

```bash
mikavt list azmika --token "$MIKAVT_TOKEN"
```

## 6. Disaster recovery

```bash
# On the creator's own offline machine, with the exported root private key:
mikavt recover --root-key ./root.key --new-host my-server-02 --data-dir /var/lib/mikavt
```

Any failure here (wrong key, missing vault) leaves `vault.mika`
byte-for-byte unchanged — safe to retry. See
[`docs/recovery-runbook.md`](../recovery-runbook.md).

## 7. Audit

```bash
mikavt audit tail --count 50 --data-dir /var/lib/mikavt
```
