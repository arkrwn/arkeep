# Sample integration: shell / CLI

## 1. One-time setup: root key, first host, a consuming service

```bash
# Once, by the creator, on the first host. On Linux these need root
# (systemd-creds' host scope is root-only; see docs/adr/0009).
sudo arkeep init --root --data-dir /var/lib/arkeep
# prints the root private key ONCE — copy it offline now, it is never shown again

sudo arkeep init --host my-server-01 --data-dir /var/lib/arkeep

# Enroll a consuming service and capture its one-time token, then restart
# the daemon so it loads the new token:
sudo arkeep enroll-service myapp --paths myapp --perm rw --data-dir /var/lib/arkeep
sudo systemctl restart arkeepd
# prints a hex token ONCE — deliver it to that service the same sealed
# way you deliver the host unseal key (systemd LoadCredentialEncrypted /
# launchd + Keychain), never as a plaintext env var in a committed file.
```

If the vault has more than one enrolled host, `arkeepd` needs
`$ARKEEP_HOST_ID` set to know which host's sealed key to use — see
[`docs/deployment.md`](../deployment.md).

## 2. A consuming service's systemd unit

```ini
[Service]
LoadCredentialEncrypted=myapp_arkeep_token:/etc/myapp/arkeep-token.cred
Environment=ARKEEP_SOCKET=/run/arkeep/arkeepd.sock
ExecStart=/usr/local/bin/myapp-start-wrapper.sh
```

```bash
#!/usr/bin/env bash
# myapp-start-wrapper.sh
set -euo pipefail
export ARKEEP_TOKEN="$(cat "$CREDENTIALS_DIRECTORY/myapp_arkeep_token")"
exec /usr/local/bin/myapp
```

## 3. Reading a secret from a shell script

```bash
export ARKEEP_TOKEN="<the enrolled service's token>"
export ARKEEP_SOCKET="/run/arkeep/arkeepd.sock"

OPENAI_API_KEY="$(arkeep get myapp/OPENAI_API_KEY)"
```

## 4. Writing a secret

```bash
arkeep set myapp/OPENAI_API_KEY "sk-..." --token "$ARKEEP_TOKEN"
```

A `--perm ro` token rejects `set`/`rm` with `Err(CliError::Denied)` —
grant `--perm rw` at enrollment time if the service needs to write.

## 5. Listing what a token can see

```bash
arkeep list myapp --token "$ARKEEP_TOKEN"
```

## 6. Disaster recovery

```bash
# On the creator's own offline machine, with the exported root private key:
arkeep recover --root-key ./root.key --new-host my-server-02 --data-dir /var/lib/arkeep
```

Any failure here (wrong key, missing vault) leaves `vault.arkeep`
byte-for-byte unchanged — safe to retry. See
[`docs/recovery-runbook.md`](../recovery-runbook.md).

## 7. Audit

```bash
arkeep audit tail --count 50 --data-dir /var/lib/arkeep
```
