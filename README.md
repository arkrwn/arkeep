<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/cofferak-logo-dark.svg">
    <img src="docs/assets/cofferak-logo.svg" alt="cofferak" width="260">
  </picture>
</p>

<p align="center">
  <strong>A military-grade, superfast coffer for your secrets and credentials.</strong><br>
  CNSA 2.0 algorithms · post-quantum recovery key · mutual TLS 1.3 · 0.24 µs decrypt · sub-millisecond reads<br>
  Self-hosted on Linux and macOS. No external server, cloud KMS or account.
</p>

<p align="center">
  <a href="https://github.com/arkrwn/cofferak/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/arkrwn/cofferak/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="Cargo.toml"><img alt="Version" src="https://img.shields.io/badge/version-0.1.0-264233.svg"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <img alt="Rust 1.89+" src="https://img.shields.io/badge/rust-1.89%2B-C75126.svg?logo=rust">
  <img alt="Platforms: Linux | macOS" src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-264233.svg">
  <a href="docs/adr/0011-cnsa-grade-crypto-and-hardened-transport.md"><img alt="Crypto: CNSA 2.0 algorithms, post-quantum" src="https://img.shields.io/badge/crypto-CNSA%202.0%20%7C%20post--quantum-264233.svg"></a>
  <a href="docs/adr/0011-cnsa-grade-crypto-and-hardened-transport.md"><img alt="Server mode: TLS 1.3 + mandatory mTLS" src="https://img.shields.io/badge/server%20mode-TLS%201.3%20%2B%20mandatory%20mTLS-264233.svg"></a>
  <a href="docs/benchmarks.md"><img alt="Benchmarks" src="https://img.shields.io/badge/decrypt-0.24%20%C2%B5s-C75126.svg"></a>
  <img alt="SDKs: Rust, Go, Python, TypeScript" src="https://img.shields.io/badge/SDKs-Rust%20%7C%20Go%20%7C%20Python%20%7C%20TypeScript-C75126.svg">
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> ·
  <a href="docs/overview.md">How it works</a> ·
  <a href="docs/commands.md">Commands</a> ·
  <a href="docs/sdks.md">SDKs</a> ·
  <a href="docs/server-mode.md">Server mode</a> ·
  <a href="docs/deployment.md">Deployment</a> ·
  <a href="docs/backup.md">Backup</a> ·
  <a href="docs/SPEC.md">Spec</a>
</p>

---

**cofferak** keeps application secrets (API keys, database passwords,
tokens, SSH keys) in one encrypted file and serves them to your services
through a small daemon. The key that opens the vault is sealed by the
operating system (`systemd-creds` and the TPM2 on Linux, the Keychain on
macOS), so there is never a plaintext master key on disk. Each service
gets its own token, limited to the paths and permissions you grant it.

- **Strong crypto:** CNSA 2.0 algorithms, a post-quantum recovery key,
  TLS 1.3 with mandatory mutual TLS for remote access.
- **Fast:** reads in well under a millisecond, 0.24 µs to decrypt a value.
- **Hard to misuse:** edits and rollbacks of the vault file are detected,
  tokens never go on the command line, admin commands on macOS need Touch
  ID, backups stay encrypted.
- **Easy to adopt:** import a `.env` file, run your app with
  `cofferak run`, or use the Rust, Go, Python and TypeScript SDKs.

## Quickstart

Try it locally in about five minutes. You need Rust 1.89 or newer
([rustup.rs](https://rustup.rs)), macOS or Linux with systemd.

**1. Build and point your shell at a throwaway vault**

```bash
git clone https://github.com/arkrwn/cofferak && cd cofferak
cargo build --release
export PATH="$PWD/target/release:$PATH"
export COFFERAK_DATA_DIR="$HOME/.cofferak-demo"
export COFFERAK_SOCKET="$COFFERAK_DATA_DIR/cofferakd.sock"
mkdir -p "$COFFERAK_DATA_DIR" && chmod 700 "$COFFERAK_DATA_DIR"
```

**2. Create the vault and enroll this machine**

```bash
ADMIN=cofferak                                    # macOS
ADMIN="sudo env COFFERAK_DATA_DIR=$COFFERAK_DATA_DIR $(command -v cofferak)"   # Linux: sealing needs root

$ADMIN init --root            # prints the root private key ONCE: save the whole
                              # -----BEGIN/END----- block offline (it's your recovery key)
$ADMIN init --host demo       # seals this machine's key (Keychain / systemd-creds)
$ADMIN enroll-service myapp --paths myapp --perm rw
                              # prints myapp's access token ONCE
                              # (macOS asks for Touch ID or your password: admin
                              # commands need you, not just any program you run)
```

**3. Start the daemon** (in a second terminal, with the same `export`s)

```bash
# macOS
cofferak daemon

# Linux: run it the way production does, as you (not root), with systemd
# handing it the host key (copy as-is):
sudo systemd-run --unit=cofferak-demo --uid="$(id -u)" --gid="$(id -g)" \
  -p "LoadCredentialEncrypted=cofferak-demo:$COFFERAK_DATA_DIR/hosts/demo.seal" \
  --setenv=COFFERAK_DATA_DIR="$COFFERAK_DATA_DIR" --setenv=COFFERAK_SOCKET="$COFFERAK_SOCKET" \
  --setenv=COFFERAK_HOST_ID=demo "$(command -v cofferak)" daemon
```

**4. Store and read secrets**

```bash
export COFFERAK_TOKEN=<token printed by enroll-service>   # this shell only

# Type a secret without it touching the screen, argv or shell history:
read -rs -p "DB password: " V && printf %s "$V" | cofferak set myapp/DB_PASSWORD --stdin; unset V
cofferak get myapp/DB_PASSWORD

# Store a whole file, byte for byte (an SSH key, a certificate, a JSON credential):
cofferak set myapp/ssh/id_ed25519 --from-file ~/.ssh/id_ed25519
cofferak get myapp/ssh/id_ed25519 | ssh-add -      # load it into ssh-agent
cofferak list myapp
cofferak get other/thing                           # denied: outside myapp's paths
```

**5. Replace your `.env` file**

```bash
cofferak import-env .env --prefix myapp/env       # parses quotes, export, comments, multi-line values
cofferak run --prefix myapp/env -- ./your-app      # app gets the variables; no file on disk
rm .env
```

or read secrets in code with an [SDK](docs/sdks.md). To clean up: stop the daemon
(Ctrl-C, or `sudo systemctl stop cofferak-demo` on Linux) and
`rm -rf ~/.cofferak-demo`, on macOS also
`security delete-generic-password -s cofferak -a demo` and
`security delete-generic-password -s cofferak-anchor -a demo`.

A step-by-step walkthrough of every command, the SDKs and the failure
cases is in [docs/getting-started.md](docs/getting-started.md). For a
permanent install (systemd unit, launchd agent) see
[docs/deployment.md](docs/deployment.md).

## Documentation

| | |
|---|---|
| [Overview](docs/overview.md) | What cofferak is, why, and how it works |
| [Getting started](docs/getting-started.md) | Every command step by step, with failure cases |
| [Commands](docs/commands.md) | Full CLI reference, import, export and migrate |
| [SDKs](docs/sdks.md) | Rust, Go, Python, TypeScript and JavaScript |
| [Server mode](docs/server-mode.md) | Remote access over TLS 1.3 with mutual TLS |
| [Deployment](docs/deployment.md) | systemd and launchd, environment variables |
| [Backup](docs/backup.md) | Backups, health checks, restore |
| [Migration](docs/migration.md) | From `.env`, HashiCorp Vault, or between machines |
| [Security](docs/key-security.md) | Protecting the root key, [recovery runbook](docs/recovery-runbook.md), [comparison](docs/comparison.md) |
| [Spec](docs/SPEC.md) and [ADRs](docs/adr/README.md) | Design, file format, protocol, decisions |
| [Development](docs/development.md) | Repository layout, building and testing, contributing |

The same pages are built into a documentation site with MkDocs (see
[`mkdocs.yml`](mkdocs.yml)): `pip install -r docs/requirements.txt && mkdocs serve`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions require accepting
the project's CLA ([CLA.md](CLA.md)) on your first pull request.

## License

Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). The
`cofferak` name and logo are governed separately by the
[trademark policy](TRADEMARK.md): the license covers the code, not the
name.
