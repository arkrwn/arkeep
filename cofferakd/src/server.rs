use std::collections::BTreeMap;
use std::io::{BufReader, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cofferak_core::crypto::{decrypt_entry, unwrap_dek_for_host, Aad, KeyBytes};
use cofferak_core::format::{FormatError, VaultFile};
use cofferak_core::seal::{HostSeal, SealedBlob};

#[cfg(target_os = "macos")]
use cofferak_core::seal::KeychainSeal;
#[cfg(target_os = "linux")]
use cofferak_core::seal::SystemdCredsSeal;

use crate::audit::AuditLog;
use crate::daemon::{token_key, Daemon};
use crate::protocol::{decode_request, encode, Response};

/// Default data directory on Linux, used unless `$COFFERAK_DATA_DIR` is set.
#[cfg(target_os = "linux")]
fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/cofferak")
}

/// Default data directory on macOS, used unless `$COFFERAK_DATA_DIR` is set.
#[cfg(target_os = "macos")]
fn default_data_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
    PathBuf::from(home).join("Library/Application Support/cofferak")
}

/// Default Unix socket path on Linux, used unless `$COFFERAK_SOCKET` is set.
#[cfg(target_os = "linux")]
fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/cofferak/cofferakd.sock")
}

/// Default Unix socket path on macOS, used unless `$COFFERAK_SOCKET` is set.
#[cfg(target_os = "macos")]
fn default_socket_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
    PathBuf::from(home).join("Library/Application Support/cofferak/cofferakd.sock")
}

fn data_dir() -> PathBuf {
    std::env::var_os("COFFERAK_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(default_data_dir)
}

fn socket_path() -> PathBuf {
    std::env::var_os("COFFERAK_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(default_socket_path)
}

/// Load the vault at `data_dir/vault.cofferak`.
///
/// Returns `Err` with a clear message on any failure — missing file, I/O
/// error, or a corrupt/truncated file — instead of panicking or silently
/// falling back to a freshly-initialized empty vault. This is the testable
/// core of vault loading; `main` wraps it with the thin `exit`-on-failure
/// logic below so this function itself never terminates the process.
pub fn load_vault_or_exit(data_dir: &Path) -> Result<VaultFile, String> {
    let path = data_dir.join("vault.cofferak");
    VaultFile::load(&path).map_err(|e| match e {
        FormatError::Io(io_err) => {
            format!("could not read vault file at {}: {io_err}", path.display())
        }
        FormatError::Corrupt => format!(
            "vault file at {} is corrupt or truncated; refusing to start",
            path.display()
        ),
        e @ FormatError::UnsupportedVersion(_) => {
            format!("vault file at {}: {e}; refusing to start", path.display())
        }
    })
}

/// Build the `HostSeal` backend for `host_id`. **Must match
/// `cofferak-cli/src/commands/init.rs`'s `current_host_seal(host_id)`
/// exactly** — the daemon and the CLI are sealing/unsealing the same
/// per-host blob under the same OS-level identity (Keychain
/// service/account, or `systemd-creds` credential name), so a mismatch
/// here means the daemon can never unseal what `init --host`/
/// `enroll-host` sealed.
#[cfg(target_os = "linux")]
fn host_seal(host_id: &str) -> SystemdCredsSeal {
    SystemdCredsSeal {
        name: format!("cofferak-{host_id}"),
    }
}

#[cfg(target_os = "macos")]
fn host_seal(host_id: &str) -> KeychainSeal {
    KeychainSeal {
        service: "cofferak".to_string(),
        account: host_id.to_string(),
    }
}

/// Which host this daemon process is running as. `$COFFERAK_HOST_ID` if
/// set; otherwise, if the vault has exactly one enrolled host, that one
/// (the common single-host case needs no extra configuration); otherwise
/// an error naming every enrolled host so the operator can set the env
/// var explicitly. The result is validated (`acl::validate_id`) because it
/// is used to build a file path and a credential name.
fn resolve_host_id(vault: &VaultFile) -> Result<String, String> {
    let id = match std::env::var("COFFERAK_HOST_ID") {
        Ok(id) if !id.is_empty() => id,
        _ => {
            let mut ids: Vec<&String> = vault.hosts.keys().collect();
            match ids.len() {
                0 => {
                    return Err(
                        "this vault has no enrolled hosts yet; run `cofferak init --host` first"
                            .into(),
                    )
                }
                1 => ids.remove(0).clone(),
                _ => {
                    return Err(format!(
                        "this vault has multiple enrolled hosts ({}); set $COFFERAK_HOST_ID to the one this process runs as",
                        ids.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                    ))
                }
            }
        }
    };
    cofferak_core::acl::validate_id("host", &id)?;
    Ok(id)
}

/// The systemd credential name carrying this host's key. Identical to the
/// `--name=` the CLI passes to `systemd-creds encrypt` when sealing it, so
/// `LoadCredentialEncrypted=cofferak-<host_id>:<data_dir>/hosts/<host_id>.seal`
/// in the unit decrypts it under the name it was sealed with.
fn credential_name(host_id: &str) -> String {
    format!("cofferak-{host_id}")
}

/// Obtain this host's unseal key (ADR 0009).
///
/// 1. **Production (systemd):** if `$CREDENTIALS_DIRECTORY` contains
///    `cofferak-<host_id>`, read it. systemd decrypted it *as root* from the
///    sealed blob named in `LoadCredentialEncrypted=` and placed the
///    plaintext on a private, unit-only tmpfs before dropping to
///    `User=cofferak` — so this unprivileged daemon never needs access to
///    `systemd-creds`'s root-only host secret.
/// 2. **Fallback:** unseal `hosts/<host_id>.seal` directly through the
///    platform `HostSeal` (Keychain on macOS; on Linux this shells out to
///    `systemd-creds decrypt`, which requires root for host-scope
///    credentials — so on Linux this path is for manual/root use only).
fn load_host_key(host_id: &str, data_dir: &Path) -> Result<KeyBytes, String> {
    if let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY") {
        let cred_path = PathBuf::from(dir).join(credential_name(host_id));
        if cred_path.exists() {
            let bytes = std::fs::read(&cred_path)
                .map_err(|e| format!("could not read {}: {e}", cred_path.display()))?;
            let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                format!(
                    "systemd credential {} is {} bytes, expected 32 — was it sealed by `cofferak init --host`?",
                    credential_name(host_id),
                    bytes.len()
                )
            })?;
            return Ok(KeyBytes::new(key));
        }
    }

    let sealed_path = data_dir.join("hosts").join(format!("{host_id}.seal"));
    let sealed_bytes = std::fs::read(&sealed_path).map_err(|e| {
        format!(
            "could not read sealed host key at {}: {e}",
            sealed_path.display()
        )
    })?;
    host_seal(host_id)
        .unseal(&SealedBlob(sealed_bytes))
        .map(KeyBytes::new)
        .map_err(|e| {
            let hint = if cfg!(target_os = "linux") {
                format!(
                    " — under systemd, deliver it with `LoadCredentialEncrypted={}:{}` \
                     (see docs/deployment.md); a direct `systemd-creds decrypt` needs root",
                    credential_name(host_id),
                    sealed_path.display()
                )
            } else {
                String::new()
            };
            format!("failed to unseal this host's key: {e}{hint}")
        })
}

/// Decrypt and deserialize every enrolled service's `AccessToken` out of
/// `vault.services`, keyed for [`Daemon`] by [`token_key`] (the wire
/// token string clients send). A service entry that fails to
/// decrypt/deserialize is skipped with a warning rather than aborting
/// startup over one bad entry — mirroring the audit log's "skip the
/// malformed line, keep the rest" philosophy.
fn load_tokens(
    vault: &VaultFile,
    dek: &[u8; 32],
) -> BTreeMap<String, cofferak_core::acl::AccessToken> {
    let mut tokens = BTreeMap::new();
    for (service_id, entry) in &vault.services {
        let plaintext = match decrypt_entry(dek, &Aad::service_token(service_id), entry) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!(
                    "cofferakd: could not decrypt token for service '{service_id}': {e}, skipping it"
                );
                continue;
            }
        };
        let token: cofferak_core::acl::AccessToken = match bincode::deserialize(&plaintext) {
            Ok(token) => token,
            Err(e) => {
                eprintln!(
                    "cofferakd: could not decode token for service '{service_id}': {e}, skipping it"
                );
                continue;
            }
        };
        tokens.insert(token_key(&token.secret), token);
    }
    tokens
}

/// Run the daemon until the process is killed: load the vault, obtain this
/// host's key, unwrap the DEK, then serve the Unix socket (and the TLS
/// listener when server mode is configured). Configuration comes from the
/// `COFFERAK_*` environment variables (see `docs/deployment.md`). Exits
/// the process with a clear message on any startup failure.
///
/// Shared by the `cofferakd` binary and `cofferak daemon`. On macOS run
/// it as `cofferak daemon`: the host key lives in a Keychain item created
/// by the `cofferak` binary, and the Keychain lets the creating binary read
/// it back without an authorization prompt (ADR 0007).
pub fn run() {
    let data_dir = data_dir();

    // Thin wrapper: `load_vault_or_exit` itself only ever returns `Result`;
    // this is the one place that turns a load failure into a process exit.
    let vault = match load_vault_or_exit(&data_dir) {
        Ok(vault) => vault,
        Err(msg) => {
            eprintln!("cofferakd: {msg}");
            std::process::exit(1);
        }
    };

    let host_id = resolve_host_id(&vault).unwrap_or_else(|msg| {
        eprintln!("cofferakd: {msg}");
        std::process::exit(1);
    });

    let host_wrap = vault.hosts.get(&host_id).cloned().unwrap_or_else(|| {
        eprintln!("cofferakd: host '{host_id}' is not enrolled in this vault");
        std::process::exit(1);
    });
    let dek = {
        // `host_key` is zeroized when this block ends: it is only needed to
        // unwrap the DEK, never kept for the life of the process.
        let host_key = load_host_key(&host_id, &data_dir).unwrap_or_else(|msg| {
            eprintln!("cofferakd: {msg}");
            std::process::exit(1);
        });
        unwrap_dek_for_host(&host_wrap, &host_id, &host_key).unwrap_or_else(|e| {
            eprintln!("cofferakd: failed to unwrap this vault's DEK for host '{host_id}': {e}");
            std::process::exit(1);
        })
    };

    let audit_path = data_dir.join("audit.jsonl");
    let audit = AuditLog::open(&audit_path).unwrap_or_else(|e| {
        eprintln!(
            "cofferakd: could not open audit log at {}: {e}",
            audit_path.display()
        );
        std::process::exit(1);
    });

    let tokens = load_tokens(&vault, &dek);

    // Durable (ADR 0010): every set/rm is written to vault.cofferak before it
    // is acknowledged.
    let daemon = Arc::new(Mutex::new(
        Daemon::new(dek, vault, tokens, audit).with_persistence(
            data_dir.join("vault.cofferak"),
            host_id.clone(),
            host_wrap,
        ),
    ));

    // Server mode (ADR 0008): additive, opt-in via $COFFERAK_TLS_ADDR. The
    // Unix socket below is unaffected either way.
    match crate::tls_server::resolve() {
        Ok(Some(tls_config)) => crate::tls_server::start(tls_config, Arc::clone(&daemon)),
        Ok(None) => {}
        Err(msg) => {
            eprintln!("cofferakd: {msg}");
            std::process::exit(1);
        }
    }

    let sock_path = socket_path();
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path).unwrap_or_else(|e| {
        eprintln!(
            "cofferakd: could not bind socket at {}: {e}",
            sock_path.display()
        );
        std::process::exit(1);
    });
    // Enforce the socket mode in code rather than relying on the ambient umask.
    if let Err(e) = std::fs::set_permissions(
        &sock_path,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o660),
    ) {
        eprintln!(
            "cofferakd: could not set permissions on socket at {}: {e}",
            sock_path.display()
        );
        std::process::exit(1);
    }

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let daemon = Arc::clone(&daemon);
        std::thread::spawn(move || handle_connection(stream, daemon));
    }
}

/// Serve one client connection: read newline-delimited JSON requests,
/// dispatch each through `Daemon::handle_request` under the shared mutex,
/// and write back the newline-delimited JSON response.
fn handle_connection(stream: UnixStream, daemon: Arc<Mutex<Daemon>>) {
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let mut writer = stream;
    let mut line = Vec::new();

    loop {
        // Bounded, not `read_until`: an unbounded read lets a client
        // that never sends `\n` grow this buffer without limit. Unix
        // socket clients are local/trusted, but the daemon uses one
        // consistent, audited cap (`protocol::MAX_LINE_BYTES`) across
        // every transport rather than a per-transport exception.
        match crate::protocol::read_line_bounded(&mut reader, &mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(_) => break,
        }
        if line.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }

        let response = match decode_request(&line) {
            Ok(req) => daemon.lock().unwrap().handle_request(req),
            Err(_) => Response::Err("malformed request".to_string()),
        };

        if writer.write_all(&encode(&response)).is_err() {
            break;
        }
    }

    let _ = writer.shutdown(Shutdown::Both);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "cofferakd-main-test-{}-{}-{}-{tag}",
            std::process::id(),
            nanos,
            n
        ))
    }

    #[test]
    fn load_vault_or_exit_returns_err_when_file_missing() {
        let dir = temp_dir("missing");
        let result = load_vault_or_exit(&dir);
        assert!(result.is_err());
    }

    #[test]
    fn load_vault_or_exit_returns_err_on_truncated_file_not_fresh_vault() {
        let dir = temp_dir("truncated");
        std::fs::create_dir_all(&dir).expect("create temp dir");

        let (root_pubkey, _root_privkey) = cofferak_core::crypto::generate_root_keypair().unwrap();
        let vault = VaultFile::new(root_pubkey);
        let path = dir.join("vault.cofferak");
        vault.save(&path).expect("save fixture vault");

        let mut bytes = std::fs::read(&path).expect("read fixture vault");
        assert!(
            bytes.len() > 10,
            "fixture must be larger than the truncation"
        );
        bytes.truncate(bytes.len() - 10);
        std::fs::write(&path, &bytes).expect("write truncated vault");

        let result = load_vault_or_exit(&dir);

        // Must be an error, never a panic and never a freshly-initialized
        // vault returned as if nothing were wrong.
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
