use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use mikavt_core::crypto::{decrypt_entry, unwrap_dek_for_host};
use mikavt_core::format::{FormatError, VaultFile};
use mikavt_core::seal::{HostSeal, SealedBlob};

#[cfg(target_os = "macos")]
use mikavt_core::seal::KeychainSeal;
#[cfg(target_os = "linux")]
use mikavt_core::seal::SystemdCredsSeal;

use mikavtd::audit::AuditLog;
use mikavtd::daemon::{token_key, Daemon};
use mikavtd::protocol::{decode_request, encode, Response};

/// Default data directory on Linux, used unless `$MIKAVT_DATA_DIR` is set.
#[cfg(target_os = "linux")]
fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/mikavt")
}

/// Default data directory on macOS, used unless `$MIKAVT_DATA_DIR` is set.
#[cfg(target_os = "macos")]
fn default_data_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
    PathBuf::from(home).join("Library/Application Support/mikavt")
}

/// Default Unix socket path on Linux, used unless `$MIKAVT_SOCKET` is set.
#[cfg(target_os = "linux")]
fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/mikavt/mikavtd.sock")
}

/// Default Unix socket path on macOS, used unless `$MIKAVT_SOCKET` is set.
#[cfg(target_os = "macos")]
fn default_socket_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
    PathBuf::from(home).join("Library/Application Support/mikavt/mikavtd.sock")
}

fn data_dir() -> PathBuf {
    std::env::var_os("MIKAVT_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(default_data_dir)
}

fn socket_path() -> PathBuf {
    std::env::var_os("MIKAVT_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(default_socket_path)
}

/// Load the vault at `data_dir/vault.mika`.
///
/// Returns `Err` with a clear message on any failure — missing file, I/O
/// error, or a corrupt/truncated file — instead of panicking or silently
/// falling back to a freshly-initialized empty vault. This is the testable
/// core of vault loading; `main` wraps it with the thin `exit`-on-failure
/// logic below so this function itself never terminates the process.
pub fn load_vault_or_exit(data_dir: &Path) -> Result<VaultFile, String> {
    let path = data_dir.join("vault.mika");
    VaultFile::load(&path).map_err(|e| match e {
        FormatError::Io(io_err) => {
            format!("could not read vault file at {}: {io_err}", path.display())
        }
        FormatError::Corrupt => format!(
            "vault file at {} is corrupt or truncated; refusing to start",
            path.display()
        ),
    })
}

/// Build the `HostSeal` backend for `host_id`. **Must match
/// `mikavt-cli/src/commands/init.rs`'s `current_host_seal(host_id)`
/// exactly** — the daemon and the CLI are sealing/unsealing the same
/// per-host blob under the same OS-level identity (Keychain
/// service/account, or `systemd-creds` credential name), so a mismatch
/// here means the daemon can never unseal what `init --host`/
/// `enroll-host` sealed.
#[cfg(target_os = "linux")]
fn host_seal(host_id: &str) -> SystemdCredsSeal {
    SystemdCredsSeal {
        name: format!("mikavt-{host_id}"),
    }
}

#[cfg(target_os = "macos")]
fn host_seal(host_id: &str) -> KeychainSeal {
    KeychainSeal {
        service: "mikavt".to_string(),
        account: host_id.to_string(),
    }
}

/// Which host this daemon process is running as. `$MIKAVT_HOST_ID` if
/// set; otherwise, if the vault has exactly one enrolled host, that one
/// (the common single-host case needs no extra configuration); otherwise
/// an error naming every enrolled host so the operator can set the env
/// var explicitly.
fn resolve_host_id(vault: &VaultFile) -> Result<String, String> {
    if let Ok(id) = std::env::var("MIKAVT_HOST_ID") {
        if !id.is_empty() {
            return Ok(id);
        }
    }
    let mut ids: Vec<&String> = vault.hosts.keys().collect();
    match ids.len() {
        0 => Err("this vault has no enrolled hosts yet; run `mikavt init --host` first".into()),
        1 => Ok(ids.remove(0).clone()),
        _ => Err(format!(
            "this vault has multiple enrolled hosts ({}); set $MIKAVT_HOST_ID to the one this process runs as",
            ids.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        )),
    }
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
) -> BTreeMap<String, mikavt_core::acl::AccessToken> {
    let mut tokens = BTreeMap::new();
    for (service_id, entry) in &vault.services {
        let plaintext = match decrypt_entry(dek, entry) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!(
                    "mikavtd: could not decrypt token for service '{service_id}': {e}, skipping it"
                );
                continue;
            }
        };
        let token: mikavt_core::acl::AccessToken = match bincode::deserialize(&plaintext) {
            Ok(token) => token,
            Err(e) => {
                eprintln!(
                    "mikavtd: could not decode token for service '{service_id}': {e}, skipping it"
                );
                continue;
            }
        };
        tokens.insert(token_key(&token.secret), token);
    }
    tokens
}

fn main() {
    let data_dir = data_dir();

    // Thin wrapper: `load_vault_or_exit` itself only ever returns `Result`;
    // this is the one place that turns a load failure into a process exit.
    let vault = match load_vault_or_exit(&data_dir) {
        Ok(vault) => vault,
        Err(msg) => {
            eprintln!("mikavtd: {msg}");
            std::process::exit(1);
        }
    };

    let host_id = resolve_host_id(&vault).unwrap_or_else(|msg| {
        eprintln!("mikavtd: {msg}");
        std::process::exit(1);
    });

    let seal = host_seal(&host_id);
    let sealed_path = data_dir.join("hosts").join(format!("{host_id}.seal"));
    let sealed_bytes = std::fs::read(&sealed_path).unwrap_or_else(|e| {
        eprintln!(
            "mikavtd: could not read sealed host key at {}: {e}",
            sealed_path.display()
        );
        std::process::exit(1);
    });
    let host_key = seal.unseal(&SealedBlob(sealed_bytes)).unwrap_or_else(|e| {
        eprintln!("mikavtd: failed to unseal this host's key: {e}");
        std::process::exit(1);
    });
    let host_wrap = vault.hosts.get(&host_id).unwrap_or_else(|| {
        eprintln!(
            "mikavtd: host '{host_id}' has a sealed key file but is not enrolled in this vault"
        );
        std::process::exit(1);
    });
    let dek = unwrap_dek_for_host(host_wrap, &host_key).unwrap_or_else(|e| {
        eprintln!("mikavtd: failed to unwrap this vault's DEK for host '{host_id}': {e}");
        std::process::exit(1);
    });

    let audit_path = data_dir.join("audit.jsonl");
    let audit = AuditLog::open(&audit_path).unwrap_or_else(|e| {
        eprintln!(
            "mikavtd: could not open audit log at {}: {e}",
            audit_path.display()
        );
        std::process::exit(1);
    });

    let tokens = load_tokens(&vault, &dek);

    let daemon = Arc::new(Mutex::new(Daemon::new(dek, vault, tokens, audit)));

    let sock_path = socket_path();
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path).unwrap_or_else(|e| {
        eprintln!(
            "mikavtd: could not bind socket at {}: {e}",
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
            "mikavtd: could not set permissions on socket at {}: {e}",
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
        line.clear();
        match reader.read_until(b'\n', &mut line) {
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
            "mikavtd-main-test-{}-{}-{}-{tag}",
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

        let (root_pubkey, _root_privkey) = mikavt_core::crypto::generate_root_keypair();
        let vault = VaultFile::new(root_pubkey);
        let path = dir.join("vault.mika");
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
