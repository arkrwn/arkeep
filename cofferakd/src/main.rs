use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cofferak_core::format::{FormatError, VaultFile};
use cofferak_core::seal::{HostSeal, SealedBlob};

#[cfg(target_os = "macos")]
use cofferak_core::seal::KeychainSeal;
#[cfg(target_os = "linux")]
use cofferak_core::seal::SystemdCredsSeal;

use cofferakd::audit::AuditLog;
use cofferakd::daemon::Daemon;
use cofferakd::protocol::{decode_request, encode, Response};

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
    })
}

#[cfg(target_os = "linux")]
fn host_seal() -> SystemdCredsSeal {
    SystemdCredsSeal {
        name: "cofferakd".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn host_seal() -> KeychainSeal {
    KeychainSeal {
        service: "cofferakd".to_string(),
        account: "host-key".to_string(),
    }
}

fn main() {
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

    let seal = host_seal();
    let sealed_path = data_dir.join("host.seal");
    let sealed_bytes = std::fs::read(&sealed_path).unwrap_or_else(|e| {
        eprintln!(
            "cofferakd: could not read sealed host key at {}: {e}",
            sealed_path.display()
        );
        std::process::exit(1);
    });
    let dek = seal.unseal(&SealedBlob(sealed_bytes)).unwrap_or_else(|e| {
        eprintln!("cofferakd: failed to unseal host key: {e}");
        std::process::exit(1);
    });

    let audit_path = data_dir.join("audit.jsonl");
    let audit = AuditLog::open(&audit_path).unwrap_or_else(|e| {
        eprintln!(
            "cofferakd: could not open audit log at {}: {e}",
            audit_path.display()
        );
        std::process::exit(1);
    });

    // Token provisioning (loading the real token store from disk) lands in
    // a later task; start with an empty token map so the daemon still
    // compiles and runs end-to-end, denying every request until tokens are
    // wired in.
    let tokens: BTreeMap<String, cofferak_core::acl::AccessToken> = BTreeMap::new();

    let daemon = Arc::new(Mutex::new(Daemon::new(dek, vault, tokens, audit)));

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

        let (root_pubkey, _root_privkey) = cofferak_core::crypto::generate_root_keypair();
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
