//! `mikvault-cli init --root` / `init --host <id>`.
//!
//! `init --root` creates a brand-new vault: a fresh root X25519 keypair,
//! an empty `VaultFile` (no DEK yet — `root_wrap: None`, `hosts: {}`), and
//! prints the root private key to stdout exactly once so the operator can
//! copy it offline. That key is never written to disk and never logged.
//!
//! `init --host <id>` enrolls a host into an existing vault: on the very
//! first host, it generates the vault's data-encryption key (DEK) and
//! wraps it for the root keypair (`root_wrap`); on any later host, it
//! recovers the existing DEK by unsealing and unwrapping an
//! already-enrolled host's wrap, then wraps that same DEK for the new
//! host. Either way, this host's own unseal key is sealed with the
//! platform [`HostSeal`] backend and persisted under
//! `<data_dir>/hosts/<host_id>.seal`.

use std::fmt;
use std::path::{Path, PathBuf};

use mikvault_core::crypto::{
    generate_root_keypair, unwrap_dek_for_host, wrap_dek_for_host, wrap_dek_for_root, KeyBytes,
};
use mikvault_core::format::{FormatError, VaultFile, VaultMeta};
use mikvault_core::seal::{HostSeal, SealedBlob};

#[cfg(target_os = "linux")]
use mikvault_core::seal::SystemdCredsSeal;
#[cfg(target_os = "macos")]
use mikvault_core::seal::KeychainSeal;

/// Errors produced by the `init` CLI command.
#[derive(Debug)]
pub enum CliError {
    /// An I/O error occurred (also used to wrap a [`SealError`](mikvault_core::seal::SealError)
    /// or [`CryptoError`](mikvault_core::crypto::CryptoError), neither of
    /// which this enum has a dedicated variant for).
    Io(std::io::Error),
    /// The on-disk vault/meta file could not be decoded.
    Format(FormatError),
    /// `init --root` was run against a data dir that already has a vault.
    VaultExists,
    /// `init --host` was run against a data dir with no vault yet.
    VaultMissing,
    /// `init --host` was run with a `host_id` that is already enrolled.
    HostAlreadyEnrolled,
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Io(e) => write!(f, "I/O error: {e}"),
            CliError::Format(e) => write!(f, "vault format error: {e}"),
            CliError::VaultExists => write!(f, "a vault already exists in this data directory"),
            CliError::VaultMissing => {
                write!(f, "no vault found in this data directory; run `init --root` first")
            }
            CliError::HostAlreadyEnrolled => write!(f, "this host is already enrolled"),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CliError::Io(e) => Some(e),
            CliError::Format(e) => Some(e),
            CliError::VaultExists | CliError::VaultMissing | CliError::HostAlreadyEnrolled => None,
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Io(e)
    }
}

impl From<FormatError> for CliError {
    fn from(e: FormatError) -> Self {
        CliError::Format(e)
    }
}

fn vault_path(data_dir: &Path) -> PathBuf {
    data_dir.join("vault.mika")
}

fn meta_path(data_dir: &Path) -> PathBuf {
    data_dir.join("meta.json")
}

fn host_seal_path(data_dir: &Path, host_id: &str) -> PathBuf {
    data_dir.join("hosts").join(format!("{host_id}.seal"))
}

/// Generate a fresh random 32-byte key (used for both the vault DEK and a
/// host's unseal key) using the OS CSPRNG.
fn random_key() -> [u8; 32] {
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Select the real platform [`HostSeal`] backend for `host_id`.
///
/// Follows the same `cfg(target_os = ...)` pattern used by `mikvaultd`'s
/// own `host_seal()` helper, but parameterizes the backend's
/// name/account by `host_id` so distinct hosts enrolled from the same
/// data dir get distinct sealed storage.
// `#[allow(dead_code)]`: this file is also included directly (via
// `#[path]`) into the `cli_init` integration test binary, which only
// exercises `run_init_root`/`run_init_host_with_seal`/`CliError` and
// never references `current_host_seal`/`run_init_host` — those two are
// used by the real `mikvault-cli` binary's `main.rs`.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub fn current_host_seal(host_id: &str) -> Box<dyn HostSeal> {
    Box::new(SystemdCredsSeal {
        name: format!("mikvault-{host_id}"),
    })
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub fn current_host_seal(host_id: &str) -> Box<dyn HostSeal> {
    Box::new(KeychainSeal {
        service: "mikvault".to_string(),
        account: host_id.to_string(),
    })
}

/// Create a brand-new vault at `data_dir`: a fresh root X25519 keypair, an
/// empty `VaultFile` (`root_wrap: None`, no hosts/services), and
/// `meta.json`.
///
/// The root *private* key is printed to stdout exactly once, clearly
/// labeled for the operator to copy offline — it is never written to any
/// file and never logged anywhere else. On success, returns the root
/// public key's fingerprint (matching `VaultMeta::root_pubkey_fingerprint`)
/// so callers/tests can confirm it without re-deriving it themselves.
///
/// Returns `Err(CliError::VaultExists)` without touching any existing
/// file if `data_dir/vault.mika` already exists.
pub fn run_init_root(data_dir: &Path) -> Result<String, CliError> {
    std::fs::create_dir_all(data_dir)?;

    let vpath = vault_path(data_dir);
    if vpath.exists() {
        return Err(CliError::VaultExists);
    }

    let (root_pubkey, root_privkey) = generate_root_keypair();
    let root_privkey = KeyBytes::new(root_privkey);

    let vault = VaultFile::new(root_pubkey);
    let meta = VaultMeta::from_vault(&vault);

    vault.save(&vpath)?;
    meta.save(&meta_path(data_dir))?;

    let hex_privkey: String = root_privkey.iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "=== MIKVAULT ROOT PRIVATE KEY — copy this offline now, it will not be shown again ==="
    );
    println!("{hex_privkey}");
    println!(
        "======================================================================================"
    );

    Ok(meta.root_pubkey_fingerprint)
}

/// Enroll `host_id` into the vault at `data_dir`, using `seal` as the
/// `HostSeal` backend (injected so tests can use an in-memory fake instead
/// of the real platform backend).
///
/// - Returns `Err(CliError::VaultMissing)` if `data_dir` has no vault yet
///   (i.e. `init --root` was never run).
/// - Returns `Err(CliError::HostAlreadyEnrolled)` if `host_id` is already
///   in `vault.hosts`.
/// - On the first host (vault has zero hosts), generates a fresh DEK and
///   sets `vault.root_wrap`.
/// - On any later host, recovers the existing DEK by unsealing and
///   unwrapping an already-enrolled host's wrap.
/// - Either way, generates a fresh unseal key for this host, seals it via
///   `seal`, persists the sealed blob under
///   `data_dir/hosts/<host_id>.seal`, wraps the DEK for this host, and
///   updates `vault.mika` + `meta.json`.
pub fn run_init_host_with_seal(
    data_dir: &Path,
    host_id: &str,
    seal: &dyn HostSeal,
) -> Result<(), CliError> {
    let vpath = vault_path(data_dir);
    if !vpath.exists() {
        return Err(CliError::VaultMissing);
    }

    let mut vault = VaultFile::load(&vpath)?;

    if vault.hosts.contains_key(host_id) {
        return Err(CliError::HostAlreadyEnrolled);
    }

    let dek: [u8; 32] = if vault.hosts.is_empty() {
        let dek = random_key();
        vault.root_wrap = Some(wrap_dek_for_root(&dek, &vault.root_pubkey));
        dek
    } else {
        // Recover the existing DEK via any already-enrolled host's wrap.
        let (existing_id, existing_wrap) = vault
            .hosts
            .iter()
            .next()
            .map(|(id, wrap)| (id.clone(), wrap.clone()))
            .expect("checked non-empty above");

        let sealed_bytes = std::fs::read(host_seal_path(data_dir, &existing_id))?;
        let existing_host_key = seal
            .unseal(&SealedBlob(sealed_bytes))
            .map_err(|e| CliError::Io(std::io::Error::other(e)))?;

        unwrap_dek_for_host(&existing_wrap, &existing_host_key)
            .map_err(|e| CliError::Io(std::io::Error::other(e)))?
    };

    let host_key = random_key();
    let sealed = seal
        .seal(&host_key)
        .map_err(|e| CliError::Io(std::io::Error::other(e)))?;

    std::fs::create_dir_all(data_dir.join("hosts"))?;
    std::fs::write(host_seal_path(data_dir, host_id), &sealed.0)?;

    vault
        .hosts
        .insert(host_id.to_string(), wrap_dek_for_host(&dek, &host_key));

    vault.save(&vpath)?;
    let meta = VaultMeta::from_vault(&vault);
    meta.save(&meta_path(data_dir))?;

    Ok(())
}

/// Thin wrapper around [`run_init_host_with_seal`] that picks the real
/// platform [`HostSeal`] backend for `host_id` via [`current_host_seal`].
#[allow(dead_code)]
pub fn run_init_host(data_dir: &Path, host_id: &str) -> Result<(), CliError> {
    let seal = current_host_seal(host_id);
    run_init_host_with_seal(data_dir, host_id, seal.as_ref())
}
