//! `cofferak-cli init --root` / `init --host <id>`.
//!
//! `init --root` creates a brand-new vault: a fresh root X25519 keypair,
//! an empty `VaultFile` (no DEK yet — `root_wrap: None`, `hosts: {}`), and
//! prints the root private key to stdout exactly once so the operator can
//! copy it offline. That key is never written to disk and never logged.
//!
//! `init --host <id>` enrolls the *first* host into an existing vault: it
//! generates the vault's data-encryption key (DEK), wraps it for the root
//! keypair (`root_wrap`), generates this host's unseal key, seals it with
//! the platform [`HostSeal`] backend, and wraps the DEK for this host.
//! This host's sealed unseal key is persisted under
//! `<data_dir>/hosts/<host_id>.seal`.
//!
//! Enrolling an *additional* host into a vault that already has one is
//! deliberately out of scope here and returns
//! `Err(CliError::RootWrapAlreadySet)`: doing that correctly requires
//! unsealing the already-enrolled host's own key with *that host's* seal
//! backend and sealing the new host's key with the *new* host's backend —
//! two distinct `HostSeal`s. This function's signature only accepts one
//! `seal`, which is structurally the wrong shape for that operation (on
//! name-bound backends like `systemd-creds`, unsealing an existing host's
//! blob with a seal constructed for a different host_id simply fails).
//! That two-seal operation is Task 12's `run_enroll_host_with_seal`.

use std::fmt;
use std::path::{Path, PathBuf};

use cofferak_core::crypto::{
    generate_root_keypair, wrap_dek_for_host, wrap_dek_for_root, KeyBytes,
};
use cofferak_core::format::{FormatError, VaultFile, VaultMeta};
use cofferak_core::seal::HostSeal;

#[cfg(target_os = "macos")]
use cofferak_core::seal::KeychainSeal;
#[cfg(target_os = "linux")]
use cofferak_core::seal::SystemdCredsSeal;

/// Errors produced by the `init` CLI command.
#[derive(Debug)]
pub enum CliError {
    /// An I/O error occurred (also used to wrap a [`SealError`](cofferak_core::seal::SealError)
    /// or [`CryptoError`](cofferak_core::crypto::CryptoError), neither of
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
    /// `init --host` was run against a vault that already has
    /// `root_wrap: Some(_)` (i.e. a host is already enrolled) and a
    /// *different* `host_id` than any already enrolled. Adding an
    /// additional host to an already-initialized vault is Task 12's
    /// `run_enroll_host_with_seal` (which takes both the existing host's
    /// seal and the new host's seal), not `init --host` — see the module
    /// doc comment for why a single-seal signature can't do this safely.
    RootWrapAlreadySet,
    /// A referenced `host_id` is not present in `vault.hosts` — used by
    /// Task 12's `run_enroll_host_with_seal` when `this_host_id` isn't
    /// actually enrolled, and by `run_enroll_service`'s internal lookup
    /// when no enrolled host's sealed blob can be unsealed with this
    /// machine's real platform `HostSeal` backend. Task 13's
    /// `run_rotate_dek` reuses this same variant when none of its given
    /// `(host_id, seal)` pairs are both unseal-able and actually enrolled.
    HostNotFound,
    /// Task 13: the daemon denied a `Get`/`Set`/`Rm`/`List` request
    /// (unknown token, wrong permission level, or a path outside the
    /// token's granted prefixes). Never constructed from a silently-empty
    /// value — every denial takes this explicit path.
    Denied,
    /// Task 13: the daemon reported `Response::NotFound` for a `Get` or
    /// `Rm` whose path has no entry.
    NotFound,
    /// Task 13: the daemon reported `Response::Err(msg)`, or sent back a
    /// response shape the caller wasn't expecting for that request kind.
    Remote(String),
    /// Task 14: `recover --root-key <path>` was given a key file that is
    /// not exactly 32 bytes, or whose bytes do not unwrap
    /// `VaultFile.root_wrap` (the wrong keypair, or random garbage).
    BadRootKey,
    /// Bad user input or an unusable file (a `.env` syntax error, a wrong
    /// bundle passphrase, ...), with a message that says what to fix.
    Invalid(String),
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
            CliError::RootWrapAlreadySet => write!(
                f,
                "vault already has a host enrolled; use `enroll` to add another host, not `init --host`"
            ),
            CliError::HostNotFound => write!(f, "no matching enrolled host found"),
            CliError::Denied => write!(f, "access denied"),
            CliError::NotFound => write!(f, "not found"),
            CliError::Remote(msg) => write!(f, "daemon error: {msg}"),
            CliError::BadRootKey => write!(
                f,
                "root key file is not a valid cofferak root private key (armored block from `init --root`), or does not match this vault's root public key"
            ),
            CliError::Invalid(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CliError::Io(e) => Some(e),
            CliError::Format(e) => Some(e),
            CliError::VaultExists
            | CliError::VaultMissing
            | CliError::HostAlreadyEnrolled
            | CliError::RootWrapAlreadySet
            | CliError::HostNotFound
            | CliError::Denied
            | CliError::NotFound
            | CliError::Remote(_)
            | CliError::BadRootKey
            | CliError::Invalid(_) => None,
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

// These four helpers are `pub(crate)` (not just module-private) so Task
// 12's `commands::enroll` can reuse them instead of duplicating the
// path/key-generation conventions established here.

pub(crate) fn vault_path(data_dir: &Path) -> PathBuf {
    data_dir.join("vault.cofferak")
}

pub(crate) fn meta_path(data_dir: &Path) -> PathBuf {
    data_dir.join("meta.json")
}

pub(crate) fn host_seal_path(data_dir: &Path, host_id: &str) -> PathBuf {
    data_dir.join("hosts").join(format!("{host_id}.seal"))
}

/// Generate a fresh random 32-byte key (used for both the vault DEK and a
/// host's unseal key) using the OS CSPRNG.
/// Create `data_dir/hosts` (mode 0700) if needed.
pub(crate) fn ensure_hosts_dir(data_dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(data_dir.join("hosts"))
}

/// Write a sealed host-key blob atomically with mode 0600.
pub(crate) fn write_host_seal(data_dir: &Path, host_id: &str, blob: &[u8]) -> std::io::Result<()> {
    ensure_hosts_dir(data_dir)?;
    cofferak_core::format::write_atomic(&host_seal_path(data_dir, host_id), blob)
}

pub(crate) fn random_key() -> [u8; 32] {
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Select the real platform [`HostSeal`] backend for `host_id`.
///
/// Follows the same `cfg(target_os = ...)` pattern used by `cofferakd`'s
/// own `host_seal()` helper, but parameterizes the backend's
/// name/account by `host_id` so distinct hosts enrolled from the same
/// data dir get distinct sealed storage.
// `#[allow(dead_code)]`: this file is also included directly (via
// `#[path]`) into the `cli_init` integration test binary, which only
// exercises `run_init_root`/`run_init_host_with_seal`/`CliError` and
// never references `current_host_seal`/`run_init_host` — those two are
// used by the real `cofferak-cli` binary's `main.rs`.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub fn current_host_seal(host_id: &str) -> Box<dyn HostSeal> {
    Box::new(SystemdCredsSeal {
        name: format!("cofferak-{host_id}"),
    })
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub fn current_host_seal(host_id: &str) -> Box<dyn HostSeal> {
    Box::new(KeychainSeal {
        service: "cofferak".to_string(),
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
/// file if `data_dir/vault.cofferak` already exists.
pub fn run_init_root(data_dir: &Path) -> Result<String, CliError> {
    std::fs::create_dir_all(data_dir)?;

    let vpath = vault_path(data_dir);
    if vpath.exists() {
        return Err(CliError::VaultExists);
    }

    let (root_pubkey, root_privkey) =
        generate_root_keypair().map_err(|e| CliError::Io(std::io::Error::other(e)))?;

    let vault = VaultFile::new(root_pubkey);
    let meta = VaultMeta::from_vault(&vault);

    vault.save(&vpath)?;
    meta.save(&meta_path(data_dir))?;

    // The armored block is the whole recovery key (X25519 + ML-KEM-1024,
    // with a checksum). Save it verbatim to a file kept offline; `recover
    // --root-key <file>` reads exactly this format.
    println!("=== COFFERAK ROOT PRIVATE KEY: save everything between the lines to a file and store it OFFLINE now; it will not be shown again ===");
    print!("{}", *root_privkey.to_armored());
    println!("=== END OF ROOT PRIVATE KEY ===");

    Ok(meta.root_pubkey_fingerprint)
}

/// Enroll the *first* host, `host_id`, into the vault at `data_dir`, using
/// `seal` as the `HostSeal` backend (injected so tests can use an
/// in-memory fake instead of the real platform backend).
///
/// - Returns `Err(CliError::VaultMissing)` if `data_dir` has no vault yet
///   (i.e. `init --root` was never run).
/// - Returns `Err(CliError::HostAlreadyEnrolled)` if `host_id` is already
///   in `vault.hosts`.
/// - Returns `Err(CliError::RootWrapAlreadySet)` if the vault already has
///   `root_wrap: Some(_)` (i.e. some other host is already enrolled) —
///   see the module doc comment for why adding an *additional* host is
///   deliberately not handled here.
/// - Otherwise (the vault has zero hosts and `root_wrap: None`): generates
///   a fresh DEK, wraps it for the root keypair into `vault.root_wrap`,
///   generates a fresh unseal key for this host, seals it via `seal`,
///   persists the sealed blob under `data_dir/hosts/<host_id>.seal`, wraps
///   the DEK for this host into `vault.hosts[host_id]`, and updates
///   `vault.cofferak` + `meta.json`.
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

    if vault.root_wrap.is_some() {
        return Err(CliError::RootWrapAlreadySet);
    }

    let dek = random_key();
    vault.root_wrap = Some(
        wrap_dek_for_root(&dek, &vault.root_pubkey)
            .map_err(|e| CliError::Io(std::io::Error::other(e)))?,
    );

    let host_key = KeyBytes::new(random_key());
    let sealed = seal
        .seal(&host_key)
        .map_err(|e| CliError::Io(std::io::Error::other(e)))?;

    write_host_seal(data_dir, host_id, &sealed.0)?;

    vault.hosts.insert(
        host_id.to_string(),
        wrap_dek_for_host(&dek, host_id, &host_key),
    );

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
