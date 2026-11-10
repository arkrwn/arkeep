//! On-disk vault format.
//!
//! This module defines the binary `vault.cofferak` file format (serialized with
//! `bincode`) and the JSON `meta.json` sidecar (serialized with
//! `serde_json`). `vault.cofferak` holds the full vault state, including wrapped
//! DEKs and encrypted entries; `meta.json` holds a small amount of
//! non-secret metadata (fingerprint, host/service ids) that tooling can read
//! without unwrapping anything.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{DekWrapHost, DekWrapRoot, EncryptedEntry};

/// Current time as Unix seconds, saturating to 0 if the clock is somehow
/// before the epoch.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Errors produced while loading or saving on-disk vault format files.
#[derive(Debug)]
pub enum FormatError {
    /// An I/O error occurred while reading or writing the file.
    Io(std::io::Error),
    /// The file's contents could not be decoded (truncated, malformed, or
    /// otherwise not a valid instance of the expected format).
    Corrupt,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::Io(e) => write!(f, "I/O error: {e}"),
            FormatError::Corrupt => write!(f, "corrupt or malformed vault file"),
        }
    }
}

impl std::error::Error for FormatError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FormatError::Io(e) => Some(e),
            FormatError::Corrupt => None,
        }
    }
}

impl From<std::io::Error> for FormatError {
    fn from(e: std::io::Error) -> Self {
        FormatError::Io(e)
    }
}

/// A single vault entry: the encrypted payload plus bookkeeping metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultEntry {
    pub ciphertext: EncryptedEntry,
    pub version: u32,
    pub updated_at: i64,
}

/// The full on-disk vault state, serialized as `vault.cofferak`.
///
/// `root_wrap` is `None` only between `init --root` (vault exists, no DEK
/// yet) and the first `init --host` (which generates the DEK and must set
/// `root_wrap`); every vault with at least one host has
/// `root_wrap = Some(_)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultFile {
    pub version: u16,
    pub created_at: i64,
    pub root_pubkey: [u8; 32],
    pub root_wrap: Option<DekWrapRoot>,
    pub hosts: BTreeMap<String, DekWrapHost>,
    pub services: BTreeMap<String, EncryptedEntry>,
    pub entries: BTreeMap<String, VaultEntry>,
}

impl VaultFile {
    /// Create a fresh vault for the given root public key: no DEK wrap yet,
    /// and empty hosts/services/entries.
    pub fn new(root_pubkey: [u8; 32]) -> Self {
        VaultFile {
            version: 1,
            created_at: now_unix(),
            root_pubkey,
            root_wrap: None,
            hosts: BTreeMap::new(),
            services: BTreeMap::new(),
            entries: BTreeMap::new(),
        }
    }

    /// Serialize this vault with `bincode` and write it to `path`.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let bytes = bincode::serialize(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, bytes)
    }

    /// Read and deserialize a vault previously written by [`VaultFile::save`].
    ///
    /// Returns `Err(FormatError::Corrupt)` (never panics) if the file is
    /// truncated or otherwise not a valid encoding of `VaultFile`.
    pub fn load(path: &Path) -> Result<Self, FormatError> {
        let bytes = std::fs::read(path)?;
        bincode::deserialize(&bytes).map_err(|_| FormatError::Corrupt)
    }
}

/// Non-secret vault metadata, serialized as JSON to `meta.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultMeta {
    pub version: u16,
    pub root_pubkey_fingerprint: String,
    pub host_ids: Vec<String>,
    pub service_ids: Vec<String>,
}

impl VaultMeta {
    /// Derive a `VaultMeta` snapshot from a `VaultFile`. The fingerprint is
    /// the lowercase hex encoding of the SHA-256 digest of `root_pubkey`.
    pub fn from_vault(v: &VaultFile) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(v.root_pubkey);
        let digest = hasher.finalize();
        let root_pubkey_fingerprint = digest.iter().map(|b| format!("{b:02x}")).collect();

        VaultMeta {
            version: v.version,
            root_pubkey_fingerprint,
            host_ids: v.hosts.keys().cloned().collect(),
            service_ids: v.services.keys().cloned().collect(),
        }
    }

    /// Serialize this metadata as JSON and write it to `path`.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }

    /// Read and deserialize metadata previously written by
    /// [`VaultMeta::save`].
    ///
    /// Returns `Err(FormatError::Corrupt)` (never panics) if the file is
    /// malformed JSON or is missing a required field.
    pub fn load(path: &Path) -> Result<Self, FormatError> {
        let bytes = std::fs::read(path)?;
        serde_json::from_slice(&bytes).map_err(|_| FormatError::Corrupt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        encrypt_entry, generate_root_keypair, wrap_dek_for_host, wrap_dek_for_root,
    };

    /// Build a unique path under the OS temp dir for this test process, so
    /// parallel test runs don't collide.
    fn temp_path(name: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "cofferak-format-test-{}-{}-{}-{name}",
            std::process::id(),
            nanos,
            n
        ))
    }

    fn sample_vault_with_root_wrap_none() -> VaultFile {
        let (root_pubkey, _root_privkey) = generate_root_keypair();
        VaultFile::new(root_pubkey)
    }

    fn sample_vault_with_root_wrap_some() -> VaultFile {
        let (root_pubkey, _root_privkey) = generate_root_keypair();
        let dek = [0x7Au8; 32];
        let mut vault = VaultFile::new(root_pubkey);
        vault.root_wrap = Some(wrap_dek_for_root(&dek, &root_pubkey));

        let host_key = [0x11u8; 32];
        vault
            .hosts
            .insert("host-a".to_string(), wrap_dek_for_host(&dek, &host_key));

        vault.services.insert(
            "service-a".to_string(),
            encrypt_entry(&dek, b"service secret"),
        );

        vault.entries.insert(
            "entry-a".to_string(),
            VaultEntry {
                ciphertext: encrypt_entry(&dek, b"entry secret"),
                version: 1,
                updated_at: 1_700_000_000,
            },
        );

        vault
    }

    #[test]
    fn new_vault_has_no_root_wrap_and_empty_maps() {
        let (root_pubkey, _) = generate_root_keypair();
        let vault = VaultFile::new(root_pubkey);

        assert_eq!(vault.root_pubkey, root_pubkey);
        assert!(vault.root_wrap.is_none());
        assert!(vault.hosts.is_empty());
        assert!(vault.services.is_empty());
        assert!(vault.entries.is_empty());
    }

    #[test]
    fn vault_file_round_trips_with_root_wrap_none() {
        let vault = sample_vault_with_root_wrap_none();
        let path = temp_path("none.cofferak");

        vault.save(&path).expect("save should succeed");
        let loaded = VaultFile::load(&path).expect("load should succeed");

        assert_eq!(loaded, vault);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn vault_file_round_trips_with_root_wrap_some() {
        let vault = sample_vault_with_root_wrap_some();
        let path = temp_path("some.cofferak");

        vault.save(&path).expect("save should succeed");
        let loaded = VaultFile::load(&path).expect("load should succeed");

        assert_eq!(loaded, vault);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn vault_file_load_truncated_file_returns_corrupt_not_panic() {
        let vault = sample_vault_with_root_wrap_some();
        let path = temp_path("truncated.cofferak");

        vault.save(&path).expect("save should succeed");
        let mut bytes = std::fs::read(&path).expect("read should succeed");
        assert!(
            bytes.len() > 10,
            "fixture must be larger than the truncation"
        );
        bytes.truncate(bytes.len() - 10);
        std::fs::write(&path, &bytes).expect("write truncated file should succeed");

        let result = VaultFile::load(&path);

        assert!(matches!(result, Err(FormatError::Corrupt)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn vault_meta_round_trips_from_vault() {
        let vault = sample_vault_with_root_wrap_some();
        let meta = VaultMeta::from_vault(&vault);
        let path = temp_path("meta.json");

        meta.save(&path).expect("save should succeed");
        let loaded = VaultMeta::load(&path).expect("load should succeed");

        assert_eq!(loaded, meta);
        assert_eq!(meta.version, vault.version);
        assert_eq!(meta.host_ids, vec!["host-a".to_string()]);
        assert_eq!(meta.service_ids, vec!["service-a".to_string()]);

        let mut hasher = Sha256::new();
        hasher.update(vault.root_pubkey);
        let expected_fingerprint = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(meta.root_pubkey_fingerprint, expected_fingerprint);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn vault_meta_load_with_missing_field_returns_corrupt() {
        let path = temp_path("meta-missing-field.json");
        // Missing `service_ids` entirely.
        let malformed = r#"{
            "version": 1,
            "root_pubkey_fingerprint": "deadbeef",
            "host_ids": []
        }"#;
        std::fs::write(&path, malformed).expect("write should succeed");

        let result = VaultMeta::load(&path);

        assert!(matches!(result, Err(FormatError::Corrupt)));
        let _ = std::fs::remove_file(&path);
    }
}
