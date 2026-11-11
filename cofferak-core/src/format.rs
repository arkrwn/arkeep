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

use bincode::Options as _;
use serde::{Deserialize, Serialize};

use crate::crypto::{DekWrapHost, DekWrapRoot, EncryptedEntry, RootPublicKey};

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
    /// The file is a vault of a format version this build doesn't read
    /// (e.g. a crypto-format v1 vault, see ADR 0011).
    UnsupportedVersion(u16),
}

/// The vault file failed an integrity check (ADR 0015).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityError {
    /// The file was edited outside cofferak: its integrity code doesn't
    /// match (entries, services, hosts or peers added, removed or swapped).
    Tampered,
    /// The file is an older copy than the newest one this host has seen.
    Rollback { found: u64, expected_at_least: u64 },
}

impl fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IntegrityError::Tampered => write!(
                f,
                "vault.cofferak was modified outside cofferak (integrity check failed)"
            ),
            IntegrityError::Rollback { found, expected_at_least } => write!(
                f,
                "vault.cofferak is an older copy (generation {found}, this host has seen {expected_at_least}), \
                 if you restored a backup on purpose, run `cofferak accept-restore`"
            ),
        }
    }
}

impl std::error::Error for IntegrityError {}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::Io(e) => write!(f, "I/O error: {e}"),
            FormatError::Corrupt => write!(f, "corrupt or malformed vault file"),
            FormatError::UnsupportedVersion(v) => write!(
                f,
                "vault format version {v} is not supported by this build (expected {VAULT_FORMAT_VERSION})"
            ),
        }
    }
}

impl std::error::Error for FormatError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FormatError::Io(e) => Some(e),
            FormatError::Corrupt | FormatError::UnsupportedVersion(_) => None,
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
/// `root_wrap`), every vault with at least one host has
/// `root_wrap = Some(_)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultFile {
    pub version: u16,
    pub created_at: i64,
    pub root_pubkey: RootPublicKey,
    pub root_wrap: Option<DekWrapRoot>,
    pub hosts: BTreeMap<String, DekWrapHost>,
    pub services: BTreeMap<String, EncryptedEntry>,
    pub entries: BTreeMap<String, VaultEntry>,
    /// This coffer's identity private key (ADR 0013), encrypted under the
    /// DEK with associated data `cofferak/v2/identity`, created on first
    /// use by `cofferak identity`.
    pub identity: Option<EncryptedEntry>,
    /// Trusted peer coffers' public identities by name, each encrypted
    /// under the DEK (associated data `cofferak/v2/peer\0<name>`) so an
    /// attacker who can write the file can't add a peer.
    pub peers: BTreeMap<String, EncryptedEntry>,
    /// Incremented on every sealed write, compared with this host's
    /// anchor to detect an older copy being put back (ADR 0015).
    pub generation: u64,
    /// HMAC-SHA384 over the whole vault (with this field empty), keyed from
    /// the DEK. Empty until the first sealed write.
    pub mac: Vec<u8>,
}

/// Vault format version 3 (before generation and integrity code).
#[derive(Deserialize)]
struct VaultFileV3 {
    _version: u16,
    created_at: i64,
    root_pubkey: RootPublicKey,
    root_wrap: Option<DekWrapRoot>,
    hosts: BTreeMap<String, DekWrapHost>,
    services: BTreeMap<String, EncryptedEntry>,
    entries: BTreeMap<String, VaultEntry>,
    identity: Option<EncryptedEntry>,
    peers: BTreeMap<String, EncryptedEntry>,
}

/// Vault format version 2 (before identities and peers), read and
/// upgraded in memory by [`VaultFile::load`].
#[derive(Deserialize)]
struct VaultFileV2 {
    _version: u16,
    created_at: i64,
    root_pubkey: RootPublicKey,
    root_wrap: Option<DekWrapRoot>,
    hosts: BTreeMap<String, DekWrapHost>,
    services: BTreeMap<String, EncryptedEntry>,
    entries: BTreeMap<String, VaultEntry>,
}

impl VaultFile {
    /// Create a fresh vault for the given root public key: no DEK wrap yet,
    /// and empty hosts/services/entries.
    pub fn new(root_pubkey: RootPublicKey) -> Self {
        VaultFile {
            version: VAULT_FORMAT_VERSION,
            created_at: now_unix(),
            root_pubkey,
            root_wrap: None,
            hosts: BTreeMap::new(),
            services: BTreeMap::new(),
            entries: BTreeMap::new(),
            identity: None,
            peers: BTreeMap::new(),
            generation: 0,
            mac: Vec::new(),
        }
    }

    fn mac_key(dek: &[u8; 32]) -> aws_lc_rs::hmac::Key {
        let mut k = zeroize::Zeroizing::new([0u8; 48]);
        hkdf::Hkdf::<sha2::Sha384>::new(None, dek)
            .expand(b"cofferak/v2/vault-mac", &mut k[..])
            .expect("48 bytes is a valid HKDF-SHA384 length");
        aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA384, &k[..])
    }

    fn mac_input(&self) -> Vec<u8> {
        let mut copy = self.clone();
        copy.mac = Vec::new();
        bincode_options()
            .serialize(&copy)
            .expect("an in-memory vault always encodes")
    }

    /// Prepare for a write: bump `generation` and recompute the integrity
    /// code under `dek`. Call right before [`save`](Self::save) whenever
    /// the DEK is available (every write except `init --root`).
    pub fn seal(&mut self, dek: &[u8; 32]) {
        self.generation = self.generation.saturating_add(1);
        self.mac = Vec::new();
        let tag = aws_lc_rs::hmac::sign(&Self::mac_key(dek), &self.mac_input());
        self.mac = tag.as_ref().to_vec();
    }

    /// Check the integrity code under `dek`, and the generation against
    /// `anchor` (the newest generation this host has seen, if any).
    ///
    /// A vault that has never been sealed (generation 0, no code: created
    /// by `init --root` or upgraded from an older format) is accepted only
    /// while the host has no anchor above 0, so stripping the code from a
    /// sealed vault is caught.
    pub fn verify(&self, dek: &[u8; 32], anchor: Option<u64>) -> Result<(), IntegrityError> {
        if self.mac.is_empty() {
            if self.generation != 0 {
                return Err(IntegrityError::Tampered);
            }
        } else if aws_lc_rs::hmac::verify(&Self::mac_key(dek), &self.mac_input(), &self.mac)
            .is_err()
        {
            return Err(IntegrityError::Tampered);
        }
        if let Some(seen) = anchor {
            if self.generation < seen {
                return Err(IntegrityError::Rollback {
                    found: self.generation,
                    expected_at_least: seen,
                });
            }
        }
        Ok(())
    }

    /// Serialize this vault with `bincode` and write it to `path`
    /// atomically (see [`write_atomic`]): a crash mid-write leaves either
    /// the previous complete file or the new complete file, never a
    /// truncated one.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        write_atomic(path, &self.to_bytes()?)
    }

    /// The exact bytes [`VaultFile::save`] writes.
    pub fn to_bytes(&self) -> std::io::Result<Vec<u8>> {
        bincode_options()
            .serialize(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Read and deserialize a vault previously written by [`VaultFile::save`].
    ///
    /// Returns `Err(FormatError::Corrupt)` (never panics) if the file is
    /// truncated or otherwise not a valid encoding of `VaultFile`. Decoding
    /// is size-limited ([`MAX_VAULT_BYTES`]), so a corrupted length prefix
    /// can't make the decoder try to allocate an absurd amount of memory.
    pub fn load(path: &Path) -> Result<Self, FormatError> {
        Self::from_bytes(&std::fs::read(path)?)
    }

    /// Decode a vault from the bytes of a `vault.cofferak` file.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() as u64 > MAX_VAULT_BYTES {
            return Err(FormatError::Corrupt);
        }
        // The format version is the first field (a little-endian u16).
        // Check it before decoding the rest, so a vault from another format
        // version gets a clear error instead of being misparsed.
        let version = match bytes.get(..2) {
            Some(b) => u16::from_le_bytes([b[0], b[1]]),
            None => return Err(FormatError::Corrupt),
        };
        match version {
            VAULT_FORMAT_VERSION => bincode_options()
                .deserialize(bytes)
                .map_err(|_| FormatError::Corrupt),
            3 => {
                let v3: VaultFileV3 = bincode_options()
                    .deserialize(bytes)
                    .map_err(|_| FormatError::Corrupt)?;
                Ok(VaultFile {
                    version: VAULT_FORMAT_VERSION,
                    created_at: v3.created_at,
                    root_pubkey: v3.root_pubkey,
                    root_wrap: v3.root_wrap,
                    hosts: v3.hosts,
                    services: v3.services,
                    entries: v3.entries,
                    identity: v3.identity,
                    peers: v3.peers,
                    generation: 0,
                    mac: Vec::new(),
                })
            }
            // Format 2 has the same layout minus the identity/peers fields:
            // upgrade it in memory, the next save writes format 3.
            2 => {
                let v2: VaultFileV2 = bincode_options()
                    .deserialize(bytes)
                    .map_err(|_| FormatError::Corrupt)?;
                Ok(VaultFile {
                    version: VAULT_FORMAT_VERSION,
                    created_at: v2.created_at,
                    root_pubkey: v2.root_pubkey,
                    root_wrap: v2.root_wrap,
                    hosts: v2.hosts,
                    services: v2.services,
                    entries: v2.entries,
                    identity: None,
                    peers: BTreeMap::new(),
                    generation: 0,
                    mac: Vec::new(),
                })
            }
            other => Err(FormatError::UnsupportedVersion(other)),
        }
    }
}

/// The `vault.cofferak` format version this build writes. Version 2 is
/// crypto format v2 (ADR 0011): hybrid post-quantum root wrap and
/// context-bound ciphertexts, version 3 adds the coffer identity and
/// trusted peers (ADR 0013), version 4 adds the generation counter and
/// whole-file integrity code (ADR 0015). Versions 2 and 3 are read and
/// upgraded.
pub const VAULT_FORMAT_VERSION: u16 = 4;

/// Path of `host_id`'s anchor file: the newest vault generation this host
/// has written or accepted (ADR 0015).
pub fn anchor_path(data_dir: &Path, host_id: &str) -> std::path::PathBuf {
    data_dir.join("hosts").join(format!("{host_id}.anchor"))
}

fn anchor_tag(dek: &[u8; 32], host_id: &str, generation: u64) -> aws_lc_rs::hmac::Tag {
    let mut k = zeroize::Zeroizing::new([0u8; 48]);
    hkdf::Hkdf::<sha2::Sha384>::new(None, dek)
        .expand(b"cofferak/v2/anchor", &mut k[..])
        .expect("valid length");
    let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA384, &k[..]);
    let mut msg = host_id.as_bytes().to_vec();
    msg.push(0);
    msg.extend_from_slice(&generation.to_le_bytes());
    aws_lc_rs::hmac::sign(&key, &msg)
}

/// A second place to keep each host's anchor, outside the data directory
/// (ADR 0017): the macOS Keychain, or a separate state directory on Linux.
/// Restoring the data directory from a backup then leaves the newer
/// mirrored anchor in place, so the older vault is still detected.
pub trait AnchorMirror: Send + Sync {
    /// The stored anchor bytes, `Ok(None)` if there are none yet.
    fn read(&self, host_id: &str) -> std::io::Result<Option<Vec<u8>>>;
    fn write(&self, host_id: &str, bytes: &[u8]) -> std::io::Result<()>;
}

static ANCHOR_MIRROR: std::sync::OnceLock<Box<dyn AnchorMirror>> = std::sync::OnceLock::new();

/// Turn on the anchor mirror for this process (the real binaries do this
/// at startup, tests don't). Only the first call has an effect.
pub fn set_anchor_mirror(mirror: Box<dyn AnchorMirror>) {
    let _ = ANCHOR_MIRROR.set(mirror);
}

fn decode_anchor(bytes: &[u8], host_id: &str, dek: &[u8; 32]) -> Result<u64, IntegrityError> {
    if bytes.len() != 8 + 48 {
        return Err(IntegrityError::Tampered);
    }
    let generation = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
    if anchor_tag(dek, host_id, generation).as_ref() != &bytes[8..] {
        return Err(IntegrityError::Tampered);
    }
    Ok(generation)
}

/// Read `host_id`'s anchor: the newest of the anchor file and its mirror.
/// `Ok(None)` if there is none yet. An anchor whose code doesn't verify
/// under `dek` is reported as tampering.
pub fn read_anchor(
    data_dir: &Path,
    host_id: &str,
    dek: &[u8; 32],
) -> Result<Option<u64>, IntegrityError> {
    let from_file = read_anchor_file(data_dir, host_id, dek)?;
    let from_mirror = match ANCHOR_MIRROR.get() {
        Some(m) => match m.read(host_id) {
            Ok(Some(bytes)) => Some(decode_anchor(&bytes, host_id, dek)?),
            Ok(None) => None,
            Err(_) => return Err(IntegrityError::Tampered),
        },
        None => None,
    };
    Ok(from_file.max(from_mirror))
}

fn read_anchor_file(
    data_dir: &Path,
    host_id: &str,
    dek: &[u8; 32],
) -> Result<Option<u64>, IntegrityError> {
    let bytes = match std::fs::read(anchor_path(data_dir, host_id)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(IntegrityError::Tampered),
    };
    if bytes.len() != 8 + 48 {
        return Err(IntegrityError::Tampered);
    }
    let generation = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
    let tag = anchor_tag(dek, host_id, generation);
    if tag.as_ref() != &bytes[8..] {
        return Err(IntegrityError::Tampered);
    }
    Ok(Some(generation))
}

/// Record `generation` as `host_id`'s anchor (atomic write, mode 0600).
pub fn write_anchor(
    data_dir: &Path,
    host_id: &str,
    dek: &[u8; 32],
    generation: u64,
) -> std::io::Result<()> {
    let hosts = data_dir.join("hosts");
    if !hosts.is_dir() {
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        b.create(&hosts)?;
    }
    let mut bytes = generation.to_le_bytes().to_vec();
    bytes.extend_from_slice(anchor_tag(dek, host_id, generation).as_ref());
    write_atomic(&anchor_path(data_dir, host_id), &bytes)?;
    if let Some(m) = ANCHOR_MIRROR.get() {
        m.write(host_id, &bytes)?;
    }
    Ok(())
}

/// Linux anchor mirror: `<dir>/<host_id>.anchor`, where `dir` is a state
/// directory outside the data directory (the systemd unit provides
/// `/var/lib/cofferak-anchor`). When run as root, files are handed to the
/// directory's owner so the unprivileged daemon can keep them current.
#[cfg(unix)]
pub struct DirAnchorMirror {
    pub dir: std::path::PathBuf,
}

#[cfg(unix)]
impl DirAnchorMirror {
    /// `$COFFERAK_ANCHOR_DIR`, else `/var/lib/cofferak-anchor` if it exists.
    pub fn from_env() -> Option<Self> {
        let dir = match std::env::var_os("COFFERAK_ANCHOR_DIR") {
            Some(d) if !d.is_empty() => std::path::PathBuf::from(d),
            _ => std::path::PathBuf::from("/var/lib/cofferak-anchor"),
        };
        let meta = std::fs::symlink_metadata(&dir).ok()?;
        meta.is_dir().then_some(DirAnchorMirror { dir })
    }

    fn path(&self, host_id: &str) -> std::path::PathBuf {
        self.dir.join(format!("{host_id}.anchor"))
    }
}

#[cfg(unix)]
impl AnchorMirror for DirAnchorMirror {
    fn read(&self, host_id: &str) -> std::io::Result<Option<Vec<u8>>> {
        match std::fs::read(self.path(host_id)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn write(&self, host_id: &str, bytes: &[u8]) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let path = self.path(host_id);
        write_atomic(&path, bytes)?;
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            let dir = std::fs::symlink_metadata(&self.dir)?;
            if dir.is_dir() {
                std::os::unix::fs::lchown(&path, Some(dir.uid()), Some(dir.gid()))?;
            }
        }
        Ok(())
    }
}

/// Upper bound on a `vault.cofferak` file, enforced on both encode and decode.
pub const MAX_VAULT_BYTES: u64 = 256 * 1024 * 1024;

/// The exact `bincode` configuration `vault.cofferak` uses: identical wire
/// encoding to `bincode::serialize`/`deserialize` (fixed-width integers,
/// little-endian, trailing bytes tolerated), plus a hard size limit.
fn bincode_options() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(MAX_VAULT_BYTES)
}

/// Write `bytes` to `path` atomically and durably: write a temporary file
/// in the same directory (mode `0600` on Unix), `fsync` it, `rename` it
/// over `path`, then `fsync` the directory so the rename itself survives
/// a crash. Readers only ever observe the old complete file or the new
/// complete file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("write_atomic: path has no file name"))?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}-{}",
        file_name.to_string_lossy(),
        std::process::id(),
        now_nanos()
    ));

    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)?;
        #[cfg(unix)]
        {
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// An exclusive, process-wide advisory lock on a vault, held for as long
/// as this value is alive. Every read-modify-write of `vault.cofferak` - the
/// daemon persisting a `set`/`rm`, and every CLI admin command - takes
/// this lock first, so two writers can never interleave and silently drop
/// each other's changes. The lock file is `<vault path>.lock`.
pub struct VaultLock {
    _file: std::fs::File,
}

impl VaultLock {
    /// Block until the exclusive lock for the vault at `vault_path` is
    /// acquired.
    pub fn acquire(vault_path: &Path) -> std::io::Result<Self> {
        let mut lock_name = vault_path.as_os_str().to_owned();
        lock_name.push(".lock");
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Never follow a symlink planted at the lock path: admin commands
            // run as root, and the data directory belongs to the daemon user.
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(std::path::PathBuf::from(lock_name))?;
        file.lock()?;
        Ok(VaultLock { _file: file })
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
    /// [`RootPublicKey::fingerprint`] (SHA-256 over both root public keys).
    pub fn from_vault(v: &VaultFile) -> Self {
        VaultMeta {
            version: v.version,
            root_pubkey_fingerprint: v.root_pubkey.fingerprint(),
            host_ids: v.hosts.keys().cloned().collect(),
            service_ids: v.services.keys().cloned().collect(),
        }
    }

    /// Serialize this metadata as JSON and write it to `path` atomically
    /// (see [`write_atomic`]).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        write_atomic(path, &json)
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
        encrypt_entry, generate_root_keypair, wrap_dek_for_host, wrap_dek_for_root, Aad,
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
        let (root_pubkey, _root_privkey) = generate_root_keypair().unwrap();
        VaultFile::new(root_pubkey)
    }

    fn sample_vault_with_root_wrap_some() -> VaultFile {
        let (root_pubkey, _root_privkey) = generate_root_keypair().unwrap();
        let dek = [0x7Au8; 32];
        let mut vault = VaultFile::new(root_pubkey.clone());
        vault.root_wrap = Some(wrap_dek_for_root(&dek, &root_pubkey).unwrap());

        let host_key = [0x11u8; 32];
        vault.hosts.insert(
            "host-a".to_string(),
            wrap_dek_for_host(&dek, "host-a", &host_key),
        );

        vault.services.insert(
            "service-a".to_string(),
            encrypt_entry(&dek, &Aad::service_token("service-a"), b"service secret"),
        );

        vault.entries.insert(
            "entry-a".to_string(),
            VaultEntry {
                ciphertext: encrypt_entry(&dek, &Aad::entry("entry-a"), b"entry secret"),
                version: 1,
                updated_at: 1_700_000_000,
            },
        );

        vault
    }

    #[test]
    fn new_vault_has_no_root_wrap_and_empty_maps() {
        let (root_pubkey, _) = generate_root_keypair().unwrap();
        let vault = VaultFile::new(root_pubkey.clone());

        assert_eq!(vault.version, VAULT_FORMAT_VERSION);
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
    fn vault_file_load_rejects_other_format_versions_clearly() {
        let vault = sample_vault_with_root_wrap_some();
        let path = temp_path("v1.cofferak");
        vault.save(&path).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[..2].copy_from_slice(&1u16.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();

        assert!(matches!(
            VaultFile::load(&path),
            Err(FormatError::UnsupportedVersion(1))
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn version_2_vaults_load_and_upgrade() {
        #[derive(Serialize)]
        struct V2<'a> {
            version: u16,
            created_at: i64,
            root_pubkey: &'a RootPublicKey,
            root_wrap: &'a Option<DekWrapRoot>,
            hosts: &'a BTreeMap<String, DekWrapHost>,
            services: &'a BTreeMap<String, EncryptedEntry>,
            entries: &'a BTreeMap<String, VaultEntry>,
        }
        let v = sample_vault_with_root_wrap_some();
        let bytes = bincode_options()
            .serialize(&V2 {
                version: 2,
                created_at: v.created_at,
                root_pubkey: &v.root_pubkey,
                root_wrap: &v.root_wrap,
                hosts: &v.hosts,
                services: &v.services,
                entries: &v.entries,
            })
            .unwrap();
        let path = temp_path("v2.cofferak");
        std::fs::write(&path, bytes).unwrap();
        let loaded = VaultFile::load(&path).unwrap();
        assert_eq!(loaded.version, VAULT_FORMAT_VERSION);
        assert_eq!(loaded.entries, v.entries);
        assert_eq!(loaded.hosts, v.hosts);
        assert!(loaded.identity.is_none() && loaded.peers.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    const DEK: [u8; 32] = [0x7Au8; 32];

    #[test]
    fn sealed_vault_verifies_and_any_edit_is_detected() {
        let mut v = sample_vault_with_root_wrap_some();
        v.seal(&DEK);
        assert_eq!(v.generation, 1);
        assert_eq!(v.verify(&DEK, Some(1)), Ok(()));

        let mut removed = v.clone();
        removed.entries.clear();
        assert_eq!(removed.verify(&DEK, None), Err(IntegrityError::Tampered));

        let mut swapped = v.clone();
        swapped.services.clear();
        assert_eq!(swapped.verify(&DEK, None), Err(IntegrityError::Tampered));

        let mut gen_edit = v.clone();
        gen_edit.generation = 99;
        assert_eq!(gen_edit.verify(&DEK, None), Err(IntegrityError::Tampered));

        // Stripping the code from a sealed vault is caught too.
        let mut stripped = v.clone();
        stripped.mac.clear();
        assert_eq!(stripped.verify(&DEK, None), Err(IntegrityError::Tampered));
        stripped.generation = 0;
        assert!(matches!(
            stripped.verify(&DEK, Some(1)),
            Err(IntegrityError::Rollback { found: 0, .. })
        ));

        // A different DEK can't vouch for it.
        assert_eq!(v.verify(&[1u8; 32], None), Err(IntegrityError::Tampered));
    }

    #[test]
    fn older_copies_are_reported_as_rollback() {
        let mut v = sample_vault_with_root_wrap_some();
        v.seal(&DEK);
        let old = v.clone();
        v.seal(&DEK);
        v.seal(&DEK);
        assert_eq!(v.verify(&DEK, Some(3)), Ok(()));
        assert_eq!(
            old.verify(&DEK, Some(3)),
            Err(IntegrityError::Rollback {
                found: 1,
                expected_at_least: 3
            })
        );
        // A fresh, never-sealed vault is fine on a host with no anchor yet.
        let fresh = sample_vault_with_root_wrap_none();
        assert_eq!(fresh.verify(&DEK, None), Ok(()));
    }

    #[test]
    fn anchors_round_trip_and_reject_edits() {
        let dir = temp_path("anchor-dir");
        std::fs::create_dir_all(dir.join("hosts")).unwrap();
        assert_eq!(read_anchor(&dir, "h", &DEK), Ok(None));
        write_anchor(&dir, "h", &DEK, 42).unwrap();
        assert_eq!(read_anchor(&dir, "h", &DEK), Ok(Some(42)));
        // Lowering the number without the key is detected.
        let mut bytes = std::fs::read(anchor_path(&dir, "h")).unwrap();
        bytes[..8].copy_from_slice(&1u64.to_le_bytes());
        std::fs::write(anchor_path(&dir, "h"), &bytes).unwrap();
        assert_eq!(read_anchor(&dir, "h", &DEK), Err(IntegrityError::Tampered));
        // An anchor is bound to its host id.
        write_anchor(&dir, "h", &DEK, 5).unwrap();
        std::fs::copy(anchor_path(&dir, "h"), anchor_path(&dir, "other")).unwrap();
        assert_eq!(
            read_anchor(&dir, "other", &DEK),
            Err(IntegrityError::Tampered)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn version_3_vaults_load_and_upgrade() {
        #[derive(Serialize)]
        struct V3<'a> {
            version: u16,
            created_at: i64,
            root_pubkey: &'a RootPublicKey,
            root_wrap: &'a Option<DekWrapRoot>,
            hosts: &'a BTreeMap<String, DekWrapHost>,
            services: &'a BTreeMap<String, EncryptedEntry>,
            entries: &'a BTreeMap<String, VaultEntry>,
            identity: &'a Option<EncryptedEntry>,
            peers: &'a BTreeMap<String, EncryptedEntry>,
        }
        let v = sample_vault_with_root_wrap_some();
        let bytes = bincode_options()
            .serialize(&V3 {
                version: 3,
                created_at: v.created_at,
                root_pubkey: &v.root_pubkey,
                root_wrap: &v.root_wrap,
                hosts: &v.hosts,
                services: &v.services,
                entries: &v.entries,
                identity: &v.identity,
                peers: &v.peers,
            })
            .unwrap();
        let path = temp_path("v3.cofferak");
        std::fs::write(&path, bytes).unwrap();
        let loaded = VaultFile::load(&path).unwrap();
        assert_eq!(loaded.version, VAULT_FORMAT_VERSION);
        assert_eq!((loaded.generation, loaded.mac.len()), (0, 0));
        assert_eq!(loaded.entries, v.entries);
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

        assert_eq!(
            meta.root_pubkey_fingerprint,
            vault.root_pubkey.fingerprint()
        );

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

    #[test]
    fn write_atomic_replaces_contents_and_leaves_no_temp_files() {
        let dir = temp_path("atomic-dir");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.cofferak");

        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second, longer contents").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second, longer contents");

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n != "vault.cofferak")
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "vault file must not be group/world readable");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_mirrored_anchor_survives_restoring_the_data_directory() {
        // Uses DirAnchorMirror directly (not the process-wide setting, so
        // other tests are unaffected).
        let data = temp_path("mirror-data");
        let mirror_dir = temp_path("mirror-dir");
        std::fs::create_dir_all(&mirror_dir).unwrap();
        let m = DirAnchorMirror {
            dir: mirror_dir.clone(),
        };
        let dek = [9u8; 32];
        write_anchor(&data, "h", &dek, 3).unwrap();
        let old_file = std::fs::read(anchor_path(&data, "h")).unwrap();
        // Newer anchor, in both places.
        write_anchor(&data, "h", &dek, 7).unwrap();
        let mut bytes = 7u64.to_le_bytes().to_vec();
        bytes.extend_from_slice(anchor_tag(&dek, "h", 7).as_ref());
        m.write("h", &bytes).unwrap();
        // Restore the old anchor file (as from a backup of the data dir).
        std::fs::write(anchor_path(&data, "h"), &old_file).unwrap();
        assert_eq!(read_anchor_file(&data, "h", &dek), Ok(Some(3)));
        let mirrored = decode_anchor(&m.read("h").unwrap().unwrap(), "h", &dek).unwrap();
        assert_eq!(mirrored, 7);
        // An edited mirror is tampering.
        let mut bad = bytes.clone();
        bad[0] ^= 1;
        assert_eq!(
            decode_anchor(&bad, "h", &dek),
            Err(IntegrityError::Tampered)
        );
        let _ = std::fs::remove_dir_all(&data);
        let _ = std::fs::remove_dir_all(&mirror_dir);
    }

    #[cfg(unix)]
    #[test]
    fn vault_lock_refuses_a_symlinked_lock_file() {
        let dir = temp_path("lock-symlink");
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target-file");
        std::os::unix::fs::symlink(&target, dir.join("vault.cofferak.lock")).unwrap();
        assert!(VaultLock::acquire(&dir.join("vault.cofferak")).is_err());
        assert!(!target.exists(), "the symlink target must not be created");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vault_lock_is_exclusive_across_threads() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let path = temp_path("lock-vault.cofferak");
        let held = Arc::new(AtomicBool::new(false));
        let overlapped = Arc::new(AtomicBool::new(false));

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let path = path.clone();
                let held = Arc::clone(&held);
                let overlapped = Arc::clone(&overlapped);
                std::thread::spawn(move || {
                    for _ in 0..10 {
                        let _guard = VaultLock::acquire(&path).unwrap();
                        if held.swap(true, Ordering::SeqCst) {
                            overlapped.store(true, Ordering::SeqCst);
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        held.store(false, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert!(
            !overlapped.load(Ordering::SeqCst),
            "two holders observed the vault lock at the same time"
        );
        let mut lock_name = path.as_os_str().to_owned();
        lock_name.push(".lock");
        let _ = std::fs::remove_file(std::path::PathBuf::from(lock_name));
    }

    #[test]
    fn vault_file_load_rejects_oversized_length_prefix_without_allocating() {
        // A file whose leading bytes decode as an absurd collection length
        // must fail cleanly as Corrupt, not attempt a huge allocation.
        let path = temp_path("oversized-prefix.cofferak");
        let mut bytes = VAULT_FORMAT_VERSION.to_le_bytes().to_vec(); // version: u16
        bytes.extend_from_slice(&0i64.to_le_bytes()); // created_at
        bytes.extend_from_slice(&[0u8; 32]); // root_pubkey.x25519
        bytes.extend_from_slice(&u64::MAX.to_le_bytes()); // root_pubkey.mlkem1024 len
        std::fs::write(&path, &bytes).unwrap();

        assert!(matches!(VaultFile::load(&path), Err(FormatError::Corrupt)));
        let _ = std::fs::remove_file(&path);
    }
}
