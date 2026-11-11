//! Encrypted, portable export bundles (`cofferak export` / `import`,
//! ADR 0012): every secret and every service token of a vault, sealed
//! with a passphrase so it can be carried to another machine or OS and
//! restored there.
//!
//! File layout (`.cfk`):
//!
//! ```text
//! magic       8 bytes  "CFKEXPT1"
//! version     u16 LE   1
//! kdf         u8       1 = PBKDF2-HMAC-SHA384
//! iterations  u32 LE   600000 by default
//! salt        32 bytes random
//! nonce       12 bytes random
//! ciphertext  rest     AES-256-GCM-SIV(key, nonce, payload, aad = all 59 header bytes)
//! ```
//!
//! The key is PBKDF2-HMAC-SHA384(passphrase, salt, iterations) via AWS-LC
//! (FIPS-approved KDF, the passphrase must be at least 14 bytes, the FIPS
//! minimum). Authenticating the header means the iteration count, salt or
//! version can't be altered without the bundle failing to open. The
//! payload is a bincode [`Bundle`], plaintext buffers are zeroized.
//!
//! A bundle holds values and tokens, never host keys or the root key, so
//! it is machine- and OS-independent.

use std::fmt;
use std::num::NonZeroU32;

use aws_lc_rs::aead::{Aad as LcAad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM_SIV};
use aws_lc_rs::pbkdf2::{derive, PBKDF2_HMAC_SHA384};
use bincode::Options as _;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::acl::AccessToken;

const MAGIC: &[u8; 8] = b"CFKEXPT1";
const VERSION: u16 = 1;
const KDF_PBKDF2_SHA384: u8 = 1;
const HEADER_LEN: usize = 8 + 2 + 1 + 4 + 32 + 12;
/// PBKDF2 iterations for new bundles.
pub const DEFAULT_ITERATIONS: u32 = 600_000;
/// Iteration bounds accepted when opening a bundle (guards against a
/// tampered header asking for a near-infinite or trivially weak KDF;
/// the header is authenticated anyway, but this fails fast).
const MIN_ITERATIONS: u32 = 100_000;
const MAX_ITERATIONS: u32 = 50_000_000;
/// Minimum passphrase length in bytes (the FIPS PBKDF2 minimum).
pub const MIN_PASSPHRASE_BYTES: usize = 14;
/// Largest bundle accepted (matches the vault's own size cap).
pub const MAX_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;

/// One secret in a bundle, in plaintext (inside the bundle's encryption).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleEntry {
    pub path: String,
    pub value: Vec<u8>,
    pub version: u32,
    pub updated_at: i64,
}

impl Drop for BundleEntry {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Everything a bundle carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub created_at: i64,
    /// Root-key fingerprint of the vault the bundle was exported from
    /// (informational, shown on import).
    pub source_fingerprint: String,
    pub entries: Vec<BundleEntry>,
    pub services: Vec<AccessToken>,
}

/// Why a bundle couldn't be created or opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    /// Passphrase shorter than [`MIN_PASSPHRASE_BYTES`].
    WeakPassphrase,
    /// Not a cofferak bundle, or a version/KDF this build doesn't know.
    NotABundle,
    /// Wrong passphrase, or the file was modified or truncated.
    WrongPassphraseOrCorrupt,
    /// Larger than [`MAX_BUNDLE_BYTES`].
    TooLarge,
    /// Encoding failure (should not happen).
    Encode(String),
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BundleError::WeakPassphrase => write!(
                f,
                "passphrase must be at least {MIN_PASSPHRASE_BYTES} characters"
            ),
            BundleError::NotABundle => write!(
                f,
                "not a cofferak export bundle (or an unsupported version)"
            ),
            BundleError::WrongPassphraseOrCorrupt => {
                write!(
                    f,
                    "wrong passphrase, or the bundle was modified or truncated"
                )
            }
            BundleError::TooLarge => write!(f, "bundle is larger than {MAX_BUNDLE_BYTES} bytes"),
            BundleError::Encode(e) => write!(f, "could not encode bundle: {e}"),
        }
    }
}

impl std::error::Error for BundleError {}

fn bincode_opts() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(MAX_BUNDLE_BYTES)
}

fn derive_key(passphrase: &[u8], salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    derive(
        PBKDF2_HMAC_SHA384,
        NonZeroU32::new(iterations).expect("iterations are validated as non-zero"),
        salt,
        passphrase,
        &mut key[..],
    );
    key
}

fn aead(key: &[u8; 32]) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&AES_256_GCM_SIV, key).expect("32-byte key"))
}

/// Encrypt `bundle` with `passphrase` using [`DEFAULT_ITERATIONS`].
pub fn seal(bundle: &Bundle, passphrase: &[u8]) -> Result<Vec<u8>, BundleError> {
    seal_with_iterations(bundle, passphrase, DEFAULT_ITERATIONS)
}

/// [`seal`] with an explicit PBKDF2 iteration count.
pub fn seal_with_iterations(
    bundle: &Bundle,
    passphrase: &[u8],
    iterations: u32,
) -> Result<Vec<u8>, BundleError> {
    if passphrase.len() < MIN_PASSPHRASE_BYTES {
        return Err(BundleError::WeakPassphrase);
    }
    let iterations = iterations.clamp(MIN_ITERATIONS, MAX_ITERATIONS);
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];
    aws_lc_rs::rand::fill(&mut salt).map_err(|_| BundleError::Encode("rng".into()))?;
    aws_lc_rs::rand::fill(&mut nonce).map_err(|_| BundleError::Encode("rng".into()))?;

    let mut out = Vec::with_capacity(HEADER_LEN + 1024);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.push(KDF_PBKDF2_SHA384);
    out.extend_from_slice(&iterations.to_le_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    debug_assert_eq!(out.len(), HEADER_LEN);

    let mut payload = Zeroizing::new(
        bincode_opts()
            .serialize(bundle)
            .map_err(|e| BundleError::Encode(e.to_string()))?,
    );
    let key = derive_key(passphrase, &salt, iterations);
    aead(&key)
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            LcAad::from(&out[..HEADER_LEN]),
            &mut *payload,
        )
        .map_err(|_| BundleError::Encode("encryption failed".into()))?;
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Decrypt a bundle produced by [`seal`].
pub fn open(bytes: &[u8], passphrase: &[u8]) -> Result<Bundle, BundleError> {
    if bytes.len() as u64 > MAX_BUNDLE_BYTES {
        return Err(BundleError::TooLarge);
    }
    if bytes.len() < HEADER_LEN + AES_256_GCM_SIV.tag_len() || &bytes[..8] != MAGIC {
        return Err(BundleError::NotABundle);
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    let kdf = bytes[10];
    let iterations = u32::from_le_bytes([bytes[11], bytes[12], bytes[13], bytes[14]]);
    if version != VERSION
        || kdf != KDF_PBKDF2_SHA384
        || !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations)
    {
        return Err(BundleError::NotABundle);
    }
    let salt = &bytes[15..47];
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bytes[47..59]);

    let key = derive_key(passphrase, salt, iterations);
    let mut buf = Zeroizing::new(bytes[HEADER_LEN..].to_vec());
    let plain = aead(&key)
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            LcAad::from(&bytes[..HEADER_LEN]),
            &mut buf,
        )
        .map_err(|_| BundleError::WrongPassphraseOrCorrupt)?;
    bincode_opts()
        .deserialize(plain)
        .map_err(|_| BundleError::WrongPassphraseOrCorrupt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::Permission;

    const PASS: &[u8] = b"correct horse battery staple";
    const FAST: u32 = MIN_ITERATIONS;

    fn sample() -> Bundle {
        Bundle {
            created_at: 1_700_000_000,
            source_fingerprint: "ab".repeat(32),
            entries: vec![
                BundleEntry {
                    path: "app/DB_PASSWORD".into(),
                    value: b"p@ss".to_vec(),
                    version: 3,
                    updated_at: 1,
                },
                BundleEntry {
                    path: "app/ssh/key".into(),
                    value: (0..=255u8).collect(),
                    version: 1,
                    updated_at: 2,
                },
            ],
            services: vec![AccessToken {
                service_id: "app".into(),
                prefixes: vec!["app".into()],
                permission: Permission::ReadWrite,
                secret: [7; 32],
            }],
        }
    }

    #[test]
    fn round_trip() {
        let sealed = seal_with_iterations(&sample(), PASS, FAST).unwrap();
        let b = open(&sealed, PASS).unwrap();
        assert_eq!(b.entries, sample().entries);
        assert_eq!(b.services[0].secret, [7; 32]);
        assert_eq!(b.source_fingerprint, sample().source_fingerprint);
    }

    #[test]
    fn no_plaintext_in_the_file() {
        let sealed = seal_with_iterations(&sample(), PASS, FAST).unwrap();
        let hay = String::from_utf8_lossy(&sealed);
        assert!(!hay.contains("DB_PASSWORD") && !hay.contains("p@ss"));
    }

    #[test]
    fn wrong_passphrase_and_tampering_are_rejected() {
        let sealed = seal_with_iterations(&sample(), PASS, FAST).unwrap();
        assert_eq!(
            open(&sealed, b"wrong passphrase!!").unwrap_err(),
            BundleError::WrongPassphraseOrCorrupt
        );
        // Flip a ciphertext byte.
        let mut t = sealed.clone();
        *t.last_mut().unwrap() ^= 1;
        assert_eq!(
            open(&t, PASS).unwrap_err(),
            BundleError::WrongPassphraseOrCorrupt
        );
        // Change the authenticated salt in the header.
        let mut h = sealed.clone();
        h[20] ^= 1;
        assert_eq!(
            open(&h, PASS).unwrap_err(),
            BundleError::WrongPassphraseOrCorrupt
        );
        // Truncate.
        assert!(open(&sealed[..sealed.len() - 5], PASS).is_err());
    }

    #[test]
    fn rejects_non_bundles_and_weak_headers() {
        assert_eq!(open(b"hello", PASS).unwrap_err(), BundleError::NotABundle);
        let mut sealed = seal_with_iterations(&sample(), PASS, FAST).unwrap();
        sealed[11..15].copy_from_slice(&1u32.to_le_bytes()); // 1 iteration
        assert_eq!(open(&sealed, PASS).unwrap_err(), BundleError::NotABundle);
    }

    #[test]
    fn weak_passphrases_are_refused() {
        assert_eq!(
            seal_with_iterations(&sample(), b"short", FAST).unwrap_err(),
            BundleError::WeakPassphrase
        );
    }

    #[test]
    fn default_iterations_are_stored_and_used() {
        let sealed = seal(&sample(), PASS).unwrap();
        assert_eq!(
            u32::from_le_bytes(sealed[11..15].try_into().unwrap()),
            DEFAULT_ITERATIONS
        );
        assert!(open(&sealed, PASS).is_ok());
    }
}
