//! Envelope encryption primitives for cofferak (crypto format v2, ADR 0011).
//!
//! - **Entries and service tokens** are encrypted under the vault's 256-bit
//!   data-encryption key (DEK) with **AES-256-GCM-SIV**. Every ciphertext is
//!   bound to its context through the AEAD's associated data ([`Aad`]): an
//!   entry to its path, a service token to its service id. A ciphertext
//!   copied to a different path or service fails to decrypt instead of
//!   silently returning another secret.
//! - **Host wraps**: the DEK is wrapped per enrolled host under that host's
//!   sealed 256-bit key, AES-256-GCM-SIV, bound to the host id.
//! - **Root (recovery) wrap**: the DEK is wrapped for the offline root key
//!   with a **hybrid post-quantum KEM**: X25519 *and* ML-KEM-1024 (FIPS 203,
//!   via the FIPS 140-3 validated AWS-LC module). The wrapping key is
//!   derived with **HKDF-SHA-384** from both shared secrets and the full
//!   transcript, so recovering the DEK requires breaking *both* X25519 and
//!   ML-KEM-1024. This protects the recovery wrap even against an attacker
//!   who stores the vault today and has a quantum computer tomorrow.
//!
//! Algorithm choices match the NSA CNSA 2.0 suite where it specifies one
//! (AES-256, ML-KEM-1024, SHA-384); X25519 is an additional classical layer.

use std::fmt;
use std::ops::Deref;

use aws_lc_rs::aead::{self as lc_aead, LessSafeKey, Nonce, UnboundKey, AES_256_GCM_SIV};
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_1024};
use base64::Engine as _;
use hkdf::Hkdf;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Size in bytes of an ML-KEM-1024 encapsulation (public) key.
pub const MLKEM1024_PUBLIC_KEY_LEN: usize = 1568;
/// Size in bytes of an ML-KEM-1024 decapsulation (private) key.
pub const MLKEM1024_PRIVATE_KEY_LEN: usize = 3168;
/// Size in bytes of an ML-KEM-1024 ciphertext.
pub const MLKEM1024_CIPHERTEXT_LEN: usize = 1568;

/// A 32-byte key buffer that is zeroized when dropped.
pub struct KeyBytes([u8; 32]);

impl KeyBytes {
    pub fn new(bytes: [u8; 32]) -> Self {
        KeyBytes(bytes)
    }
}

impl Deref for KeyBytes {
    type Target = [u8; 32];

    fn deref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for KeyBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Errors produced by the envelope crypto operations in this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Failed to unwrap (decrypt) a wrapped DEK.
    Unwrap,
    /// Failed to decrypt an entry.
    Decrypt,
    /// A key was malformed (wrong length, unparsable armor, bad checksum).
    InvalidKey,
    /// The underlying cryptographic library reported an internal failure.
    Internal,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Unwrap => write!(f, "failed to unwrap key"),
            CryptoError::Decrypt => write!(f, "failed to decrypt entry"),
            CryptoError::InvalidKey => write!(f, "malformed key"),
            CryptoError::Internal => write!(f, "internal cryptographic failure"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Associated data that binds a ciphertext to what it encrypts. Each
/// constructor yields a distinct, unambiguous byte string
/// (`cofferak/v2/<kind>` NUL `<id>`), so a ciphertext produced for one
/// context never authenticates under another.
pub struct Aad(Vec<u8>);

impl Aad {
    fn ctx(kind: &str, id: &str) -> Self {
        let mut v = Vec::with_capacity(16 + kind.len() + id.len());
        v.extend_from_slice(b"cofferak/v2/");
        v.extend_from_slice(kind.as_bytes());
        v.push(0);
        v.extend_from_slice(id.as_bytes());
        Aad(v)
    }

    /// For a secret stored at `path`.
    pub fn entry(path: &str) -> Self {
        Self::ctx("entry", path)
    }

    /// For the access token of service `service_id`.
    pub fn service_token(service_id: &str) -> Self {
        Self::ctx("service-token", service_id)
    }

    /// For this coffer's identity private key (ADR 0013).
    pub fn identity() -> Self {
        Self::ctx("identity", "")
    }

    /// For a trusted peer's public identity, by peer name (ADR 0013).
    pub fn peer(name: &str) -> Self {
        Self::ctx("peer", name)
    }

    fn host_wrap(host_id: &str) -> Self {
        Self::ctx("host-wrap", host_id)
    }

    fn root_wrap() -> Self {
        Self::ctx("root-wrap", "")
    }
}

/// A DEK wrapped under a symmetric host key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DekWrapHost {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// A DEK wrapped for the root key with the hybrid X25519 + ML-KEM-1024 KEM.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DekWrapRoot {
    pub ephemeral_pubkey: [u8; 32],
    pub mlkem_ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// A value encrypted under the vault's DEK.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptedEntry {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// The root public key: an X25519 key and an ML-KEM-1024 encapsulation key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootPublicKey {
    pub x25519: [u8; 32],
    pub mlkem1024: Vec<u8>,
}

impl RootPublicKey {
    /// Lowercase hex SHA-256 over both public keys — what `init --root`
    /// prints and `meta.json` records.
    pub fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"cofferak/v2/root-pubkey");
        h.update(self.x25519);
        h.update(&self.mlkem1024);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// The root private key. Zeroized on drop; `Debug` never prints key bytes.
pub struct RootPrivateKey {
    x25519: Zeroizing<[u8; 32]>,
    mlkem1024: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for RootPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RootPrivateKey(<redacted>)")
    }
}

const ROOT_KEY_ARMOR_BEGIN: &str = "-----BEGIN COFFERAK ROOT PRIVATE KEY-----";
const ROOT_KEY_ARMOR_END: &str = "-----END COFFERAK ROOT PRIVATE KEY-----";
const ROOT_KEY_VERSION: u8 = 2;

impl RootPrivateKey {
    /// Encode as an ASCII-armored block: base64 of
    /// `version(1) || x25519(32) || ml-kem-1024(3168) || sha256(prefix)[..4]`,
    /// wrapped at 64 columns. The checksum catches a truncated or mistyped
    /// key before any decryption is attempted.
    pub fn to_armored(&self) -> Zeroizing<String> {
        let mut raw = Zeroizing::new(Vec::with_capacity(1 + 32 + MLKEM1024_PRIVATE_KEY_LEN + 4));
        raw.push(ROOT_KEY_VERSION);
        raw.extend_from_slice(&*self.x25519);
        raw.extend_from_slice(&self.mlkem1024);
        let check = Sha256::digest(&raw[..]);
        raw.extend_from_slice(&check[..4]);
        let b64 = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(&raw[..]));
        let mut out = Zeroizing::new(String::with_capacity(b64.len() + b64.len() / 64 + 100));
        out.push_str(ROOT_KEY_ARMOR_BEGIN);
        out.push('\n');
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
            out.push('\n');
        }
        out.push_str(ROOT_KEY_ARMOR_END);
        out.push('\n');
        out
    }

    /// Parse the block produced by [`to_armored`](Self::to_armored).
    /// Whitespace and surrounding text outside the armor lines are ignored.
    pub fn from_armored(text: &str) -> Result<Self, CryptoError> {
        let start = text
            .find(ROOT_KEY_ARMOR_BEGIN)
            .ok_or(CryptoError::InvalidKey)?
            + ROOT_KEY_ARMOR_BEGIN.len();
        let end = text[start..]
            .find(ROOT_KEY_ARMOR_END)
            .ok_or(CryptoError::InvalidKey)?
            + start;
        let b64: Zeroizing<String> = Zeroizing::new(
            text[start..end]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect(),
        );
        let raw = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .map_err(|_| CryptoError::InvalidKey)?,
        );
        let want = 1 + 32 + MLKEM1024_PRIVATE_KEY_LEN + 4;
        if raw.len() != want || raw[0] != ROOT_KEY_VERSION {
            return Err(CryptoError::InvalidKey);
        }
        let (body, check) = raw.split_at(want - 4);
        if Sha256::digest(body)[..4] != *check {
            return Err(CryptoError::InvalidKey);
        }
        let mut x = Zeroizing::new([0u8; 32]);
        x.copy_from_slice(&body[1..33]);
        Ok(RootPrivateKey {
            x25519: x,
            mlkem1024: Zeroizing::new(body[33..].to_vec()),
        })
    }
}

/// AES-256-GCM-SIV (RFC 8452) through AWS-LC, which uses the CPU's AES
/// and carry-less-multiply instructions (AES-NI/PCLMUL on x86-64, the
/// ARMv8 crypto extensions on arm64). Output is the standard RFC 8452
/// ciphertext || tag; a test cross-checks it against an independent
/// implementation.
fn aead_key(key: &[u8; 32]) -> LessSafeKey {
    LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM_SIV, key).expect("a 32-byte key is valid for AES-256-GCM-SIV"),
    )
}

/// Encrypt under `key` with AES-256-GCM-SIV, a fresh random 96-bit nonce,
/// and `aad`. GCM-SIV is also nonce-misuse resistant: even a repeated
/// nonce reveals only whether two identical plaintexts were encrypted.
fn aead_encrypt(key: &[u8; 32], aad: &Aad, plaintext: &[u8]) -> ([u8; 12], Vec<u8>) {
    let mut nonce = [0u8; 12];
    aws_lc_rs::rand::fill(&mut nonce).expect("the system RNG is available");
    let mut in_out = Vec::with_capacity(plaintext.len() + AES_256_GCM_SIV.tag_len());
    in_out.extend_from_slice(plaintext);
    aead_key(key)
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            lc_aead::Aad::from(aad.0.as_slice()),
            &mut in_out,
        )
        .expect("AES-256-GCM-SIV encryption does not fail for valid inputs");
    (nonce, in_out)
}

fn aead_decrypt(
    key: &[u8; 32],
    aad: &Aad,
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ()> {
    let mut in_out = ciphertext.to_vec();
    let len = aead_key(key)
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            lc_aead::Aad::from(aad.0.as_slice()),
            &mut in_out,
        )
        .map_err(|_| ())?
        .len();
    in_out.truncate(len);
    Ok(in_out)
}

fn to_key32(v: Vec<u8>) -> Result<[u8; 32], CryptoError> {
    let v = Zeroizing::new(v);
    v.as_slice().try_into().map_err(|_| CryptoError::Unwrap)
}

/// Wrap `dek` for host `host_id` under its sealed `host_key`.
pub fn wrap_dek_for_host(dek: &[u8; 32], host_id: &str, host_key: &[u8; 32]) -> DekWrapHost {
    let (nonce, ciphertext) = aead_encrypt(host_key, &Aad::host_wrap(host_id), dek);
    DekWrapHost { nonce, ciphertext }
}

/// Unwrap a DEK wrapped by [`wrap_dek_for_host`] for the same `host_id`.
pub fn unwrap_dek_for_host(
    wrap: &DekWrapHost,
    host_id: &str,
    host_key: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let pt = aead_decrypt(
        host_key,
        &Aad::host_wrap(host_id),
        &wrap.nonce,
        &wrap.ciphertext,
    )
    .map_err(|_| CryptoError::Unwrap)?;
    to_key32(pt)
}

/// Generate a fresh root keypair (X25519 + ML-KEM-1024).
pub fn generate_root_keypair() -> Result<(RootPublicKey, RootPrivateKey), CryptoError> {
    let x_secret = StaticSecret::random_from_rng(OsRng);
    let x_public = PublicKey::from(&x_secret);

    let dk = DecapsulationKey::generate(&ML_KEM_1024).map_err(|_| CryptoError::Internal)?;
    let ek = dk.encapsulation_key().map_err(|_| CryptoError::Internal)?;
    let ek_bytes = ek.key_bytes().map_err(|_| CryptoError::Internal)?;
    let dk_bytes = dk.key_bytes().map_err(|_| CryptoError::Internal)?;

    let public = RootPublicKey {
        x25519: x_public.to_bytes(),
        mlkem1024: ek_bytes.as_ref().to_vec(),
    };
    let private = RootPrivateKey {
        x25519: Zeroizing::new(x_secret.to_bytes()),
        mlkem1024: Zeroizing::new(dk_bytes.as_ref().to_vec()),
    };
    Ok((public, private))
}

/// HKDF-SHA-384 over both shared secrets, binding the full transcript
/// (ephemeral X25519 key, root X25519 key, ML-KEM ciphertext, root ML-KEM key).
fn root_kek(
    x_ss: &[u8; 32],
    k_ss: &[u8],
    eph_pub: &[u8; 32],
    root: &RootPublicKey,
    mlkem_ct: &[u8],
) -> Result<KeyBytes, CryptoError> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(x_ss);
    ikm.extend_from_slice(k_ss);
    let mut info = Vec::with_capacity(64 + 32 * 2 + mlkem_ct.len() + root.mlkem1024.len());
    info.extend_from_slice(b"cofferak/v2/root-wrap-kek");
    info.extend_from_slice(eph_pub);
    info.extend_from_slice(&root.x25519);
    info.extend_from_slice(mlkem_ct);
    info.extend_from_slice(&root.mlkem1024);
    let mut okm = [0u8; 32];
    Hkdf::<Sha384>::new(None, &ikm)
        .expand(&info, &mut okm)
        .map_err(|_| CryptoError::Internal)?;
    let key = KeyBytes::new(okm);
    okm.zeroize();
    Ok(key)
}

/// Wrap `dek` for the root public key with the hybrid KEM.
pub fn wrap_dek_for_root(dek: &[u8; 32], root: &RootPublicKey) -> Result<DekWrapRoot, CryptoError> {
    let eph = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let x_ss = eph.diffie_hellman(&PublicKey::from(root.x25519));
    if !x_ss.was_contributory() {
        return Err(CryptoError::InvalidKey);
    }

    let ek = EncapsulationKey::new(&ML_KEM_1024, &root.mlkem1024)
        .map_err(|_| CryptoError::InvalidKey)?;
    let (ct, k_ss) = ek.encapsulate().map_err(|_| CryptoError::Internal)?;
    let mlkem_ciphertext = ct.as_ref().to_vec();

    let kek = root_kek(
        x_ss.as_bytes(),
        k_ss.as_ref(),
        &eph_pub,
        root,
        &mlkem_ciphertext,
    )?;
    let (nonce, ciphertext) = aead_encrypt(&kek, &Aad::root_wrap(), dek);
    Ok(DekWrapRoot {
        ephemeral_pubkey: eph_pub,
        mlkem_ciphertext,
        nonce,
        ciphertext,
    })
}

/// Unwrap a DEK wrapped by [`wrap_dek_for_root`]. `root` is the vault's
/// stored root public key (bound into the key derivation).
pub fn unwrap_dek_for_root(
    wrap: &DekWrapRoot,
    root: &RootPublicKey,
    private: &RootPrivateKey,
) -> Result<[u8; 32], CryptoError> {
    let x_secret = StaticSecret::from(*private.x25519);
    let x_ss = x_secret.diffie_hellman(&PublicKey::from(wrap.ephemeral_pubkey));
    if !x_ss.was_contributory() {
        return Err(CryptoError::Unwrap);
    }

    let dk = DecapsulationKey::new(&ML_KEM_1024, &private.mlkem1024)
        .map_err(|_| CryptoError::InvalidKey)?;
    let k_ss = dk
        .decapsulate(Ciphertext::from(wrap.mlkem_ciphertext.as_slice()))
        .map_err(|_| CryptoError::Unwrap)?;

    let kek = root_kek(
        x_ss.as_bytes(),
        k_ss.as_ref(),
        &wrap.ephemeral_pubkey,
        root,
        &wrap.mlkem_ciphertext,
    )?;
    let pt = aead_decrypt(&kek, &Aad::root_wrap(), &wrap.nonce, &wrap.ciphertext)
        .map_err(|_| CryptoError::Unwrap)?;
    to_key32(pt)
}

/// Encrypt a value under the vault DEK, bound to `aad`.
pub fn encrypt_entry(dek: &[u8; 32], aad: &Aad, plaintext: &[u8]) -> EncryptedEntry {
    let (nonce, ciphertext) = aead_encrypt(dek, aad, plaintext);
    EncryptedEntry { nonce, ciphertext }
}

/// Decrypt a value encrypted by [`encrypt_entry`] with the same `aad`.
pub fn decrypt_entry(
    dek: &[u8; 32],
    aad: &Aad,
    entry: &EncryptedEntry,
) -> Result<Vec<u8>, CryptoError> {
    aead_decrypt(dek, aad, &entry.nonce, &entry.ciphertext).map_err(|_| CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEK: [u8; 32] = [0x42; 32];

    #[test]
    fn host_wrap_round_trips_and_is_bound_to_key_and_host_id() {
        let key = [0x11; 32];
        let w = wrap_dek_for_host(&DEK, "host-a", &key);
        assert_eq!(unwrap_dek_for_host(&w, "host-a", &key).unwrap(), DEK);
        assert_eq!(
            unwrap_dek_for_host(&w, "host-a", &[0x22; 32]),
            Err(CryptoError::Unwrap)
        );
        assert_eq!(
            unwrap_dek_for_host(&w, "host-b", &key),
            Err(CryptoError::Unwrap)
        );
    }

    #[test]
    fn root_wrap_round_trips_with_hybrid_kem() {
        let (public, private) = generate_root_keypair().unwrap();
        assert_eq!(public.mlkem1024.len(), MLKEM1024_PUBLIC_KEY_LEN);
        let w = wrap_dek_for_root(&DEK, &public).unwrap();
        assert_eq!(w.mlkem_ciphertext.len(), MLKEM1024_CIPHERTEXT_LEN);
        assert_eq!(unwrap_dek_for_root(&w, &public, &private).unwrap(), DEK);
    }

    #[test]
    fn root_wrap_fails_with_another_private_key() {
        let (public, _) = generate_root_keypair().unwrap();
        let (_, other) = generate_root_keypair().unwrap();
        let w = wrap_dek_for_root(&DEK, &public).unwrap();
        assert!(unwrap_dek_for_root(&w, &public, &other).is_err());
    }

    #[test]
    fn root_wrap_needs_both_kem_halves() {
        // Tampering with either KEM component must break the unwrap: the
        // derived key depends on both shared secrets.
        let (public, private) = generate_root_keypair().unwrap();
        let w = wrap_dek_for_root(&DEK, &public).unwrap();

        let mut bad_x = w.clone();
        bad_x.ephemeral_pubkey = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes();
        assert!(unwrap_dek_for_root(&bad_x, &public, &private).is_err());

        let mut bad_k = w.clone();
        bad_k.mlkem_ciphertext[0] ^= 1;
        assert!(unwrap_dek_for_root(&bad_k, &public, &private).is_err());

        let mut bad_ct = w;
        bad_ct.ciphertext[0] ^= 1;
        assert!(unwrap_dek_for_root(&bad_ct, &public, &private).is_err());
    }

    #[test]
    fn root_private_key_armor_round_trips_and_detects_corruption() {
        let (public, private) = generate_root_keypair().unwrap();
        let armored = private.to_armored();
        assert!(armored.starts_with(ROOT_KEY_ARMOR_BEGIN));
        let parsed = RootPrivateKey::from_armored(&format!("note\n{}\ntrailer", *armored)).unwrap();
        let w = wrap_dek_for_root(&DEK, &public).unwrap();
        assert_eq!(unwrap_dek_for_root(&w, &public, &parsed).unwrap(), DEK);

        // Flip one base64 character in the body: checksum must reject it.
        let mut chars: Vec<char> = armored.chars().collect();
        let i = ROOT_KEY_ARMOR_BEGIN.len() + 10;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let corrupted: String = chars.into_iter().collect();
        assert_eq!(
            RootPrivateKey::from_armored(&corrupted).unwrap_err(),
            CryptoError::InvalidKey
        );
        assert_eq!(
            RootPrivateKey::from_armored("garbage").unwrap_err(),
            CryptoError::InvalidKey
        );
        assert!(!format!("{private:?}").contains(&armored[60..80]));
    }

    #[test]
    fn entry_round_trips_and_is_bound_to_its_path() {
        let e = encrypt_entry(&DEK, &Aad::entry("app/A"), b"secret-a");
        assert_eq!(
            decrypt_entry(&DEK, &Aad::entry("app/A"), &e).unwrap(),
            b"secret-a"
        );
        // Same ciphertext presented under another path or as a token: rejected.
        assert_eq!(
            decrypt_entry(&DEK, &Aad::entry("app/B"), &e),
            Err(CryptoError::Decrypt)
        );
        assert_eq!(
            decrypt_entry(&DEK, &Aad::service_token("app/A"), &e),
            Err(CryptoError::Decrypt)
        );
    }

    #[test]
    fn entry_round_trips_empty_input_and_rejects_tampering() {
        let aad = Aad::entry("p");
        let e = encrypt_entry(&DEK, &aad, b"");
        assert_eq!(decrypt_entry(&DEK, &aad, &e).unwrap(), b"");
        let mut t = encrypt_entry(&DEK, &aad, b"data");
        t.ciphertext[0] ^= 1;
        assert_eq!(decrypt_entry(&DEK, &aad, &t), Err(CryptoError::Decrypt));
    }

    #[test]
    fn aad_contexts_are_unambiguous() {
        // "entry" NUL "a" must differ from e.g. kind "entr" + id "y\0a".
        assert_ne!(Aad::entry("x").0, Aad::service_token("x").0);
        assert_ne!(Aad::entry("a/b").0, Aad::entry("a").0);
    }

    #[test]
    fn fingerprint_covers_both_public_keys() {
        let (a, _) = generate_root_keypair().unwrap();
        let mut b = a.clone();
        b.mlkem1024[0] ^= 1;
        assert_ne!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.fingerprint().len(), 64);
    }

    #[test]
    fn aead_output_is_standard_rfc8452_and_interoperates() {
        // Cross-check against an independent AES-256-GCM-SIV implementation
        // (RustCrypto `aes-gcm-siv`, NCC Group audited) in both directions.
        use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
        use aes_gcm_siv::{Aes256GcmSiv, Nonce as RcNonce};
        let key = [0x5Au8; 32];
        let aad = Aad::entry("app/X");
        let rc = Aes256GcmSiv::new_from_slice(&key).unwrap();

        let (nonce, ct) = aead_encrypt(&key, &aad, b"interop");
        let pt = rc
            .decrypt(
                RcNonce::from_slice(&nonce),
                Payload {
                    msg: &ct,
                    aad: &aad.0,
                },
            )
            .unwrap();
        assert_eq!(pt, b"interop");

        let ct2 = rc
            .encrypt(
                RcNonce::from_slice(&nonce),
                Payload {
                    msg: b"other way",
                    aad: &aad.0,
                },
            )
            .unwrap();
        assert_eq!(
            aead_decrypt(&key, &aad, &nonce, &ct2).unwrap(),
            b"other way"
        );
    }

    #[test]
    fn key_bytes_derefs_to_inner_bytes() {
        assert_eq!(*KeyBytes::new([7u8; 32]), [7u8; 32]);
    }
}
