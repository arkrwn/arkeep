//! Envelope encryption primitives for mikvault.
//!
//! This module provides the cryptographic building blocks for the vault's
//! envelope encryption scheme:
//!
//! - A per-entry data-encryption key (DEK) encrypts individual vault entries
//!   with AES-256-GCM-SIV (`encrypt_entry` / `decrypt_entry`).
//! - The DEK itself is "wrapped" (encrypted) two ways so it can be recovered
//!   by different holders:
//!   - Wrapped for the local host under a symmetric host key
//!     (`wrap_dek_for_host` / `unwrap_dek_for_host`), also AES-256-GCM-SIV.
//!   - Wrapped for the root keypair using an ECIES-style construction over
//!     X25519 (`wrap_dek_for_root` / `unwrap_dek_for_root`): a fresh
//!     ephemeral X25519 keypair is generated per call, a shared secret is
//!     computed with the root's public key, and that shared secret is used
//!     directly as an AES-256-GCM-SIV key to encrypt the DEK.

use std::fmt;
use std::ops::Deref;

use aes_gcm_siv::aead::{Aead, AeadCore, KeyInit};
use aes_gcm_siv::{Aes256GcmSiv, Key as AesKey, Nonce as AesNonce};
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

/// A 32-byte key buffer that is zeroized when dropped.
///
/// Used to hold long-lived symmetric/secret key material so it does not
/// linger in memory after it is no longer needed.
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
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Unwrap => write!(f, "failed to unwrap key"),
            CryptoError::Decrypt => write!(f, "failed to decrypt entry"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// A DEK wrapped (encrypted) under a symmetric host key.
pub struct DekWrapHost {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// A DEK wrapped (encrypted) for a root X25519 keypair, ECIES-style.
pub struct DekWrapRoot {
    pub ephemeral_pubkey: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// A vault entry encrypted under the vault's DEK.
pub struct EncryptedEntry {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Encrypt `plaintext` under `key_bytes` with AES-256-GCM-SIV and a fresh
/// random nonce.
fn aead_encrypt(key_bytes: &[u8; 32], plaintext: &[u8]) -> ([u8; 12], Vec<u8>) {
    let cipher = Aes256GcmSiv::new(AesKey::<Aes256GcmSiv>::from_slice(key_bytes));
    let nonce = Aes256GcmSiv::generate_nonce(OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("AES-256-GCM-SIV encryption does not fail for valid inputs");
    (nonce.into(), ciphertext)
}

/// Decrypt `ciphertext` under `key_bytes` with AES-256-GCM-SIV. Returns an
/// opaque error on authentication/decryption failure.
fn aead_decrypt(key_bytes: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
    let cipher = Aes256GcmSiv::new(AesKey::<Aes256GcmSiv>::from_slice(key_bytes));
    let nonce = AesNonce::from_slice(nonce);
    cipher.decrypt(nonce, ciphertext).map_err(|_| ())
}

/// Wrap `dek` under a symmetric `host_key` (AES-256-GCM-SIV).
pub fn wrap_dek_for_host(dek: &[u8; 32], host_key: &[u8; 32]) -> DekWrapHost {
    let (nonce, ciphertext) = aead_encrypt(host_key, dek);
    DekWrapHost { nonce, ciphertext }
}

/// Unwrap a DEK previously wrapped with [`wrap_dek_for_host`].
pub fn unwrap_dek_for_host(
    wrap: &DekWrapHost,
    host_key: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let plaintext = aead_decrypt(host_key, &wrap.nonce, &wrap.ciphertext)
        .map_err(|_| CryptoError::Unwrap)?;
    plaintext.try_into().map_err(|_| CryptoError::Unwrap)
}

/// Generate a fresh X25519 root keypair, returning `(pubkey, privkey)`.
pub fn generate_root_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (public.to_bytes(), secret.to_bytes())
}

/// Wrap `dek` for a root X25519 public key using an ECIES-style
/// construction: a fresh ephemeral X25519 keypair is generated, a shared
/// secret is derived with `root_pubkey`, and that shared secret is used
/// directly as the AES-256-GCM-SIV key.
pub fn wrap_dek_for_root(dek: &[u8; 32], root_pubkey: &[u8; 32]) -> DekWrapRoot {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pubkey = PublicKey::from(&ephemeral_secret).to_bytes();
    let root_public = PublicKey::from(*root_pubkey);
    let shared_secret = ephemeral_secret.diffie_hellman(&root_public);
    let key = KeyBytes::new(shared_secret.to_bytes());

    let (nonce, ciphertext) = aead_encrypt(&key, dek);
    DekWrapRoot {
        ephemeral_pubkey,
        nonce,
        ciphertext,
    }
}

/// Unwrap a DEK previously wrapped with [`wrap_dek_for_root`], given the
/// root private key.
pub fn unwrap_dek_for_root(
    wrap: &DekWrapRoot,
    root_privkey: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let root_secret = StaticSecret::from(*root_privkey);
    let ephemeral_public = PublicKey::from(wrap.ephemeral_pubkey);
    let shared_secret = root_secret.diffie_hellman(&ephemeral_public);
    let key = KeyBytes::new(shared_secret.to_bytes());

    let plaintext = aead_decrypt(&key, &wrap.nonce, &wrap.ciphertext)
        .map_err(|_| CryptoError::Unwrap)?;
    plaintext.try_into().map_err(|_| CryptoError::Unwrap)
}

/// Encrypt a vault entry's plaintext under the vault DEK.
pub fn encrypt_entry(dek: &[u8; 32], plaintext: &[u8]) -> EncryptedEntry {
    let (nonce, ciphertext) = aead_encrypt(dek, plaintext);
    EncryptedEntry { nonce, ciphertext }
}

/// Decrypt a vault entry previously encrypted with [`encrypt_entry`].
pub fn decrypt_entry(dek: &[u8; 32], entry: &EncryptedEntry) -> Result<Vec<u8>, CryptoError> {
    aead_decrypt(dek, &entry.nonce, &entry.ciphertext).map_err(|_| CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_dek() -> [u8; 32] {
        [0x42; 32]
    }

    #[test]
    fn wrap_unwrap_dek_for_host_round_trips() {
        let dek = sample_dek();
        let host_key = [0x11; 32];

        let wrapped = wrap_dek_for_host(&dek, &host_key);
        let unwrapped = unwrap_dek_for_host(&wrapped, &host_key).expect("unwrap should succeed");

        assert_eq!(unwrapped, dek);
    }

    #[test]
    fn unwrap_dek_for_host_with_wrong_key_fails() {
        let dek = sample_dek();
        let host_key = [0x11; 32];
        let wrong_key = [0x22; 32];

        let wrapped = wrap_dek_for_host(&dek, &host_key);
        let result = unwrap_dek_for_host(&wrapped, &wrong_key);

        assert_eq!(result, Err(CryptoError::Unwrap));
    }

    #[test]
    fn wrap_unwrap_dek_for_root_round_trips() {
        let dek = sample_dek();
        let (root_pubkey, root_privkey) = generate_root_keypair();

        let wrapped = wrap_dek_for_root(&dek, &root_pubkey);
        let unwrapped =
            unwrap_dek_for_root(&wrapped, &root_privkey).expect("unwrap should succeed");

        assert_eq!(unwrapped, dek);
    }

    #[test]
    fn unwrap_dek_for_root_with_wrong_private_key_fails() {
        let dek = sample_dek();
        let (root_pubkey, _root_privkey) = generate_root_keypair();
        let (_other_pubkey, other_privkey) = generate_root_keypair();

        let wrapped = wrap_dek_for_root(&dek, &root_pubkey);
        let result = unwrap_dek_for_root(&wrapped, &other_privkey);

        assert_eq!(result, Err(CryptoError::Unwrap));
    }

    #[test]
    fn encrypt_decrypt_entry_round_trips_arbitrary_bytes() {
        let dek = sample_dek();
        let plaintext = b"super secret entry contents, with \x00 and \xff bytes".to_vec();

        let entry = encrypt_entry(&dek, &plaintext);
        let decrypted = decrypt_entry(&dek, &entry).expect("decrypt should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_entry_round_trips_empty_input() {
        let dek = sample_dek();
        let plaintext: Vec<u8> = Vec::new();

        let entry = encrypt_entry(&dek, &plaintext);
        let decrypted = decrypt_entry(&dek, &entry).expect("decrypt should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_entry_with_flipped_ciphertext_byte_fails_without_panic() {
        let dek = sample_dek();
        let plaintext = b"some data to protect".to_vec();

        let mut entry = encrypt_entry(&dek, &plaintext);
        entry.ciphertext[0] ^= 0x01;

        let result = decrypt_entry(&dek, &entry);

        assert_eq!(result, Err(CryptoError::Decrypt));
    }

    #[test]
    fn key_bytes_derefs_to_inner_bytes() {
        let key = KeyBytes::new([7u8; 32]);
        assert_eq!(*key, [7u8; 32]);
    }
}
