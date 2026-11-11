//! Coffer identities and signed, encrypted transfers between coffers
//! (ADR 0013).
//!
//! Every coffer can have one **identity**: a long-term keypair used only to
//! receive and send transfers.
//!
//! - encryption: X25519 + ML-KEM-1024 (hybrid, like the recovery wrap);
//! - signatures: ECDSA P-384 + ML-DSA-87 (hybrid; both must verify).
//!
//! The private half lives inside `vault.cofferak`, encrypted under the
//! coffer's DEK, so a coffer still has exactly one master key and nothing
//! extra to store. The public half is shared as a one-line text file
//! (`COFFERAK-IDENTITY-1:<base64>`) and recorded by the other side as a
//! trusted **peer**.
//!
//! A transfer ([`seal_transfer`]) is a [`Bundle`] encrypted so only the
//! recipient coffer can open it (AES-256-GCM-SIV under a key from
//! HKDF-SHA-384 over both KEM shared secrets and the transcript) and
//! signed by the sender over every byte. [`open_transfer`] checks it was
//! addressed to this coffer, verifies both signatures with the sender's
//! embedded public identity, then decrypts. The caller decides whether the
//! sender is trusted (by fingerprint) before applying anything.

use std::fmt;

use aws_lc_rs::aead::{Aad as LcAad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM_SIV};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_1024};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    EcdsaKeyPair, KeyPair, PqdsaKeyPair, UnparsedPublicKey, ECDSA_P384_SHA384_ASN1,
    ECDSA_P384_SHA384_ASN1_SIGNING, ML_DSA_87, ML_DSA_87_SIGNING,
};
use base64::Engine as _;
use bincode::Options as _;
use hkdf::Hkdf;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::bundle::{Bundle, MAX_BUNDLE_BYTES};

const TEXT_PREFIX: &str = "COFFERAK-IDENTITY-1:";
const MAGIC: &[u8; 8] = b"CFKEXPT2";
const VERSION: u16 = 1;

/// Errors from identity and transfer operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// Malformed identity text or key material.
    InvalidIdentity,
    /// Not a transfer bundle, or a version this build doesn't know.
    NotATransfer,
    /// The transfer was made for a different coffer.
    WrongRecipient,
    /// A signature didn't verify, or the bundle was modified/truncated.
    BadSignatureOrCorrupt,
    /// The cryptographic library reported an internal failure.
    Internal,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::InvalidIdentity => write!(f, "not a valid cofferak identity"),
            IdentityError::NotATransfer => write!(
                f,
                "not a cofferak transfer bundle (or an unsupported version)"
            ),
            IdentityError::WrongRecipient => {
                write!(f, "this bundle was made for a different coffer")
            }
            IdentityError::BadSignatureOrCorrupt => {
                write!(
                    f,
                    "signature check failed: the bundle was modified, truncated or forged"
                )
            }
            IdentityError::Internal => write!(f, "internal cryptographic failure"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// The public half of a coffer identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityPublic {
    pub x25519: [u8; 32],
    pub mlkem1024: Vec<u8>,
    /// Uncompressed P-384 point.
    pub ecdsa_p384: Vec<u8>,
    /// ML-DSA-87 public key (DER SubjectPublicKeyInfo).
    pub mldsa87: Vec<u8>,
}

/// The private half of a coffer identity. Zeroized on drop; never printed.
#[derive(Clone, Serialize, Deserialize)]
pub struct IdentitySecret {
    x25519: [u8; 32],
    mlkem_dk: Vec<u8>,
    ecdsa_pkcs8: Vec<u8>,
    mldsa_pkcs8: Vec<u8>,
    public: IdentityPublic,
}

impl Drop for IdentitySecret {
    fn drop(&mut self) {
        self.x25519.zeroize();
        self.mlkem_dk.zeroize();
        self.ecdsa_pkcs8.zeroize();
        self.mldsa_pkcs8.zeroize();
    }
}

impl fmt::Debug for IdentitySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdentitySecret(<redacted>)")
    }
}

fn opts() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(MAX_BUNDLE_BYTES)
}

impl IdentityPublic {
    /// SHA-256 over a domain label and the encoded public keys, as 64 hex
    /// characters.
    pub fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"cofferak/v2/identity");
        h.update(opts().serialize(self).expect("encodes"));
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The fingerprint grouped for reading aloud / comparing by eye:
    /// first 32 hex characters in groups of four.
    pub fn short_fingerprint(&self) -> String {
        let fp = self.fingerprint();
        fp.as_bytes()[..32]
            .chunks(4)
            .map(|c| std::str::from_utf8(c).expect("hex"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// One-line text form to share: `COFFERAK-IDENTITY-1:<base64>`.
    pub fn to_text(&self) -> String {
        let bytes = opts().serialize(self).expect("encodes");
        format!(
            "{TEXT_PREFIX}{}",
            base64::engine::general_purpose::STANDARD.encode(bytes)
        )
    }

    /// Parse [`to_text`](Self::to_text) output; surrounding whitespace and
    /// other lines (comments) are ignored.
    pub fn from_text(text: &str) -> Result<Self, IdentityError> {
        let line = text
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with(TEXT_PREFIX))
            .ok_or(IdentityError::InvalidIdentity)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&line[TEXT_PREFIX.len()..])
            .map_err(|_| IdentityError::InvalidIdentity)?;
        let p: IdentityPublic = opts()
            .deserialize(&bytes)
            .map_err(|_| IdentityError::InvalidIdentity)?;
        // Structural checks: each key must parse.
        EncapsulationKey::new(&ML_KEM_1024, &p.mlkem1024)
            .map_err(|_| IdentityError::InvalidIdentity)?;
        if p.ecdsa_p384.len() != 97 || p.ecdsa_p384[0] != 0x04 || p.mldsa87.is_empty() {
            return Err(IdentityError::InvalidIdentity);
        }
        Ok(p)
    }
}

impl IdentitySecret {
    /// Generate a fresh identity.
    pub fn generate() -> Result<Self, IdentityError> {
        let x = StaticSecret::random_from_rng(OsRng);
        let dk = DecapsulationKey::generate(&ML_KEM_1024).map_err(|_| IdentityError::Internal)?;
        let ek = dk
            .encapsulation_key()
            .map_err(|_| IdentityError::Internal)?;
        let rng = SystemRandom::new();
        let ecdsa_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng)
            .map_err(|_| IdentityError::Internal)?;
        let ecdsa = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, ecdsa_pkcs8.as_ref())
            .map_err(|_| IdentityError::Internal)?;
        let mldsa =
            PqdsaKeyPair::generate(&ML_DSA_87_SIGNING).map_err(|_| IdentityError::Internal)?;
        let mldsa_pkcs8 = mldsa.to_pkcs8v1().map_err(|_| IdentityError::Internal)?;
        let public = IdentityPublic {
            x25519: PublicKey::from(&x).to_bytes(),
            mlkem1024: ek
                .key_bytes()
                .map_err(|_| IdentityError::Internal)?
                .as_ref()
                .to_vec(),
            ecdsa_p384: ecdsa.public_key().as_ref().to_vec(),
            mldsa87: mldsa
                .public_key()
                .as_der()
                .map_err(|_| IdentityError::Internal)?
                .as_ref()
                .to_vec(),
        };
        Ok(IdentitySecret {
            x25519: x.to_bytes(),
            mlkem_dk: dk
                .key_bytes()
                .map_err(|_| IdentityError::Internal)?
                .as_ref()
                .to_vec(),
            ecdsa_pkcs8: ecdsa_pkcs8.as_ref().to_vec(),
            mldsa_pkcs8: mldsa_pkcs8.as_ref().to_vec(),
            public,
        })
    }

    pub fn public(&self) -> &IdentityPublic {
        &self.public
    }

    /// Encode for storage inside the vault (the caller encrypts it).
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(opts().serialize(self).expect("encodes"))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        opts()
            .deserialize(bytes)
            .map_err(|_| IdentityError::InvalidIdentity)
    }

    fn sign(&self, msg: &[u8]) -> Result<(Vec<u8>, Vec<u8>), IdentityError> {
        let rng = SystemRandom::new();
        let ecdsa = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &self.ecdsa_pkcs8)
            .map_err(|_| IdentityError::Internal)?;
        let s1 = ecdsa.sign(&rng, msg).map_err(|_| IdentityError::Internal)?;
        let mldsa = PqdsaKeyPair::from_pkcs8(&ML_DSA_87_SIGNING, &self.mldsa_pkcs8)
            .map_err(|_| IdentityError::Internal)?;
        let mut s2 = vec![0u8; ML_DSA_87_SIGNING.signature_len()];
        let n = mldsa
            .sign(msg, &mut s2)
            .map_err(|_| IdentityError::Internal)?;
        s2.truncate(n);
        Ok((s1.as_ref().to_vec(), s2))
    }
}

fn verify(public: &IdentityPublic, msg: &[u8], s1: &[u8], s2: &[u8]) -> Result<(), IdentityError> {
    UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, &public.ecdsa_p384)
        .verify(msg, s1)
        .map_err(|_| IdentityError::BadSignatureOrCorrupt)?;
    UnparsedPublicKey::new(&ML_DSA_87, &public.mldsa87)
        .verify(msg, s2)
        .map_err(|_| IdentityError::BadSignatureOrCorrupt)?;
    Ok(())
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or(0);
    }
    out
}

fn transfer_key(
    x_ss: &[u8],
    k_ss: &[u8],
    recipient_fp: &[u8; 32],
    sender_fp: &str,
    eph: &[u8; 32],
    mlkem_ct: &[u8],
) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(x_ss);
    ikm.extend_from_slice(k_ss);
    let mut info = Vec::with_capacity(64 + 32 + 64 + 32 + mlkem_ct.len());
    info.extend_from_slice(b"cofferak/v2/transfer-key");
    info.extend_from_slice(recipient_fp);
    info.extend_from_slice(sender_fp.as_bytes());
    info.extend_from_slice(eph);
    info.extend_from_slice(mlkem_ct);
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha384>::new(None, &ikm)
        .expand(&info, &mut key[..])
        .map_err(|_| IdentityError::Internal)?;
    Ok(key)
}

fn put_len_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

/// True if `bytes` starts like a transfer bundle (vs. a passphrase bundle).
pub fn is_transfer(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && &bytes[..8] == MAGIC
}

/// Encrypt `bundle` for `recipient` and sign it as `sender`.
pub fn seal_transfer(
    bundle: &Bundle,
    sender: &IdentitySecret,
    recipient: &IdentityPublic,
) -> Result<Vec<u8>, IdentityError> {
    let recipient_fp = hex32(&recipient.fingerprint());
    let sender_fp = sender.public.fingerprint();
    let sender_pub = opts()
        .serialize(&sender.public)
        .map_err(|_| IdentityError::Internal)?;

    let eph = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let x_ss = eph.diffie_hellman(&PublicKey::from(recipient.x25519));
    if !x_ss.was_contributory() {
        return Err(IdentityError::InvalidIdentity);
    }
    let ek = EncapsulationKey::new(&ML_KEM_1024, &recipient.mlkem1024)
        .map_err(|_| IdentityError::InvalidIdentity)?;
    let (ct, k_ss) = ek.encapsulate().map_err(|_| IdentityError::Internal)?;
    let key = transfer_key(
        x_ss.as_bytes(),
        k_ss.as_ref(),
        &recipient_fp,
        &sender_fp,
        &eph_pub,
        ct.as_ref(),
    )?;

    let mut nonce = [0u8; 12];
    aws_lc_rs::rand::fill(&mut nonce).map_err(|_| IdentityError::Internal)?;

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&recipient_fp);
    put_len_bytes(&mut out, &sender_pub);
    out.extend_from_slice(&eph_pub);
    put_len_bytes(&mut out, ct.as_ref());
    out.extend_from_slice(&nonce);
    let header_len = out.len();

    let mut payload = Zeroizing::new(
        opts()
            .serialize(bundle)
            .map_err(|_| IdentityError::Internal)?,
    );
    LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM_SIV, &key[..]).map_err(|_| IdentityError::Internal)?,
    )
    .seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        LcAad::from(&out[..header_len]),
        &mut *payload,
    )
    .map_err(|_| IdentityError::Internal)?;
    put_len_bytes(&mut out, &payload);

    let (s1, s2) = sender.sign(&out)?;
    put_len_bytes(&mut out, &s1);
    put_len_bytes(&mut out, &s2);
    Ok(out)
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], IdentityError> {
        let end = self.i.checked_add(n).ok_or(IdentityError::NotATransfer)?;
        let s = self
            .b
            .get(self.i..end)
            .ok_or(IdentityError::BadSignatureOrCorrupt)?;
        self.i = end;
        Ok(s)
    }
    fn len_bytes(&mut self) -> Result<&'a [u8], IdentityError> {
        let n = u32::from_le_bytes(self.take(4)?.try_into().expect("4 bytes")) as usize;
        self.take(n)
    }
}

/// Verify and decrypt a transfer addressed to `recipient`. Returns the
/// sender's public identity (verified: both signatures over the whole
/// bundle) and the decrypted bundle. The caller must still check that the
/// sender is a trusted peer before using the contents.
pub fn open_transfer(
    bytes: &[u8],
    recipient: &IdentitySecret,
) -> Result<(IdentityPublic, Bundle), IdentityError> {
    if bytes.len() as u64 > MAX_BUNDLE_BYTES || !is_transfer(bytes) {
        return Err(IdentityError::NotATransfer);
    }
    let mut r = Reader { b: bytes, i: 8 };
    let version = u16::from_le_bytes(r.take(2)?.try_into().expect("2 bytes"));
    if version != VERSION {
        return Err(IdentityError::NotATransfer);
    }
    let recipient_fp: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
    if recipient_fp != hex32(&recipient.public.fingerprint()) {
        return Err(IdentityError::WrongRecipient);
    }
    let sender_pub_bytes = r.len_bytes()?;
    let eph: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
    let mlkem_ct = r.len_bytes()?;
    let nonce: [u8; 12] = r.take(12)?.try_into().expect("12 bytes");
    let header_end = r.i;
    let ciphertext = r.len_bytes()?;
    let signed_end = r.i;
    let s1 = r.len_bytes()?;
    let s2 = r.len_bytes()?;
    if r.i != bytes.len() {
        return Err(IdentityError::BadSignatureOrCorrupt);
    }

    let sender: IdentityPublic = opts()
        .deserialize(sender_pub_bytes)
        .map_err(|_| IdentityError::BadSignatureOrCorrupt)?;
    verify(&sender, &bytes[..signed_end], s1, s2)?;

    let x = StaticSecret::from(recipient.x25519);
    let x_ss = x.diffie_hellman(&PublicKey::from(eph));
    if !x_ss.was_contributory() {
        return Err(IdentityError::BadSignatureOrCorrupt);
    }
    let dk = DecapsulationKey::new(&ML_KEM_1024, &recipient.mlkem_dk)
        .map_err(|_| IdentityError::Internal)?;
    let k_ss = dk
        .decapsulate(Ciphertext::from(mlkem_ct))
        .map_err(|_| IdentityError::BadSignatureOrCorrupt)?;
    let key = transfer_key(
        x_ss.as_bytes(),
        k_ss.as_ref(),
        &recipient_fp,
        &sender.fingerprint(),
        &eph,
        mlkem_ct,
    )?;
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let plain = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM_SIV, &key[..]).map_err(|_| IdentityError::Internal)?,
    )
    .open_in_place(
        Nonce::assume_unique_for_key(nonce),
        LcAad::from(&bytes[..header_end]),
        &mut buf,
    )
    .map_err(|_| IdentityError::BadSignatureOrCorrupt)?;
    let bundle: Bundle = opts()
        .deserialize(plain)
        .map_err(|_| IdentityError::BadSignatureOrCorrupt)?;
    Ok((sender, bundle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::BundleEntry;

    fn sample() -> Bundle {
        Bundle {
            created_at: 1,
            source_fingerprint: "src".into(),
            entries: vec![BundleEntry {
                path: "app/KEY".into(),
                value: b"secret-value".to_vec(),
                version: 1,
                updated_at: 2,
            }],
            services: vec![],
        }
    }

    #[test]
    fn transfer_round_trip_between_two_coffers() {
        let mac = IdentitySecret::generate().unwrap();
        let server = IdentitySecret::generate().unwrap();
        let bytes = seal_transfer(&sample(), &mac, server.public()).unwrap();
        let (from, b) = open_transfer(&bytes, &server).unwrap();
        assert_eq!(from.fingerprint(), mac.public().fingerprint());
        assert_eq!(b.entries, sample().entries);
        assert!(!String::from_utf8_lossy(&bytes).contains("secret-value"));
    }

    #[test]
    fn only_the_recipient_can_open_it() {
        let mac = IdentitySecret::generate().unwrap();
        let server = IdentitySecret::generate().unwrap();
        let other = IdentitySecret::generate().unwrap();
        let bytes = seal_transfer(&sample(), &mac, server.public()).unwrap();
        assert_eq!(
            open_transfer(&bytes, &other).unwrap_err(),
            IdentityError::WrongRecipient
        );
    }

    #[test]
    fn any_modification_breaks_the_signature() {
        let mac = IdentitySecret::generate().unwrap();
        let server = IdentitySecret::generate().unwrap();
        let bytes = seal_transfer(&sample(), &mac, server.public()).unwrap();
        for i in [12usize, 60, bytes.len() / 2, bytes.len() - 10] {
            let mut t = bytes.clone();
            t[i] ^= 1;
            assert!(
                open_transfer(&t, &server).is_err(),
                "byte {i} flip accepted"
            );
        }
        assert!(open_transfer(&bytes[..bytes.len() - 1], &server).is_err());
    }

    #[test]
    fn a_forger_cannot_impersonate_a_sender() {
        // An attacker who knows the server's public identity can build a
        // valid bundle, but only signed with their own identity: the
        // verified sender returned is the attacker, never the claimed peer.
        let mac = IdentitySecret::generate().unwrap();
        let server = IdentitySecret::generate().unwrap();
        let attacker = IdentitySecret::generate().unwrap();
        let forged = seal_transfer(&sample(), &attacker, server.public()).unwrap();
        let (from, _) = open_transfer(&forged, &server).unwrap();
        assert_ne!(from.fingerprint(), mac.public().fingerprint());
        // Swapping in the mac's public identity breaks the signature.
        let mac_pub = opts().serialize(mac.public()).unwrap();
        let att_pub = opts().serialize(attacker.public()).unwrap();
        let pos = forged
            .windows(att_pub.len())
            .position(|w| w == att_pub.as_slice())
            .unwrap();
        assert_eq!(mac_pub.len(), att_pub.len());
        let mut swapped = forged.clone();
        swapped[pos..pos + mac_pub.len()].copy_from_slice(&mac_pub);
        assert_eq!(
            open_transfer(&swapped, &server).unwrap_err(),
            IdentityError::BadSignatureOrCorrupt
        );
    }

    #[test]
    fn identity_text_and_secret_round_trip() {
        let id = IdentitySecret::generate().unwrap();
        let text = id.public().to_text();
        assert!(text.starts_with(TEXT_PREFIX) && !text.contains('\n'));
        let parsed = IdentityPublic::from_text(&format!("# my mac\n{text}\n")).unwrap();
        assert_eq!(&parsed, id.public());
        assert!(IdentityPublic::from_text("COFFERAK-IDENTITY-1:AAAA").is_err());
        let back = IdentitySecret::from_bytes(&id.to_bytes()).unwrap();
        assert_eq!(back.public(), id.public());
        assert_eq!(id.public().short_fingerprint().len(), 39);
        assert_eq!(format!("{id:?}"), "IdentitySecret(<redacted>)");
    }
}
