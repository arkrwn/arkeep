//! macOS `HostSeal` backend: stores the key as a generic password item in
//! the user's Keychain via `security-framework`.
//!
//! Unlike the Linux backend (`systemd-creds`), the Keychain *is* the
//! persistent store rather than a stateless encrypt/decrypt facility:
//! [`KeychainSeal::seal`] writes the raw 32-byte key into a keychain item
//! named by `service`/`account`, and [`KeychainSeal::unseal`] reads it back
//! out by that same name. The [`SealedBlob`] returned by `seal` therefore
//! carries no key material of its own (unlike the Linux backend's, which
//! is the `systemd-creds`-encrypted bytes) - it's just a marker that lets
//! `unseal` reject a blob that obviously didn't come from this backend,
//! while the real secret lives in the Keychain under this backend's
//! `service`/`account`.
//!
//! Access control: a generic-password item created via `SecItemAdd`
//! without an explicit ACL gets the default ACL, which restricts access to
//! the creating application/process by default. Pinning the ACL to a
//! specific code-signature identity requirement (so a different binary
//! running as the same user still can't read the item) is a documented
//! follow-up, not implemented here.

use security_framework::base::Error as SfError;
use security_framework::passwords::{get_generic_password, set_generic_password};

use super::{HostSeal, SealError, SealedBlob};

/// `errSecItemNotFound` from Security framework's `SecBase.h`: no keychain
/// item matched the query.
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

/// `errSecInteractionNotAllowed` from `SecBase.h`: the keychain exists but
/// can't be used right now (e.g. locked, or no session to prompt the
/// user) - the macOS analogue of the Linux backend's "binary not
/// spawnable".
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

/// `errSecNotAvailable` from `SecBase.h`: no keychain is available at all.
const ERR_SEC_NOT_AVAILABLE: i32 = -25291;

/// Marker bytes placed in the [`SealedBlob`] returned by
/// [`KeychainSeal::seal`]. The real key material lives in the Keychain,
/// keyed by `service`/`account`, this marker lets
/// [`KeychainSeal::unseal`] reject a blob that obviously didn't come from
/// this backend without needing to decode anything else out of it.
const SEALED_MARKER: &[u8] = b"cofferak-keychain-seal-v1";

/// A [`HostSeal`] backend that stores the key as a generic password in the
/// macOS Keychain, scoped to `service`/`account`.
pub struct KeychainSeal {
    pub service: String,
    pub account: String,
}

/// Appended to the key in the Keychain item when the host was created to
/// require user presence (Touch ID or the login password) before admin
/// commands may use it. The flag lives in the Keychain item itself, which
/// only cofferak can write, not in the data directory.
const PRESENCE_FLAG: u8 = 0x01;

impl KeychainSeal {
    /// Store `key`, recording whether admin commands must confirm user
    /// presence before using it (see [`KeychainSeal::presence_required`]).
    pub fn seal_with_presence(
        &self,
        key: &[u8; 32],
        require_presence: bool,
    ) -> Result<SealedBlob, SealError> {
        let mut value = key.to_vec();
        if require_presence {
            value.push(PRESENCE_FLAG);
        }
        let r = set_generic_password(&self.service, &self.account, &value).map_err(map_sf_error);
        value.iter_mut().for_each(|b| *b = 0);
        r?;
        Ok(SealedBlob(SEALED_MARKER.to_vec()))
    }

    /// Whether this host's key was stored with the user-presence flag.
    pub fn presence_required(&self) -> Result<bool, SealError> {
        let mut bytes = get_generic_password(&self.service, &self.account).map_err(map_sf_error)?;
        let required = bytes.len() == 33 && bytes[32] == PRESENCE_FLAG;
        bytes.iter_mut().for_each(|b| *b = 0);
        Ok(required)
    }
}

impl HostSeal for KeychainSeal {
    fn seal(&self, key: &[u8; 32]) -> Result<SealedBlob, SealError> {
        self.seal_with_presence(key, false)
    }

    fn unseal(&self, blob: &SealedBlob) -> Result<[u8; 32], SealError> {
        if blob.0 != SEALED_MARKER {
            return Err(SealError::Invalid(
                "sealed blob does not match the expected marker".to_string(),
            ));
        }

        let mut bytes = get_generic_password(&self.service, &self.account).map_err(map_sf_error)?;

        let valid = bytes.len() == 32 || (bytes.len() == 33 && bytes[32] == PRESENCE_FLAG);
        if !valid {
            let n = bytes.len();
            bytes.iter_mut().for_each(|b| *b = 0);
            return Err(SealError::Invalid(format!(
                "Keychain item was {n} bytes, expected 32"
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[..32]);
        bytes.iter_mut().for_each(|b| *b = 0);
        Ok(key)
    }
}

/// Map a `security-framework` error to the shared `SealError` taxonomy,
/// following the same conventions as the Linux backend
/// (`seal::linux::SystemdCredsSeal::run`): a missing/untrustworthy result
/// maps to `Invalid`, the facility itself being unreachable maps to
/// `Unavailable`, anything else maps to `Io`.
fn map_sf_error(e: SfError) -> SealError {
    match e.code() {
        ERR_SEC_ITEM_NOT_FOUND => SealError::Invalid("Keychain item not found".to_string()),
        ERR_SEC_INTERACTION_NOT_ALLOWED | ERR_SEC_NOT_AVAILABLE => SealError::Unavailable,
        _ => SealError::Io(std::io::Error::other(format!("keychain error: {e}"))),
    }
}

/// macOS anchor mirror (ADR 0017): each host's anchor is also kept in the
/// Keychain (service `cofferak-anchor`), which a restore of the data
/// directory from a backup doesn't touch.
pub struct KeychainAnchorMirror;

impl crate::format::AnchorMirror for KeychainAnchorMirror {
    fn read(&self, host_id: &str) -> std::io::Result<Option<Vec<u8>>> {
        match get_generic_password("cofferak-anchor", host_id) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(e) => Err(std::io::Error::other(format!("keychain error: {e}"))),
        }
    }

    fn write(&self, host_id: &str, bytes: &[u8]) -> std::io::Result<()> {
        set_generic_password("cofferak-anchor", host_id, bytes)
            .map_err(|e| std::io::Error::other(format!("keychain error: {e}")))
    }
}
