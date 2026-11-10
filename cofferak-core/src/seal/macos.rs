//! macOS `HostSeal` backend: stores the key as a generic password item in
//! the user's Keychain via `security-framework`.
//!
//! Unlike the Linux backend (`systemd-creds`), the Keychain *is* the
//! persistent store rather than a stateless encrypt/decrypt facility:
//! [`KeychainSeal::seal`] writes the raw 32-byte key into a keychain item
//! named by `service`/`account`, and [`KeychainSeal::unseal`] reads it back
//! out by that same name. The [`SealedBlob`] returned by `seal` therefore
//! carries no key material of its own (unlike the Linux backend's, which
//! is the `systemd-creds`-encrypted bytes) — it's just a marker that lets
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
/// user) — the macOS analogue of the Linux backend's "binary not
/// spawnable".
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

/// `errSecNotAvailable` from `SecBase.h`: no keychain is available at all.
const ERR_SEC_NOT_AVAILABLE: i32 = -25291;

/// Marker bytes placed in the [`SealedBlob`] returned by
/// [`KeychainSeal::seal`]. The real key material lives in the Keychain,
/// keyed by `service`/`account`; this marker lets
/// [`KeychainSeal::unseal`] reject a blob that obviously didn't come from
/// this backend without needing to decode anything else out of it.
const SEALED_MARKER: &[u8] = b"cofferak-keychain-seal-v1";

/// A [`HostSeal`] backend that stores the key as a generic password in the
/// macOS Keychain, scoped to `service`/`account`.
pub struct KeychainSeal {
    pub service: String,
    pub account: String,
}

impl HostSeal for KeychainSeal {
    fn seal(&self, key: &[u8; 32]) -> Result<SealedBlob, SealError> {
        set_generic_password(&self.service, &self.account, key).map_err(map_sf_error)?;
        Ok(SealedBlob(SEALED_MARKER.to_vec()))
    }

    fn unseal(&self, blob: &SealedBlob) -> Result<[u8; 32], SealError> {
        if blob.0 != SEALED_MARKER {
            return Err(SealError::Invalid);
        }

        let bytes = get_generic_password(&self.service, &self.account).map_err(map_sf_error)?;

        if bytes.len() != 32 {
            return Err(SealError::Invalid);
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
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
        ERR_SEC_ITEM_NOT_FOUND => SealError::Invalid,
        ERR_SEC_INTERACTION_NOT_ALLOWED | ERR_SEC_NOT_AVAILABLE => SealError::Unavailable,
        _ => SealError::Io(std::io::Error::other(format!("keychain error: {e}"))),
    }
}
