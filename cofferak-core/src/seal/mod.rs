//! `HostSeal`: the one platform-dependent abstraction in cofferak.
//!
//! A vault's host key must be stored at rest in a form that is only usable
//! on the machine that sealed it, without cofferak having to invent its own
//! key-wrapping-at-rest scheme per platform. Each OS already ships a
//! facility for exactly this (Linux's `systemd-creds`, macOS's Keychain,
//! ...); `HostSeal` is the trait that lets the rest of cofferak (daemon,
//! CLI) call "seal"/"unseal" without caring which backend is in use.
//!
//! This module (`seal::mod`) defines the trait and its associated types on
//! every platform, since downstream crates need the types to exist even on
//! a platform that implements a different backend. Concrete backends live
//! in platform-gated submodules, e.g. [`linux`] for `systemd-creds`.

use std::fmt;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::SystemdCredsSeal;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::{KeychainAnchorMirror, KeychainSeal};

/// An opaque, host-sealed blob produced by a [`HostSeal`] implementation.
///
/// The bytes are only meaningful to the backend (and host) that produced
/// them, callers must treat this as opaque and persist it verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedBlob(pub Vec<u8>);

/// Errors produced by [`HostSeal`] implementations.
#[derive(Debug)]
pub enum SealError {
    /// The host sealing facility (e.g. the `systemd-creds` binary) could not
    /// be invoked at all on this system - typically because it is not
    /// installed or not on `PATH`.
    Unavailable,
    /// The sealing facility ran but its output cannot be trusted: a
    /// non-zero exit status, empty output, or output that otherwise fails
    /// to decrypt/validate. Carries whatever diagnostic detail the backend
    /// captured (e.g. the subprocess's stderr) - never secret key material,
    /// only the backend's own operational error text - so a caller isn't
    /// left guessing between, say, "wrong name" and "permission denied."
    Invalid(String),
    /// An I/O error occurred while talking to the sealing facility (e.g.
    /// writing to its stdin or reading its stdout).
    Io(std::io::Error),
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealError::Unavailable => write!(f, "host seal backend is unavailable"),
            SealError::Invalid(detail) => {
                write!(
                    f,
                    "host seal backend rejected input or produced invalid output: {detail}"
                )
            }
            SealError::Io(e) => write!(f, "I/O error talking to host seal backend: {e}"),
        }
    }
}

impl std::error::Error for SealError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SealError::Io(e) => Some(e),
            SealError::Unavailable | SealError::Invalid(_) => None,
        }
    }
}

impl From<std::io::Error> for SealError {
    fn from(e: std::io::Error) -> Self {
        SealError::Io(e)
    }
}

/// Seals and unseals a 32-byte key using a host-specific secret-storage
/// facility, so the raw key never needs to be persisted on disk in the
/// clear.
///
/// Implementations must never panic, and must never return `Ok` with
/// garbage/forged key bytes: a corrupted or tampered [`SealedBlob`] must
/// fail with `Err`, not decode into incorrect-but-valid-looking bytes.
pub trait HostSeal {
    /// Seal `key`, producing an opaque blob that only [`unseal`](Self::unseal)
    /// (on this host, with this backend) can recover it from.
    fn seal(&self, key: &[u8; 32]) -> Result<SealedBlob, SealError>;

    /// Recover the original key from a blob produced by [`seal`](Self::seal).
    ///
    /// Returns `Err` for any blob that was not produced by this backend, or
    /// that has been truncated/corrupted/tampered with.
    fn unseal(&self, blob: &SealedBlob) -> Result<[u8; 32], SealError>;
}
