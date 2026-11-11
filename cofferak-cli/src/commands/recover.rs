//! `cofferak-cli recover --root-key <path> --new-host <id>` - disaster
//! recovery.
//!
//! Every other way of recovering the vault's DEK requires an
//! already-enrolled host's own sealed blob plus that host's own `HostSeal`
//! backend (see `enroll.rs`'s module doc comment). This command is the
//! break-glass path for when that is unavailable (every enrolled host's
//! sealed blob is lost, corrupted, or the machine itself is gone): the
//! offline root private key that `init --root` printed to stdout exactly
//! once, and only the operator holds, unwraps `VaultFile.root_wrap`
//! directly, without needing any host's cooperation at all.
//!
//! Correctness bar: on any failure (bad key file, wrong key, missing
//! vault, or a vault with no DEK yet), `vault.cofferak` is left byte-for-byte
//! unchanged on disk. This is enforced structurally: every read-only
//! validation step (vault exists, `root_wrap` is `Some(_)`, the key file
//! decodes and actually unwraps it) runs to completion *before* this
//! function writes anything at all, and the only write of `vault.cofferak`
//! itself is a temp-file-then-`rename` - never an in-place write - mirroring
//! the atomic-write discipline Task 13's `run_rotate_dek` established (see
//! `secrets.rs`'s module doc comment for why the rename is the only point
//! at which new content becomes visible at that path).

use std::path::Path;

use cofferak_core::crypto::{unwrap_dek_for_root, wrap_dek_for_host, KeyBytes, RootPrivateKey};
use cofferak_core::format::VaultFile;
use cofferak_core::seal::HostSeal;

use super::init::{random_key, vault_path, CliError};

/// Recover a vault using the offline root private key stored at
/// `root_privkey_path`, enrolling `new_host_id` with a freshly generated
/// host key sealed via `new_host_seal`.
///
/// - Returns `Err(CliError::VaultMissing)` if `data_dir` has no vault, or
///   if the vault's `root_wrap` is `None` (no DEK has ever been generated
///   - a vault with zero hosts has no DEK to recover).
/// - Returns `Err(CliError::HostAlreadyEnrolled)` if `new_host_id` is
///   already in `vault.hosts`.
/// - Returns `Err(CliError::BadRootKey)` if `root_privkey_path`'s contents
///   are not exactly 32 bytes, or those 32 bytes do not unwrap
///   `vault.root_wrap` (the wrong keypair).
/// - Otherwise: unwraps the DEK with the given root private key, generates
///   a fresh unseal key for `new_host_id`, seals it via `new_host_seal`,
///   persists the sealed blob under `data_dir/hosts/<new_host_id>.seal`,
///   wraps the (same, recovered) DEK for `new_host_id` into
///   `vault.hosts[new_host_id]`, and writes `vault.cofferak` + `meta.json`
///   back.
pub fn run_recover(
    data_dir: &Path,
    root_privkey_path: &Path,
    new_host_id: &str,
    new_host_seal: &dyn HostSeal,
) -> Result<(), CliError> {
    let vpath = vault_path(data_dir);
    if !vpath.exists() {
        return Err(CliError::VaultMissing);
    }

    let mut vault = VaultFile::load(&vpath)?;

    // A vault with `root_wrap: None` has never had a DEK generated (no
    // host has ever been enrolled) - there is nothing to recover.
    let root_wrap = vault.root_wrap.clone().ok_or(CliError::VaultMissing)?;

    if vault.hosts.contains_key(new_host_id) {
        return Err(CliError::HostAlreadyEnrolled);
    }

    // Everything above this point is read-only. Everything below either
    // fails before touching disk (`BadRootKey`) or commits via the atomic
    // rename at the bottom - no partial/in-place write of `vault.cofferak` is
    // possible.
    // The key file is the armored block `init --root` printed. Read it as
    // bytes and require UTF-8, so a binary or garbage file is a clean
    // BadRootKey rather than an I/O error.
    let key_text = zeroize::Zeroizing::new(std::fs::read(root_privkey_path)?);
    let key_text = std::str::from_utf8(&key_text).map_err(|_| CliError::BadRootKey)?;
    let root_privkey = RootPrivateKey::from_armored(key_text).map_err(|_| CliError::BadRootKey)?;

    let dek = KeyBytes::new(
        unwrap_dek_for_root(&root_wrap, &vault.root_pubkey, &root_privkey)
            .map_err(|_| CliError::BadRootKey)?,
    );
    // Recovering must not resurrect a vault someone edited: the integrity
    // code is checked (there is no anchor for the new host yet).
    vault
        .verify(&dek, None)
        .map_err(|e| CliError::Invalid(e.to_string()))?;

    let new_host_key = KeyBytes::new(random_key());
    let sealed = new_host_seal
        .seal(&new_host_key)
        .map_err(|e| CliError::Io(std::io::Error::other(e)))?;

    super::init::write_host_seal(data_dir, new_host_id, &sealed.0)?;

    vault.hosts.insert(
        new_host_id.to_string(),
        wrap_dek_for_host(&dek, new_host_id, &new_host_key),
    );

    // Sealed, atomic write (unique 0600 temp file, fsync, rename).
    super::integrity::commit(data_dir, &[new_host_id], &mut vault, &dek)?;

    Ok(())
}
