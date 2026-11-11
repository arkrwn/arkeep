//! Vault integrity for admin commands (ADR 0015): verify before changing
//! anything, seal on every write, keep this host's anchor current.

use std::path::Path;

use cofferak_core::format::{read_anchor, write_anchor, VaultFile, VaultMeta};

use super::init::{meta_path, vault_path, CliError};

/// Refuse to work on a vault that was edited outside cofferak or is older
/// than the newest generation `host_id` has seen.
pub(crate) fn check(
    data_dir: &Path,
    host_id: &str,
    vault: &VaultFile,
    dek: &[u8; 32],
) -> Result<(), CliError> {
    let anchor = read_anchor(data_dir, host_id, dek).map_err(|_| {
        CliError::Invalid(format!(
            "the anchor file for host {host_id} was modified outside cofferak"
        ))
    })?;
    vault
        .verify(dek, anchor)
        .map_err(|e| CliError::Invalid(e.to_string()))
}

/// Seal and write `vault`, its metadata, and the anchors of `hosts` (the
/// hosts on this machine whose key was used for this command).
pub(crate) fn commit(
    data_dir: &Path,
    hosts: &[&str],
    vault: &mut VaultFile,
    dek: &[u8; 32],
) -> Result<(), CliError> {
    vault.seal(dek);
    vault.save(&vault_path(data_dir))?;
    VaultMeta::from_vault(vault).save(&meta_path(data_dir))?;
    for host in hosts {
        write_anchor(data_dir, host, dek, vault.generation)?;
    }
    Ok(())
}

/// What `accept-restore` changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    pub previous_anchor: Option<u64>,
    pub accepted_generation: u64,
}

/// Accept the vault currently on disk as the newest valid one for
/// `host_id`, after an intentional restore of an older backup. The file
/// must still be authentic (its integrity code verifies under this
/// vault's DEK), only the "older than seen" check is reset.
pub fn run_accept_restore_with_seal(
    data_dir: &Path,
    host_id: &str,
    seal: &dyn cofferak_core::seal::HostSeal,
) -> Result<RestoreReport, CliError> {
    use cofferak_core::crypto::{unwrap_dek_for_host, KeyBytes};
    use cofferak_core::seal::SealedBlob;

    let vpath = vault_path(data_dir);
    if !vpath.exists() {
        return Err(CliError::VaultMissing);
    }
    let vault = VaultFile::load(&vpath)?;
    let wrap = vault.hosts.get(host_id).ok_or(CliError::HostNotFound)?;
    let sealed = std::fs::read(super::init::host_seal_path(data_dir, host_id))?;
    let host_key = KeyBytes::new(
        seal.unseal(&SealedBlob(sealed))
            .map_err(|e| CliError::Io(std::io::Error::other(e)))?,
    );
    let dek = KeyBytes::new(
        unwrap_dek_for_host(wrap, host_id, &host_key)
            .map_err(|e| CliError::Io(std::io::Error::other(e)))?,
    );
    vault.verify(&dek, None).map_err(|e| {
        CliError::Invalid(format!(
            "{e}: only an authentic copy of this vault can be accepted"
        ))
    })?;
    let previous_anchor = read_anchor(data_dir, host_id, &dek).ok().flatten();
    write_anchor(data_dir, host_id, &dek, vault.generation)?;
    Ok(RestoreReport {
        previous_anchor,
        accepted_generation: vault.generation,
    })
}
