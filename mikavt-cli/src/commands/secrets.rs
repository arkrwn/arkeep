//! `mikavt-cli set <path> <value>` / `get <path>` / `rm <path>` /
//! `list [prefix]` (all four go over the daemon's Unix socket via
//! [`crate::client::Client`]) and `rotate-dek` (a local, offline operation
//! against `vault.mika` directly — the daemon's socket protocol has no
//! request for rewriting every host's DEK wrap, and shouldn't: that's an
//! operator-only, vault-file-level operation, not a service-token-scoped
//! one).
//!
//! `run_get`/`run_set`/`run_rm`/`run_list` are thin: each builds the
//! matching `Request` variant, sends it, and maps the `Response` back to
//! either the success value or a `CliError` — `Denied`/`NotFound` for the
//! daemon's own ACL/lookup outcomes, `Remote` for `Response::Err` or any
//! response shape that doesn't belong to that request kind, and `Io`
//! (via `?`) for a transport failure from `Client::send` itself.
//!
//! `run_rotate_dek` is the one operation here that touches `vault.mika`
//! directly rather than going over the socket: it loads the vault,
//! recovers the *current* DEK by unsealing a given host's own sealed blob
//! and unwrapping that host's existing wrap, generates a fresh DEK,
//! re-encrypts every entry and service token under it, re-wraps it for
//! the root keypair (if one is already set) and for every given host
//! (reusing each host's own already-sealed, *unchanged* host key — only
//! the wrap of the DEK under that key changes), and writes the result
//! back atomically: serialized to a temp file in the same directory as
//! `vault.mika`, then `rename`d over it. The rename is the only point at
//! which the new content becomes visible at that path, and is atomic on
//! the same filesystem — a process killed at any point before it leaves
//! the untouched original `vault.mika` in place, so a corrupted vault can
//! never result from an interrupted rotation.

use std::path::Path;

use mikavt_core::crypto::{
    decrypt_entry, encrypt_entry, unwrap_dek_for_host, wrap_dek_for_host, wrap_dek_for_root,
    KeyBytes,
};
use mikavt_core::format::VaultFile;
use mikavt_core::seal::{HostSeal, SealedBlob};

use super::init::{host_seal_path, random_key, vault_path, CliError};
use crate::client::Client;
use crate::protocol::{Request, Response};

/// Fetch the decrypted value at `path`, using `token` for the daemon's
/// ACL check.
pub fn run_get(client: &Client, token: &str, path: &str) -> Result<Vec<u8>, CliError> {
    let response = client.send(&Request::Get {
        token: token.to_string(),
        path: path.to_string(),
    })?;
    match response {
        Response::Value(value) => Ok(value),
        Response::Denied => Err(CliError::Denied),
        Response::NotFound => Err(CliError::NotFound),
        Response::Err(msg) => Err(CliError::Remote(msg)),
        other => Err(CliError::Remote(format!("unexpected response: {other:?}"))),
    }
}

/// Set `path` to `value`, using `token` for the daemon's ACL check.
pub fn run_set(client: &Client, token: &str, path: &str, value: Vec<u8>) -> Result<(), CliError> {
    let response = client.send(&Request::Set {
        token: token.to_string(),
        path: path.to_string(),
        value,
    })?;
    match response {
        Response::Ok => Ok(()),
        Response::Denied => Err(CliError::Denied),
        Response::NotFound => Err(CliError::NotFound),
        Response::Err(msg) => Err(CliError::Remote(msg)),
        other => Err(CliError::Remote(format!("unexpected response: {other:?}"))),
    }
}

/// Remove the entry at `path`, using `token` for the daemon's ACL check.
pub fn run_rm(client: &Client, token: &str, path: &str) -> Result<(), CliError> {
    let response = client.send(&Request::Rm {
        token: token.to_string(),
        path: path.to_string(),
    })?;
    match response {
        Response::Ok => Ok(()),
        Response::Denied => Err(CliError::Denied),
        Response::NotFound => Err(CliError::NotFound),
        Response::Err(msg) => Err(CliError::Remote(msg)),
        other => Err(CliError::Remote(format!("unexpected response: {other:?}"))),
    }
}

/// List every path under `prefix`, using `token` for the daemon's ACL
/// check.
pub fn run_list(client: &Client, token: &str, prefix: &str) -> Result<Vec<String>, CliError> {
    let response = client.send(&Request::List {
        token: token.to_string(),
        prefix: prefix.to_string(),
    })?;
    match response {
        Response::Listed(paths) => Ok(paths),
        Response::Denied => Err(CliError::Denied),
        Response::Err(msg) => Err(CliError::Remote(msg)),
        other => Err(CliError::Remote(format!("unexpected response: {other:?}"))),
    }
}

/// Rotate the vault's DEK: generate a fresh one, re-encrypt every entry
/// and service token under it, and re-wrap it for the root keypair (if
/// already set) and for every `(host_id, seal)` pair in `hosts`.
///
/// `hosts` must include at least one host that is both actually enrolled
/// in `data_dir/vault.mika` (`vault.hosts`) and whose `data_dir/hosts/
/// <host_id>.seal` blob successfully unseals with the paired `seal` —
/// that host's wrap is used to recover the *current* DEK before rotating
/// it. Every host in `hosts`, not just that first one, gets its wrap of
/// the DEK updated; a host enrolled in the vault but *not* passed here
/// keeps wrapping the old (now-rotated-away) DEK and will need
/// re-enrolling separately.
///
/// Returns `Err(CliError::VaultMissing)` if there is no vault at
/// `data_dir`, or `Err(CliError::HostNotFound)` if no given host both
/// unseals and is actually enrolled.
pub fn run_rotate_dek(
    data_dir: &Path,
    hosts: &[(String, Box<dyn HostSeal>)],
) -> Result<(), CliError> {
    let vpath = vault_path(data_dir);
    if !vpath.exists() {
        return Err(CliError::VaultMissing);
    }

    let mut vault = VaultFile::load(&vpath)?;

    // Unseal every given host's own sealed blob to recover its host key
    // (rotation never changes a host's own key, only the vault's DEK and
    // that key's wrap of it). A failure here is reported immediately
    // rather than silently skipped, since a caller that explicitly named
    // a host expects that host to work.
    let mut host_keys: Vec<(String, [u8; 32])> = Vec::with_capacity(hosts.len());
    for (host_id, seal) in hosts {
        let sealed_bytes = std::fs::read(host_seal_path(data_dir, host_id))?;
        let host_key = seal
            .unseal(&SealedBlob(sealed_bytes))
            .map_err(|e| CliError::Io(std::io::Error::other(e)))?;
        host_keys.push((host_id.clone(), host_key));
    }

    // Recover the current DEK via the first given host that is actually
    // enrolled in this vault.
    let old_dek = host_keys
        .iter()
        .find_map(|(host_id, host_key)| {
            vault
                .hosts
                .get(host_id)
                .and_then(|wrap| unwrap_dek_for_host(wrap, host_key).ok())
        })
        .ok_or(CliError::HostNotFound)?;
    let old_dek = KeyBytes::new(old_dek);

    let new_dek = KeyBytes::new(random_key());

    for entry in vault.entries.values_mut() {
        let plaintext = decrypt_entry(&old_dek, &entry.ciphertext)
            .map_err(|e| CliError::Io(std::io::Error::other(e)))?;
        entry.ciphertext = encrypt_entry(&new_dek, &plaintext);
    }

    for service in vault.services.values_mut() {
        let plaintext =
            decrypt_entry(&old_dek, service).map_err(|e| CliError::Io(std::io::Error::other(e)))?;
        *service = encrypt_entry(&new_dek, &plaintext);
    }

    if vault.root_wrap.is_some() {
        vault.root_wrap = Some(wrap_dek_for_root(&new_dek, &vault.root_pubkey));
    }

    for (host_id, host_key) in &host_keys {
        vault
            .hosts
            .insert(host_id.clone(), wrap_dek_for_host(&new_dek, host_key));
    }

    // Atomic rewrite: see module doc comment. Serialize to a temp file in
    // the same directory as `vault.mika` (so the rename below is on the
    // same filesystem), then rename over the real path.
    let bytes = bincode::serialize(&vault)
        .map_err(|e| CliError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
    let tmp_path = data_dir.join("vault.mika.tmp");
    std::fs::write(&tmp_path, &bytes)?;
    std::fs::rename(&tmp_path, &vpath)?;

    Ok(())
}
