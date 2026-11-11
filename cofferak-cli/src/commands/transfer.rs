//! Moving secrets in and out of a vault (ADR 0012):
//!
//! - [`run_export_with_seal`] / [`run_import_with_seal`]: the whole vault
//!   (every secret and service token) as a passphrase-encrypted bundle,
//!   for backups and for moving to another machine or OS. Admin commands:
//!   they unseal this host's key and edit `vault.cofferak` directly.
//! - [`run_import_env`] / [`run_export_env`] / [`collect_env`]: `.env`
//!   files and environment variables, through the daemon with a service
//!   token, so the token's path prefixes and permission still apply.

use std::collections::BTreeMap;
use std::path::Path;

use cofferak_core::acl::AccessToken;
use cofferak_core::bundle::{self, Bundle, BundleEntry};
use cofferak_core::crypto::{decrypt_entry, encrypt_entry, unwrap_dek_for_host, Aad, KeyBytes};
use cofferak_core::dotenv;
use cofferak_core::format::{VaultEntry, VaultFile, VaultMeta};
use cofferak_core::seal::{HostSeal, SealedBlob};
use zeroize::Zeroizing;

use super::init::{host_seal_path, meta_path, vault_path, CliError};
use super::secrets::{run_get, run_list, run_set};
use crate::client::Client;

fn invalid(msg: impl Into<String>) -> CliError {
    CliError::Invalid(msg.into())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Unseal `host_id`'s key with `seal` and unwrap the vault's DEK.
fn unlock(
    data_dir: &Path,
    vault: &VaultFile,
    host_id: &str,
    seal: &dyn HostSeal,
) -> Result<KeyBytes, CliError> {
    let wrap = vault.hosts.get(host_id).ok_or(CliError::HostNotFound)?;
    let sealed = std::fs::read(host_seal_path(data_dir, host_id))?;
    let host_key = KeyBytes::new(
        seal.unseal(&SealedBlob(sealed))
            .map_err(|e| CliError::Io(std::io::Error::other(e)))?,
    );
    Ok(KeyBytes::new(
        unwrap_dek_for_host(wrap, host_id, &host_key)
            .map_err(|e| CliError::Io(std::io::Error::other(e)))?,
    ))
}

/// Counts reported by an export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportReport {
    pub entries: usize,
    pub services: usize,
}

/// Build an encrypted bundle of every secret and service token in the
/// vault at `data_dir`, unlocking it as `host_id` with `seal`.
pub fn run_export_with_seal(
    data_dir: &Path,
    host_id: &str,
    seal: &dyn HostSeal,
    passphrase: &[u8],
    iterations: u32,
) -> Result<(Vec<u8>, ExportReport), CliError> {
    if passphrase.len() < bundle::MIN_PASSPHRASE_BYTES {
        return Err(invalid(bundle::BundleError::WeakPassphrase.to_string()));
    }
    let vpath = vault_path(data_dir);
    if !vpath.exists() {
        return Err(CliError::VaultMissing);
    }
    let vault = VaultFile::load(&vpath)?;
    let dek = unlock(data_dir, &vault, host_id, seal)?;

    let mut entries = Vec::with_capacity(vault.entries.len());
    for (path, e) in &vault.entries {
        let value = decrypt_entry(&dek, &Aad::entry(path), &e.ciphertext)
            .map_err(|err| invalid(format!("could not decrypt {path}: {err}")))?;
        entries.push(BundleEntry {
            path: path.clone(),
            value,
            version: e.version,
            updated_at: e.updated_at,
        });
    }
    let mut services = Vec::with_capacity(vault.services.len());
    for (id, e) in &vault.services {
        let plain = Zeroizing::new(
            decrypt_entry(&dek, &Aad::service_token(id), e)
                .map_err(|err| invalid(format!("could not decrypt token of {id}: {err}")))?,
        );
        let token: AccessToken = bincode::deserialize(&plain)
            .map_err(|err| invalid(format!("could not decode token of {id}: {err}")))?;
        services.push(token);
    }
    let report = ExportReport {
        entries: entries.len(),
        services: services.len(),
    };
    let b = Bundle {
        created_at: now_unix(),
        source_fingerprint: vault.root_pubkey.fingerprint(),
        entries,
        services,
    };
    let sealed = bundle::seal_with_iterations(&b, passphrase, iterations)
        .map_err(|e| invalid(e.to_string()))?;
    Ok((sealed, report))
}

/// What an import did (or, with `dry_run`, would do).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub source_fingerprint: String,
    pub entries_added: usize,
    pub entries_replaced: usize,
    pub entries_skipped: Vec<String>,
    pub services_added: usize,
    pub services_replaced: usize,
    pub services_skipped: Vec<String>,
}

/// Restore a bundle into the vault at `data_dir` (which must already be
/// initialized with this host enrolled). Existing paths and service ids
/// are kept unless `overwrite`; everything is re-encrypted under this
/// vault's DEK. With `dry_run`, nothing is written.
pub fn run_import_with_seal(
    data_dir: &Path,
    host_id: &str,
    seal: &dyn HostSeal,
    bundle_bytes: &[u8],
    passphrase: &[u8],
    overwrite: bool,
    dry_run: bool,
) -> Result<ImportReport, CliError> {
    let b = bundle::open(bundle_bytes, passphrase).map_err(|e| invalid(e.to_string()))?;
    let vpath = vault_path(data_dir);
    if !vpath.exists() {
        return Err(CliError::VaultMissing);
    }
    let mut vault = VaultFile::load(&vpath)?;
    let dek = unlock(data_dir, &vault, host_id, seal)?;

    let mut report = ImportReport {
        source_fingerprint: b.source_fingerprint.clone(),
        ..Default::default()
    };
    for e in &b.entries {
        let exists = vault.entries.contains_key(&e.path);
        if exists && !overwrite {
            report.entries_skipped.push(e.path.clone());
            continue;
        }
        if exists {
            report.entries_replaced += 1;
        } else {
            report.entries_added += 1;
        }
        vault.entries.insert(
            e.path.clone(),
            VaultEntry {
                ciphertext: encrypt_entry(&dek, &Aad::entry(&e.path), &e.value),
                version: e.version,
                updated_at: e.updated_at,
            },
        );
    }
    for t in &b.services {
        let exists = vault.services.contains_key(&t.service_id);
        if exists && !overwrite {
            report.services_skipped.push(t.service_id.clone());
            continue;
        }
        if exists {
            report.services_replaced += 1;
        } else {
            report.services_added += 1;
        }
        let plain = Zeroizing::new(
            bincode::serialize(t).map_err(|err| invalid(format!("encoding token: {err}")))?,
        );
        vault.services.insert(
            t.service_id.clone(),
            encrypt_entry(&dek, &Aad::service_token(&t.service_id), &plain),
        );
    }
    if !dry_run {
        vault.save(&vpath)?;
        VaultMeta::from_vault(&vault).save(&meta_path(data_dir))?;
    }
    Ok(report)
}

fn normalize_prefix(prefix: &str) -> Result<String, CliError> {
    let p = prefix.trim_end_matches('/');
    if p.is_empty() {
        return Err(invalid("--prefix must not be empty (e.g. myapp/env)"));
    }
    Ok(p.to_string())
}

/// What `import-env` did (or would do).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvImportReport {
    pub added: Vec<String>,
    pub replaced: Vec<String>,
    pub skipped: Vec<String>,
}

/// Store each `.env` variable as `<prefix>/<KEY>` through the daemon.
/// Existing paths are skipped unless `overwrite`; `dry_run` only reports.
pub fn run_import_env(
    client: &Client,
    token: &str,
    prefix: &str,
    env_text: &str,
    overwrite: bool,
    dry_run: bool,
) -> Result<EnvImportReport, CliError> {
    let prefix = normalize_prefix(prefix)?;
    let vars = dotenv::parse(env_text).map_err(|e| invalid(format!(".env {e}")))?;
    let existing: std::collections::BTreeSet<String> = match run_list(client, token, &prefix) {
        Ok(paths) => paths.into_iter().collect(),
        Err(CliError::NotFound) => Default::default(),
        Err(e) => return Err(e),
    };
    let mut report = EnvImportReport::default();
    for v in &vars {
        let path = format!("{prefix}/{}", v.key);
        let exists = existing.contains(&path);
        if exists && !overwrite {
            report.skipped.push(v.key.clone());
            continue;
        }
        if !dry_run {
            run_set(client, token, &path, v.value.as_bytes().to_vec())?;
        }
        if exists {
            report.replaced.push(v.key.clone());
        } else {
            report.added.push(v.key.clone());
        }
    }
    Ok(report)
}

/// Environment variables collected from the vault: name → value.
pub type EnvVars = BTreeMap<String, Zeroizing<Vec<u8>>>;

/// Read every direct child of `prefix` that is a valid environment
/// variable name, returning `(NAME, value)` pairs (later prefixes override
/// earlier ones) plus the paths that were skipped and why.
pub fn collect_env(
    client: &Client,
    token: &str,
    prefixes: &[String],
) -> Result<(EnvVars, Vec<String>), CliError> {
    let mut vars = EnvVars::new();
    let mut skipped = Vec::new();
    for raw in prefixes {
        let prefix = normalize_prefix(raw)?;
        for path in run_list(client, token, &prefix)? {
            let rest = &path[prefix.len()..];
            let Some(name) = rest.strip_prefix('/') else {
                continue; // the prefix itself, not a child
            };
            if name.contains('/') {
                skipped.push(format!("{path} (nested path)"));
                continue;
            }
            if !dotenv::is_valid_key(name) {
                skipped.push(format!("{path} (not a valid variable name)"));
                continue;
            }
            let value = Zeroizing::new(run_get(client, token, &path)?);
            if value.contains(&0) {
                skipped.push(format!("{path} (contains a NUL byte)"));
                continue;
            }
            vars.insert(name.to_string(), value);
        }
    }
    Ok((vars, skipped))
}

/// Render the variables under `prefix` as `.env` text. Values must be
/// UTF-8 text; binary values are listed in the returned skip list.
pub fn run_export_env(
    client: &Client,
    token: &str,
    prefix: &str,
) -> Result<(Zeroizing<String>, Vec<String>), CliError> {
    let (vars, mut skipped) = collect_env(client, token, &[prefix.to_string()])?;
    let mut text_vars: Vec<(String, String)> = Vec::new();
    for (k, v) in vars {
        match std::str::from_utf8(&v) {
            Ok(s) => text_vars.push((k, s.to_string())),
            Err(_) => skipped.push(format!("{k} (binary value; use `get -o`)")),
        }
    }
    let text = Zeroizing::new(dotenv::format(
        text_vars.iter().map(|(k, v)| (k.as_str(), v.as_str())),
    ));
    for (_, v) in text_vars.iter_mut() {
        zeroize::Zeroize::zeroize(v);
    }
    Ok((text, skipped))
}
