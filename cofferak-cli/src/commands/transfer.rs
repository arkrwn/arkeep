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
use cofferak_core::format::{VaultEntry, VaultFile};
use cofferak_core::identity::{self, IdentityPublic, IdentitySecret};
use cofferak_core::seal::{HostSeal, SealedBlob};
use zeroize::Zeroizing;

use super::init::{host_seal_path, vault_path, CliError};
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

/// What to put in a bundle: every secret (no prefixes) or only those under
/// the given prefixes, service tokens included or not.
#[derive(Debug, Clone, Default)]
pub struct Selection {
    pub prefixes: Vec<String>,
    pub include_tokens: bool,
}

impl Selection {
    /// The whole vault, tokens included.
    #[allow(dead_code)] // used by the integration tests
    pub fn everything() -> Self {
        Selection {
            prefixes: Vec::new(),
            include_tokens: true,
        }
    }
}

/// Decrypt the selected secrets and tokens of `vault` into a [`Bundle`].
fn build_bundle(vault: &VaultFile, dek: &[u8; 32], sel: &Selection) -> Result<Bundle, CliError> {
    let prefixes: Vec<String> = sel
        .prefixes
        .iter()
        .map(|p| p.trim_end_matches('/').to_string())
        .collect();
    let mut entries = Vec::new();
    for (path, e) in &vault.entries {
        if !prefixes.is_empty() && !cofferak_core::acl::path_allowed(&prefixes, path) {
            continue;
        }
        let value = decrypt_entry(dek, &Aad::entry(path), &e.ciphertext)
            .map_err(|err| invalid(format!("could not decrypt {path}: {err}")))?;
        entries.push(BundleEntry {
            path: path.clone(),
            value,
            version: e.version,
            updated_at: e.updated_at,
        });
    }
    let mut services = Vec::new();
    if sel.include_tokens {
        for (id, e) in &vault.services {
            let plain = Zeroizing::new(
                decrypt_entry(dek, &Aad::service_token(id), e)
                    .map_err(|err| invalid(format!("could not decrypt token of {id}: {err}")))?,
            );
            let token: AccessToken = bincode::deserialize(&plain)
                .map_err(|err| invalid(format!("could not decode token of {id}: {err}")))?;
            services.push(token);
        }
    }
    Ok(Bundle {
        created_at: now_unix(),
        source_fingerprint: vault.root_pubkey.fingerprint(),
        entries,
        services,
    })
}

/// Build a passphrase-encrypted bundle of the vault at `data_dir`
/// (unlocked as `host_id` with `seal`).
pub fn run_export_with_seal(
    data_dir: &Path,
    host_id: &str,
    seal: &dyn HostSeal,
    passphrase: &[u8],
    iterations: u32,
    sel: &Selection,
) -> Result<(Vec<u8>, ExportReport), CliError> {
    if passphrase.len() < bundle::MIN_PASSPHRASE_BYTES {
        return Err(invalid(bundle::BundleError::WeakPassphrase.to_string()));
    }
    let (vault, dek) = open_vault(data_dir, host_id, seal)?;
    let b = build_bundle(&vault, &dek, sel)?;
    let report = ExportReport {
        entries: b.entries.len(),
        services: b.services.len(),
    };
    let sealed = bundle::seal_with_iterations(&b, passphrase, iterations)
        .map_err(|e| invalid(e.to_string()))?;
    Ok((sealed, report))
}

fn open_vault(
    data_dir: &Path,
    host_id: &str,
    seal: &dyn HostSeal,
) -> Result<(VaultFile, KeyBytes), CliError> {
    let vpath = vault_path(data_dir);
    if !vpath.exists() {
        return Err(CliError::VaultMissing);
    }
    let vault = VaultFile::load(&vpath)?;
    let dek = unlock(data_dir, &vault, host_id, seal)?;
    super::integrity::check(data_dir, host_id, &vault, &dek)?;
    Ok((vault, dek))
}

/// This coffer's identity, creating (and storing) one on first use.
/// Returns the identity and whether the vault was modified.
fn ensure_identity(
    vault: &mut VaultFile,
    dek: &[u8; 32],
) -> Result<(IdentitySecret, bool), CliError> {
    if let Some(enc) = &vault.identity {
        let plain = Zeroizing::new(
            decrypt_entry(dek, &Aad::identity(), enc)
                .map_err(|e| invalid(format!("could not decrypt this coffer's identity: {e}")))?,
        );
        let id = IdentitySecret::from_bytes(&plain).map_err(|e| invalid(e.to_string()))?;
        return Ok((id, false));
    }
    let id = IdentitySecret::generate().map_err(|e| invalid(e.to_string()))?;
    vault.identity = Some(encrypt_entry(dek, &Aad::identity(), &id.to_bytes()));
    Ok((id, true))
}

fn save_vault(
    data_dir: &Path,
    host_id: &str,
    vault: &mut VaultFile,
    dek: &[u8; 32],
) -> Result<(), CliError> {
    super::integrity::commit(data_dir, &[host_id], vault, dek)
}

/// This coffer's public identity (created on first use).
pub fn run_identity_with_seal(
    data_dir: &Path,
    host_id: &str,
    seal: &dyn HostSeal,
) -> Result<IdentityPublic, CliError> {
    let (mut vault, dek) = open_vault(data_dir, host_id, seal)?;
    let (id, created) = ensure_identity(&mut vault, &dek)?;
    if created {
        save_vault(data_dir, host_id, &mut vault, &dek)?;
    }
    Ok(id.public().clone())
}

fn decrypt_peers(
    vault: &VaultFile,
    dek: &[u8; 32],
) -> Result<BTreeMap<String, IdentityPublic>, CliError> {
    let mut out = BTreeMap::new();
    for (name, enc) in &vault.peers {
        let plain = Zeroizing::new(
            decrypt_entry(dek, &Aad::peer(name), enc)
                .map_err(|e| invalid(format!("could not decrypt peer {name}: {e}")))?,
        );
        let text =
            std::str::from_utf8(&plain).map_err(|_| invalid(format!("peer {name} is corrupt")))?;
        out.insert(
            name.clone(),
            IdentityPublic::from_text(text).map_err(|e| invalid(format!("peer {name}: {e}")))?,
        );
    }
    Ok(out)
}

/// Trust `peer` (another coffer's public identity) under `name`.
pub fn run_peer_add_with_seal(
    data_dir: &Path,
    host_id: &str,
    seal: &dyn HostSeal,
    name: &str,
    peer: &IdentityPublic,
    replace: bool,
) -> Result<(), CliError> {
    cofferak_core::acl::validate_id("peer", name).map_err(invalid)?;
    let (mut vault, dek) = open_vault(data_dir, host_id, seal)?;
    if vault.peers.contains_key(name) && !replace {
        return Err(invalid(format!(
            "a peer named {name} already exists (use --replace)"
        )));
    }
    let (me, created) = ensure_identity(&mut vault, &dek)?;
    if me.public().fingerprint() == peer.fingerprint() {
        return Err(invalid("that is this coffer's own identity"));
    }
    let _ = created;
    for (other, p) in decrypt_peers(&vault, &dek)? {
        if other != name && p.fingerprint() == peer.fingerprint() {
            return Err(invalid(format!(
                "this identity is already trusted as {other}"
            )));
        }
    }
    vault.peers.insert(
        name.to_string(),
        encrypt_entry(&dek, &Aad::peer(name), peer.to_text().as_bytes()),
    );
    save_vault(data_dir, host_id, &mut vault, &dek)
}

/// Trusted peers by name.
pub fn run_peer_list_with_seal(
    data_dir: &Path,
    host_id: &str,
    seal: &dyn HostSeal,
) -> Result<BTreeMap<String, IdentityPublic>, CliError> {
    let (vault, dek) = open_vault(data_dir, host_id, seal)?;
    decrypt_peers(&vault, &dek)
}

/// Stop trusting the peer `name`. Returns false if there was none.
pub fn run_peer_rm_with_seal(
    data_dir: &Path,
    host_id: &str,
    seal: &dyn HostSeal,
    name: &str,
) -> Result<bool, CliError> {
    let (mut vault, dek) = open_vault(data_dir, host_id, seal)?;
    let removed = vault.peers.remove(name).is_some();
    if removed {
        save_vault(data_dir, host_id, &mut vault, &dek)?;
    }
    Ok(removed)
}

/// Build a transfer for the trusted peer `peer_name`: encrypted so only
/// that coffer can open it, signed with this coffer's identity.
pub fn run_export_to_peer_with_seal(
    data_dir: &Path,
    host_id: &str,
    seal: &dyn HostSeal,
    peer_name: &str,
    sel: &Selection,
) -> Result<(Vec<u8>, ExportReport), CliError> {
    let (mut vault, dek) = open_vault(data_dir, host_id, seal)?;
    let peers = decrypt_peers(&vault, &dek)?;
    let peer = peers.get(peer_name).ok_or_else(|| {
        invalid(format!(
            "no trusted peer named {peer_name}, add it with `cofferak peer add {peer_name} <identity file>`"
        ))
    })?;
    let (me, created) = ensure_identity(&mut vault, &dek)?;
    if created {
        save_vault(data_dir, host_id, &mut vault, &dek)?;
    }
    let b = build_bundle(&vault, &dek, sel)?;
    let report = ExportReport {
        entries: b.entries.len(),
        services: b.services.len(),
    };
    let bytes = identity::seal_transfer(&b, &me, peer).map_err(|e| invalid(e.to_string()))?;
    Ok((bytes, report))
}

/// What an import did (or, with `dry_run`, would do).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub source_fingerprint: String,
    /// For a peer transfer: the trusted peer it came from.
    pub from_peer: Option<String>,
    pub entries_added: usize,
    pub entries_replaced: usize,
    pub entries_skipped: Vec<String>,
    pub services_added: usize,
    pub services_replaced: usize,
    pub services_skipped: Vec<String>,
    /// Service tokens the bundle carried, as (id, prefixes, permission),
    /// whether or not they were imported.
    pub tokens_offered: Vec<(String, Vec<String>, String)>,
    /// True if the bundle carried tokens that were not imported because
    /// `--with-tokens` was not given.
    pub tokens_withheld: bool,
}

/// A path from an imported bundle must look like one cofferak itself
/// would accept: non-empty, no empty or `.`/`..` segments, no leading `/`,
/// no control characters.
fn valid_import_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 1024
        && !p.starts_with('/')
        && p.split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
        && !p.chars().any(|c| c.is_control())
}

/// How to open the bundle being imported.
pub enum ImportKey<'a> {
    /// A passphrase bundle (`CFKEXPT1`).
    Passphrase(&'a [u8]),
    /// A peer transfer (`CFKEXPT2`), opened with this coffer's identity.
    /// `from` optionally pins the expected sender by its public identity
    /// instead of requiring it to be a stored peer.
    Identity {
        from: Option<IdentityPublic>,
        /// Accept a transfer older than [`MAX_TRANSFER_AGE_SECS`].
        allow_old: bool,
    },
}

/// Peer transfers older than this are refused unless `--allow-old`.
pub const MAX_TRANSFER_AGE_SECS: i64 = 30 * 24 * 3600;

/// Line added to a stored peer's (encrypted) record: when the newest
/// transfer accepted from it was made, and its SHA-256, so the same or an
/// older transfer can't be replayed (ADR 0017).
const LAST_TRANSFER: &str = "last-transfer: ";

fn peer_last_transfer(vault: &VaultFile, dek: &[u8; 32], name: &str) -> Option<(i64, String)> {
    let enc = vault.peers.get(name)?;
    let plain = Zeroizing::new(decrypt_entry(dek, &Aad::peer(name), enc).ok()?);
    let text = std::str::from_utf8(&plain).ok()?;
    let rest = text.lines().find_map(|l| l.strip_prefix(LAST_TRANSFER))?;
    let (ts, hash) = rest.split_once(' ')?;
    Some((ts.parse().ok()?, hash.to_string()))
}

fn record_peer_transfer(
    vault: &mut VaultFile,
    dek: &[u8; 32],
    name: &str,
    peer: &IdentityPublic,
    created_at: i64,
    hash: &str,
) {
    let text = format!(
        "{}\n{LAST_TRANSFER}{created_at} {hash}",
        peer.to_text().trim_end()
    );
    vault.peers.insert(
        name.to_string(),
        encrypt_entry(dek, &Aad::peer(name), text.as_bytes()),
    );
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// True if `bytes` is a peer transfer rather than a passphrase bundle.
pub fn is_peer_transfer(bytes: &[u8]) -> bool {
    identity::is_transfer(bytes)
}

/// Re-encrypt `b`'s secrets and tokens under `dek` into `vault`.
fn apply_bundle(
    vault: &mut VaultFile,
    dek: &[u8; 32],
    b: &Bundle,
    overwrite: bool,
    import_tokens: bool,
    report: &mut ImportReport,
) -> Result<(), CliError> {
    // Validate everything first: a bundle with any invalid path or service
    // id is rejected as a whole, before anything changes.
    for e in &b.entries {
        if !valid_import_path(&e.path) {
            return Err(invalid(format!(
                "bundle contains an invalid path {:?}, nothing imported",
                e.path
            )));
        }
    }
    for t in &b.services {
        cofferak_core::acl::validate_id("service", &t.service_id)
            .map_err(|m| invalid(format!("bundle contains {m}, nothing imported")))?;
        if t.prefixes.is_empty() || t.prefixes.iter().any(|p| !valid_import_path(p)) {
            return Err(invalid(format!(
                "bundle contains service {} with invalid path prefixes, nothing imported",
                t.service_id
            )));
        }
        report.tokens_offered.push((
            t.service_id.clone(),
            t.prefixes.clone(),
            format!("{:?}", t.permission),
        ));
    }
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
                ciphertext: encrypt_entry(dek, &Aad::entry(&e.path), &e.value),
                version: e.version,
                updated_at: e.updated_at,
            },
        );
    }
    if !import_tokens {
        report.tokens_withheld = !b.services.is_empty();
        return Ok(());
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
            encrypt_entry(dek, &Aad::service_token(&t.service_id), &plain),
        );
    }
    Ok(())
}

/// Restore a passphrase bundle or a peer transfer into the vault at
/// `data_dir` (initialized, with this host enrolled). Existing paths and
/// service ids are kept unless `overwrite`, everything is re-encrypted
/// under this vault's DEK. With `dry_run`, nothing is written.
#[allow(clippy::too_many_arguments)] // flags map 1:1 to `cofferak import` options
pub fn run_import_with_seal(
    data_dir: &Path,
    host_id: &str,
    seal: &dyn HostSeal,
    bundle_bytes: &[u8],
    key: ImportKey<'_>,
    overwrite: bool,
    import_tokens: bool,
    dry_run: bool,
) -> Result<ImportReport, CliError> {
    let (mut vault, dek) = open_vault(data_dir, host_id, seal)?;
    let mut report = ImportReport::default();
    let b = match key {
        ImportKey::Passphrase(p) => {
            bundle::open(bundle_bytes, p).map_err(|e| invalid(e.to_string()))?
        }
        ImportKey::Identity { from, allow_old } => {
            let Some(_) = vault.identity else {
                return Err(invalid(
                    "this coffer has no identity yet, so nothing can have been sent to it; \
                     run `cofferak identity` and give the output to the sender first",
                ));
            };
            let (me, _) = ensure_identity(&mut vault, &dek)?;
            let (sender, b) =
                identity::open_transfer(bundle_bytes, &me).map_err(|e| invalid(e.to_string()))?;
            let fp = sender.fingerprint();
            let pinned_sender = from.is_some();
            let peer_name = match from {
                Some(pinned) if pinned.fingerprint() == fp => "(pinned with --from)".to_string(),
                Some(_) => {
                    return Err(invalid(format!(
                        "the bundle was signed by {}, not by the identity given with --from",
                        sender.short_fingerprint()
                    )))
                }
                None => decrypt_peers(&vault, &dek)?
                    .into_iter()
                    .find(|(_, p)| p.fingerprint() == fp)
                    .map(|(n, _)| n)
                    .ok_or_else(|| {
                        invalid(format!(
                            "the bundle was signed by an untrusted coffer ({}), if you expected it, \
                             add that coffer with `cofferak peer add <name> <its identity file>` and retry",
                            sender.short_fingerprint()
                        ))
                    })?,
            };
            let age = now_unix() - b.created_at;
            if age > MAX_TRANSFER_AGE_SECS && !allow_old {
                return Err(invalid(format!(
                    "this transfer was made {} days ago, transfers older than 30 days are refused \
                     in case they are a replay. If you expected it, re-run with --allow-old",
                    age / 86400
                )));
            }
            if !pinned_sender {
                let hash = sha256_hex(bundle_bytes);
                if let Some((last_ts, last_hash)) = peer_last_transfer(&vault, &dek, &peer_name) {
                    if b.created_at < last_ts || (b.created_at == last_ts && hash == last_hash) {
                        return Err(invalid(format!(
                            "this transfer from peer '{peer_name}' was already imported, or is older \
                             than one already imported, refusing a possible replay"
                        )));
                    }
                }
                record_peer_transfer(&mut vault, &dek, &peer_name, &sender, b.created_at, &hash);
            }
            report.from_peer = Some(peer_name);
            b
        }
    };
    report.source_fingerprint = b.source_fingerprint.clone();
    apply_bundle(&mut vault, &dek, &b, overwrite, import_tokens, &mut report)?;
    if !dry_run {
        save_vault(data_dir, host_id, &mut vault, &dek)?;
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
/// UTF-8 text, binary values are listed in the returned skip list.
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
            Err(_) => skipped.push(format!("{k} (binary value, use `get -o`)")),
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
