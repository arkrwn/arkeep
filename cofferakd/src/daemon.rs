//! Daemon core: in-memory vault state, ACL enforcement, and request
//! handling.
//!
//! `Daemon` holds the unwrapped DEK and the vault's entries in memory,
//! together with the service tokens allowed to operate on them and a handle
//! to the append-only audit log. [`Daemon::handle_request`] is the single
//! entry point every transport (the Unix socket listener in `main`, or a
//! test harness) funnels requests through; every outcome — allowed or
//! denied — is written to the audit log before the response is returned.
//!
//! ## Token keying
//!
//! `self.tokens` is keyed by the *hex-encoded secret* (lowercase, 64 hex
//! chars for the 32-byte [`AccessToken::secret`]) — exactly the string wire
//! clients send as a `Request`'s `token` field. This makes the lookup in
//! `handle_request` a single `BTreeMap::get` by value equality on that
//! string: no token is ever decoded into a struct, formatted, or compared
//! byte-by-byte in a way that could tempt printing it. [`token_key`] is the
//! single place that derives this key from a raw secret, so every caller
//! that builds the map (tests, `main`) uses the same convention the lookup
//! relies on.
//!
//! **Security note:** an [`AccessToken`]'s `secret` field, and the token
//! wire-format string itself, must never be passed to `{:?}`, printed, or
//! written to the audit log. Only [`AccessToken::service_id`] — an opaque
//! label chosen by whoever provisioned the token, not derived from the
//! secret — ever reaches an [`AuditEntry`].
//!
//! ## Durability (ADR 0010)
//!
//! A `Daemon` built with [`Daemon::with_persistence`] writes every
//! successful `set`/`rm` through to `vault.cofferak` *before* acknowledging
//! it: under the vault's exclusive [`VaultLock`], it re-reads the file
//! from disk, applies exactly that one change, and saves atomically. If
//! the write fails, the in-memory state is left unchanged and the client
//! gets `Response::Err` — a write is never acknowledged unless it is on
//! disk. A `Daemon` built with plain [`Daemon::new`] is in-memory only
//! (used by tests and the dev-only harness).

use std::collections::BTreeMap;
use std::path::PathBuf;

use cofferak_core::acl::{path_allowed, AccessToken};
use cofferak_core::crypto::{decrypt_entry, encrypt_entry, Aad, DekWrapHost, KeyBytes};
use cofferak_core::format::{write_anchor, VaultEntry, VaultFile, VaultLock};

use crate::audit::{AuditEntry, AuditLog};
use crate::protocol::{Request, Response};

/// Derive the key under which a token with this `secret` must be stored in
/// the map passed to [`Daemon::new`]: the lowercase hex encoding of the
/// secret, matching the wire `token` string clients send.
pub fn token_key(secret: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in secret {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Current time as Unix seconds, saturating to 0 if the clock is somehow
/// before the epoch. Never panics.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Where and how a persistent `Daemon` writes its changes back to disk.
struct Persistence {
    vault_path: PathBuf,
    host_id: String,
    /// This host's DEK wrap as it was when the daemon unsealed the DEK at
    /// startup. If the on-disk wrap no longer matches (a `rotate-dek` ran,
    /// or this host was re-enrolled), the daemon's in-memory DEK is stale:
    /// writing entries encrypted under it would corrupt the vault, so
    /// writes are refused until the daemon is restarted.
    host_wrap: DekWrapHost,
    /// Identity of `vault.cofferak` as last loaded or written by this
    /// daemon. When it changes (another process — `import`,
    /// `enroll-service`, ... — replaced the file), the daemon reloads its
    /// entries and service tokens before serving the next request.
    stamp: Option<FileStamp>,
    /// Set once a re-keyed vault has been reported, to log it only once.
    rekey_reported: bool,
    /// Newest vault generation this daemon has loaded or written (ADR
    /// 0015). A file with a lower generation is an older copy.
    generation_seen: u64,
    /// Set while the file on disk fails its integrity or rollback check:
    /// reads keep using the last good state, writes are refused.
    integrity_failure: Option<String>,
}

/// (device, inode, mtime seconds, mtime nanoseconds, length) of a file.
/// Every vault write is an atomic rename, so any change gives a new inode.
type FileStamp = (u64, u64, i64, i64, u64);

fn file_stamp(path: &std::path::Path) -> Option<FileStamp> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    Some((m.dev(), m.ino(), m.mtime(), m.mtime_nsec(), m.len()))
}

/// Decrypt and decode every enrolled service's `AccessToken` from
/// `vault.services`, keyed by [`token_key`]. A service entry that fails to
/// decrypt or decode is skipped with a warning rather than taking the rest
/// down with it.
pub fn load_tokens(vault: &VaultFile, dek: &[u8; 32]) -> BTreeMap<String, AccessToken> {
    let mut tokens = BTreeMap::new();
    for (service_id, entry) in &vault.services {
        let plaintext = match decrypt_entry(dek, &Aad::service_token(service_id), entry) {
            Ok(bytes) => zeroize::Zeroizing::new(bytes),
            Err(e) => {
                eprintln!("cofferakd: could not decrypt token for service '{service_id}': {e}, skipping it");
                continue;
            }
        };
        match bincode::deserialize::<AccessToken>(&plaintext) {
            Ok(token) => {
                tokens.insert(token_key(&token.secret), token);
            }
            Err(e) => {
                eprintln!("cofferakd: could not decode token for service '{service_id}': {e}, skipping it");
            }
        }
    }
    tokens
}

/// One entry-level change to write through to disk.
enum Change<'a> {
    Upsert(&'a str, &'a VaultEntry),
    Remove(&'a str),
}

/// Daemon state: the unwrapped DEK, the vault's entries, the tokens
/// allowed to operate on those entries, the audit log every outcome is
/// appended to, and (optionally) where to persist changes.
///
/// Fields are private: only `handle_request` exposes behavior, so nothing
/// outside this module can accidentally print or leak token secrets or the
/// DEK.
pub struct Daemon {
    dek: KeyBytes,
    entries: BTreeMap<String, VaultEntry>,
    /// Indexed by SHA-256 of the wire token (see [`token_index`]), so a
    /// lookup compares fixed digests, never a client's guess against the
    /// real token string.
    tokens: BTreeMap<[u8; 32], AccessToken>,
    audit: AuditLog,
    persistence: Option<Persistence>,
}

/// SHA-256 of a wire token string: the daemon's internal token key.
fn token_digest(token: &str) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(token.as_bytes()).into()
}

/// Re-key a map from [`token_key`] strings to their digests.
fn token_index(tokens: BTreeMap<String, AccessToken>) -> BTreeMap<[u8; 32], AccessToken> {
    tokens
        .into_iter()
        .map(|(k, v)| (token_digest(&k), v))
        .collect()
}

impl Daemon {
    /// Build an in-memory `Daemon` from an unwrapped `dek`, the loaded
    /// `vault`, a map of tokens keyed by [`token_key`], and an already-open
    /// audit log. Changes are NOT persisted — call
    /// [`with_persistence`](Self::with_persistence) for a real daemon.
    pub fn new(
        dek: [u8; 32],
        vault: VaultFile,
        tokens: BTreeMap<String, AccessToken>,
        audit: AuditLog,
    ) -> Self {
        Daemon {
            dek: KeyBytes::new(dek),
            entries: vault.entries,
            tokens: token_index(tokens),
            audit,
            persistence: None,
        }
    }

    /// Make every successful `set`/`rm` durable: written through to
    /// `vault_path` (under the vault lock, atomically) before it is
    /// acknowledged. `host_id`/`host_wrap` identify the wrap the DEK was
    /// unsealed from, so a re-keyed vault on disk is detected rather than
    /// silently overwritten with entries under a stale DEK.
    pub fn with_persistence(
        mut self,
        vault_path: PathBuf,
        host_id: String,
        host_wrap: DekWrapHost,
        generation_seen: u64,
    ) -> Self {
        let stamp = file_stamp(&vault_path);
        self.persistence = Some(Persistence {
            vault_path,
            host_id,
            host_wrap,
            stamp,
            rekey_reported: false,
            generation_seen,
            integrity_failure: None,
        });
        self
    }

    /// If `vault.cofferak` changed on disk since this daemon last loaded or
    /// wrote it, reload entries and service tokens, so CLI changes
    /// (`import`, `enroll-service`, ...) take effect without a restart.
    /// If the vault was re-keyed (`rotate-dek`), the in-memory state is
    /// kept and writes stay refused until a restart (see [`persist`]).
    fn refresh_from_disk(&mut self) {
        let Some(p) = &mut self.persistence else {
            return;
        };
        let now = file_stamp(&p.vault_path);
        if now.is_none() || now == p.stamp {
            return;
        }
        let disk = match VaultFile::load(&p.vault_path) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("cofferakd: vault changed on disk but could not be reloaded: {e}");
                return;
            }
        };
        if let Err(e) = disk.verify(&self.dek, Some(p.generation_seen)) {
            let msg = e.to_string();
            if p.integrity_failure.as_deref() != Some(msg.as_str()) {
                eprintln!(
                    "cofferakd: ALERT: {msg}; serving the last verified state, writes refused"
                );
            }
            p.integrity_failure = Some(msg);
            p.stamp = now;
            return;
        }
        p.integrity_failure = None;
        if disk.hosts.get(&p.host_id) != Some(&p.host_wrap) {
            if !p.rekey_reported {
                eprintln!("cofferakd: vault on disk was re-keyed; serving the last loaded state, writes refused until restart");
                p.rekey_reported = true;
            }
            p.stamp = now;
            return;
        }
        p.stamp = now;
        p.generation_seen = p.generation_seen.max(disk.generation);
        self.tokens = token_index(load_tokens(&disk, &self.dek));
        self.entries = disk.entries;
    }

    /// Handle one request: resolve the token, enforce the ACL, perform the
    /// action, and append exactly one audit entry before returning.
    pub fn handle_request(&mut self, req: Request) -> Response {
        self.refresh_from_disk();
        match req {
            Request::Get { token, path } => self.handle_get(&token, &path),
            Request::Set { token, path, value } => self.handle_set(&token, &path, value),
            Request::Rm { token, path } => self.handle_rm(&token, &path),
            Request::List { token, prefix } => self.handle_list(&token, &prefix),
        }
    }

    /// Write one change through to disk, if this daemon is persistent.
    /// Re-reads the vault under its exclusive lock and applies only this
    /// change, so concurrent CLI admin edits to other parts of the file
    /// (hosts, services) are never clobbered.
    fn persist(&mut self, change: Change<'_>) -> Result<(), String> {
        let Some(p) = &mut self.persistence else {
            return Ok(());
        };
        let _lock =
            VaultLock::acquire(&p.vault_path).map_err(|e| format!("could not lock vault: {e}"))?;
        let mut disk = VaultFile::load(&p.vault_path)
            .map_err(|e| format!("could not re-read vault before writing: {e}"))?;
        if let Some(why) = &p.integrity_failure {
            return Err(why.clone());
        }
        disk.verify(&self.dek, Some(p.generation_seen))
            .map_err(|e| e.to_string())?;
        if disk.hosts.get(&p.host_id) != Some(&p.host_wrap) {
            return Err(format!(
                "vault on disk was re-keyed (rotate-dek) or host '{}' was re-enrolled \
                 since cofferakd started; refusing to write with a stale DEK — restart cofferakd",
                p.host_id
            ));
        }
        match change {
            Change::Upsert(path, entry) => {
                disk.entries.insert(path.to_string(), entry.clone());
            }
            Change::Remove(path) => {
                disk.entries.remove(path);
            }
        }
        disk.seal(&self.dek);
        disk.save(&p.vault_path)
            .map_err(|e| format!("could not write vault: {e}"))?;
        // Our own write must not look like an external change.
        p.stamp = file_stamp(&p.vault_path);
        p.generation_seen = disk.generation;
        if let Some(dir) = p.vault_path.parent() {
            if let Err(e) = write_anchor(dir, &p.host_id, &self.dek, disk.generation) {
                eprintln!("cofferakd: could not update this host's anchor (rollback protection is degraded until the next write): {e}");
            }
        }
        Ok(())
    }

    /// Append one audit entry. I/O failure here is best-effort: it must
    /// never crash the daemon or change the response sent to the client.
    /// `service_id` is the only token-derived value ever passed in here —
    /// never the token string or an `AccessToken` itself.
    fn log(&self, service_id: &str, path: &str, action: &str, result: &str) {
        let entry = AuditEntry {
            ts: now_unix(),
            service_id: service_id.to_string(),
            path: audit_safe(path),
            action: action.to_string(),
            result: result.to_string(),
        };
        let _ = self.audit.append(&entry);
    }

    fn handle_get(&mut self, token: &str, path: &str) -> Response {
        let tok = self.tokens.get(&token_digest(token)).cloned();
        let Some(tok) = tok else {
            self.log("unknown", path, "get", "denied");
            return Response::Denied;
        };
        if !tok.permission.allows_read() || !path_allowed(&tok.prefixes, path) {
            self.log(&tok.service_id, path, "get", "denied");
            return Response::Denied;
        }
        match self.entries.get(path) {
            None => {
                self.log(&tok.service_id, path, "get", "not_found");
                Response::NotFound
            }
            Some(entry) => match decrypt_entry(&self.dek, &Aad::entry(path), &entry.ciphertext) {
                Ok(plaintext) => {
                    self.log(&tok.service_id, path, "get", "ok");
                    Response::Value(plaintext)
                }
                Err(_) => {
                    self.log(&tok.service_id, path, "get", "error");
                    Response::Err("failed to decrypt entry".to_string())
                }
            },
        }
    }

    fn handle_set(&mut self, token: &str, path: &str, value: Vec<u8>) -> Response {
        let tok = self.tokens.get(&token_digest(token)).cloned();
        let Some(tok) = tok else {
            self.log("unknown", path, "set", "denied");
            return Response::Denied;
        };
        if !tok.permission.allows_write() || !path_allowed(&tok.prefixes, path) {
            self.log(&tok.service_id, path, "set", "denied");
            return Response::Denied;
        }
        if value.len() > crate::protocol::MAX_VALUE_BYTES {
            self.log(&tok.service_id, path, "set", "too large");
            return Response::Err(format!(
                "value too large ({} bytes, limit {})",
                value.len(),
                crate::protocol::MAX_VALUE_BYTES
            ));
        }
        let version = self
            .entries
            .get(path)
            .map(|e| e.version.saturating_add(1))
            .unwrap_or(1);
        let entry = VaultEntry {
            ciphertext: encrypt_entry(&self.dek, &Aad::entry(path), &value),
            version,
            updated_at: now_unix(),
        };
        if let Err(e) = self.persist(Change::Upsert(path, &entry)) {
            eprintln!("cofferakd: set for '{path}' not persisted: {e}");
            self.log(&tok.service_id, path, "set", "error");
            return Response::Err("write could not be persisted; see cofferakd logs".to_string());
        }
        self.entries.insert(path.to_string(), entry);
        self.log(&tok.service_id, path, "set", "ok");
        Response::Ok
    }

    fn handle_rm(&mut self, token: &str, path: &str) -> Response {
        let tok = self.tokens.get(&token_digest(token)).cloned();
        let Some(tok) = tok else {
            self.log("unknown", path, "rm", "denied");
            return Response::Denied;
        };
        if !tok.permission.allows_write() || !path_allowed(&tok.prefixes, path) {
            self.log(&tok.service_id, path, "rm", "denied");
            return Response::Denied;
        }
        if !self.entries.contains_key(path) {
            self.log(&tok.service_id, path, "rm", "not_found");
            return Response::NotFound;
        }
        if let Err(e) = self.persist(Change::Remove(path)) {
            eprintln!("cofferakd: rm for '{path}' not persisted: {e}");
            self.log(&tok.service_id, path, "rm", "error");
            return Response::Err("write could not be persisted; see cofferakd logs".to_string());
        }
        self.entries.remove(path);
        self.log(&tok.service_id, path, "rm", "ok");
        Response::Ok
    }

    fn handle_list(&mut self, token: &str, prefix: &str) -> Response {
        let tok = self.tokens.get(&token_digest(token)).cloned();
        let Some(tok) = tok else {
            self.log("unknown", prefix, "list", "denied");
            return Response::Denied;
        };
        if !tok.permission.allows_read() || !path_allowed(&tok.prefixes, prefix) {
            self.log(&tok.service_id, prefix, "list", "denied");
            return Response::Denied;
        }
        let prefix_vec = vec![prefix.to_string()];
        let matches: Vec<String> = self
            .entries
            .keys()
            .filter(|key| path_allowed(&prefix_vec, key))
            .cloned()
            .collect();
        self.log(&tok.service_id, prefix, "list", "ok");
        Response::Listed(matches)
    }
}

/// Longest path kept in an audit entry. Requests are checked before the
/// path is used, so anything longer is junk from a client and is cut.
const AUDIT_PATH_MAX: usize = 256;

/// Make a client-supplied path safe to store in the audit log: control
/// characters (newlines, terminal escapes) are escaped, and the length is
/// capped so unauthenticated requests can't grow the log quickly.
pub fn audit_safe(path: &str) -> String {
    let mut out = String::new();
    for c in path.chars() {
        if out.len() >= AUDIT_PATH_MAX {
            out.push_str("...");
            break;
        }
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod audit_safe_tests {
    use super::audit_safe;

    #[test]
    fn control_characters_are_escaped_and_length_capped() {
        assert_eq!(audit_safe("app/x"), "app/x");
        assert_eq!(
            audit_safe("a\nfake 0 svc get b ok"),
            "a\\nfake 0 svc get b ok"
        );
        assert_eq!(audit_safe("\u{1b}[31mred"), "\\u{1b}[31mred");
        let long = "a".repeat(10_000);
        assert!(audit_safe(&long).len() <= 260);
    }
}
