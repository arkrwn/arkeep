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
use cofferak_core::format::{VaultEntry, VaultFile, VaultLock};

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
    tokens: BTreeMap<String, AccessToken>,
    audit: AuditLog,
    persistence: Option<Persistence>,
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
            tokens,
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
    ) -> Self {
        self.persistence = Some(Persistence {
            vault_path,
            host_id,
            host_wrap,
        });
        self
    }

    /// Handle one request: resolve the token, enforce the ACL, perform the
    /// action, and append exactly one audit entry before returning.
    pub fn handle_request(&mut self, req: Request) -> Response {
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
    fn persist(&self, change: Change<'_>) -> Result<(), String> {
        let Some(p) = &self.persistence else {
            return Ok(());
        };
        let _lock =
            VaultLock::acquire(&p.vault_path).map_err(|e| format!("could not lock vault: {e}"))?;
        let mut disk = VaultFile::load(&p.vault_path)
            .map_err(|e| format!("could not re-read vault before writing: {e}"))?;
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
        disk.save(&p.vault_path)
            .map_err(|e| format!("could not write vault: {e}"))
    }

    /// Append one audit entry. I/O failure here is best-effort: it must
    /// never crash the daemon or change the response sent to the client.
    /// `service_id` is the only token-derived value ever passed in here —
    /// never the token string or an `AccessToken` itself.
    fn log(&self, service_id: &str, path: &str, action: &str, result: &str) {
        let entry = AuditEntry {
            ts: now_unix(),
            service_id: service_id.to_string(),
            path: path.to_string(),
            action: action.to_string(),
            result: result.to_string(),
        };
        let _ = self.audit.append(&entry);
    }

    fn handle_get(&mut self, token: &str, path: &str) -> Response {
        let tok = self.tokens.get(token).cloned();
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
        let tok = self.tokens.get(token).cloned();
        let Some(tok) = tok else {
            self.log("unknown", path, "set", "denied");
            return Response::Denied;
        };
        if !tok.permission.allows_write() || !path_allowed(&tok.prefixes, path) {
            self.log(&tok.service_id, path, "set", "denied");
            return Response::Denied;
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
        let tok = self.tokens.get(token).cloned();
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
        let tok = self.tokens.get(token).cloned();
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
