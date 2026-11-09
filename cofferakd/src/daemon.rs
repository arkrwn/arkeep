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

// `token_key` and `save_to` are part of this module's public surface for
// callers that land in later tasks (real token provisioning, vault
// persistence on shutdown) and for the test harness; `main`'s current
// minimal wiring doesn't exercise them yet.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::Path;

use cofferak_core::acl::{path_allowed, AccessToken};
use cofferak_core::crypto::{
    decrypt_entry, encrypt_entry, DekWrapHost, DekWrapRoot, EncryptedEntry, KeyBytes,
};
use cofferak_core::format::{VaultEntry, VaultFile};

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

/// In-memory daemon state: the unwrapped DEK, the vault's entries (plus the
/// bits of `VaultFile` needed to write a complete vault back out), the
/// tokens allowed to operate on those entries, and the audit log every
/// outcome is appended to.
///
/// Fields are private: only `handle_request` and `save_to` expose behavior,
/// so nothing outside this module can accidentally print or leak token
/// secrets or the DEK.
pub struct Daemon {
    dek: KeyBytes,
    version: u16,
    created_at: i64,
    root_wrap: Option<DekWrapRoot>,
    services: BTreeMap<String, EncryptedEntry>,
    entries: BTreeMap<String, VaultEntry>,
    tokens: BTreeMap<String, AccessToken>,
    audit: AuditLog,
}

impl Daemon {
    /// Build a `Daemon` from an unwrapped `dek`, the loaded `vault`, a map
    /// of tokens keyed by [`token_key`], and an already-open audit log.
    pub fn new(
        dek: [u8; 32],
        vault: VaultFile,
        tokens: BTreeMap<String, AccessToken>,
        audit: AuditLog,
    ) -> Self {
        Daemon {
            dek: KeyBytes::new(dek),
            version: vault.version,
            created_at: vault.created_at,
            root_wrap: vault.root_wrap,
            services: vault.services,
            entries: vault.entries,
            tokens,
            audit,
        }
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

    /// Serialize the current entries/services (plus a caller-supplied root
    /// pubkey and per-host DEK wraps, which the daemon itself doesn't own)
    /// into a `VaultFile` and write it to `path`.
    pub fn save_to(
        &self,
        path: &Path,
        root_pubkey: [u8; 32],
        host_wraps: BTreeMap<String, DekWrapHost>,
    ) -> std::io::Result<()> {
        let vault = VaultFile {
            version: self.version,
            created_at: self.created_at,
            root_pubkey,
            root_wrap: self.root_wrap.clone(),
            hosts: host_wraps,
            services: self.services.clone(),
            entries: self.entries.clone(),
        };
        vault.save(path)
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
            Some(entry) => match decrypt_entry(&self.dek, &entry.ciphertext) {
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
        let version = self.entries.get(path).map(|e| e.version + 1).unwrap_or(1);
        let ciphertext = encrypt_entry(&self.dek, &value);
        self.entries.insert(
            path.to_string(),
            VaultEntry {
                ciphertext,
                version,
                updated_at: now_unix(),
            },
        );
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
        match self.entries.remove(path) {
            Some(_) => {
                self.log(&tok.service_id, path, "rm", "ok");
                Response::Ok
            }
            None => {
                self.log(&tok.service_id, path, "rm", "not_found");
                Response::NotFound
            }
        }
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
