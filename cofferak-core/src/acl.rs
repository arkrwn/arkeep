//! Path-prefix access control and access-token model.
//!
//! This module is pure logic: it decides whether a secret path falls under a
//! token's granted prefixes and whether a permission level allows reads or
//! writes. It has no dependency on the crypto or on-disk format modules.

use serde::{Deserialize, Serialize};

/// Level of access a token grants over its prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
    Read,
    Write,
    ReadWrite,
}

impl Permission {
    /// Whether this permission allows reading secrets.
    pub fn allows_read(&self) -> bool {
        matches!(self, Permission::Read | Permission::ReadWrite)
    }

    /// Whether this permission allows writing secrets.
    pub fn allows_write(&self) -> bool {
        matches!(self, Permission::Write | Permission::ReadWrite)
    }
}

/// A token issued to a service, scoped to a set of path prefixes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    pub service_id: String,
    pub prefixes: Vec<String>,
    pub permission: Permission,
    pub secret: [u8; 32],
}

/// Returns true iff `path` is non-empty, contains no `..` segment, and equals
/// one of `prefixes` or starts with one of them followed by `/`.
///
/// Never panics. Empty prefixes and empty paths yield `false`.
pub fn path_allowed(prefixes: &[String], path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    if path.split('/').any(|segment| segment == "..") {
        return false;
    }
    prefixes.iter().any(|prefix| {
        !prefix.is_empty()
            && (path == prefix
                || path
                    .strip_prefix(prefix.as_str())
                    .is_some_and(|rest| rest.starts_with('/')))
    })
}

/// Validate a host or service id. Ids end up in file paths
/// (`hosts/<id>.seal`), OS credential names (`cofferak-<id>`), and Keychain
/// account names, so they are restricted to `[A-Za-z0-9._-]`, 1–64
/// characters, not starting with `.` or `-` — which rules out path
/// separators, `..`, hidden files, and option-like values by
/// construction. `kind` is only used in the error message.
pub fn validate_id(kind: &str, id: &str) -> Result<(), String> {
    let ok_len = !id.is_empty() && id.len() <= 64;
    let ok_chars = id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-');
    let ok_start = !id.starts_with('.') && !id.starts_with('-');
    if ok_len && ok_chars && ok_start {
        Ok(())
    } else {
        Err(format!(
            "invalid {kind} id {id:?}: use 1-64 characters from [A-Za-z0-9._-], \
             not starting with '.' or '-'"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_id_accepts_ordinary_ids() {
        for id in ["host-a", "web01", "my_service", "svc.v2", "A"] {
            assert!(validate_id("host", id).is_ok(), "{id} should be valid");
        }
    }

    #[test]
    fn validate_id_rejects_traversal_separators_and_option_like_values() {
        for id in [
            "",
            "..",
            "../etc/passwd",
            "a/b",
            "a\\b",
            ".hidden",
            "-rf",
            "with space",
            "nul\0byte",
            &"x".repeat(65),
        ] {
            assert!(
                validate_id("host", id).is_err(),
                "{id:?} should be rejected"
            );
        }
    }

    fn prefixes(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn path_under_prefix_is_allowed() {
        assert!(path_allowed(&prefixes(&["myapp"]), "myapp/OPENAI_API_KEY"));
    }

    #[test]
    fn exact_prefix_match_is_allowed() {
        assert!(path_allowed(&prefixes(&["myapp"]), "myapp"));
    }

    #[test]
    fn other_prefix_is_rejected() {
        assert!(!path_allowed(&prefixes(&["myapp"]), "other/KEY"));
    }

    #[test]
    fn sibling_sharing_text_prefix_is_rejected() {
        assert!(!path_allowed(&prefixes(&["myapp"]), "myappX/KEY"));
    }

    #[test]
    fn empty_path_is_rejected() {
        assert!(!path_allowed(&prefixes(&["myapp"]), ""));
    }

    #[test]
    fn traversal_segment_is_rejected() {
        assert!(!path_allowed(&prefixes(&["myapp"]), "myapp/../root/KEY"));
    }

    #[test]
    fn trailing_traversal_segment_is_rejected() {
        assert!(!path_allowed(&prefixes(&["myapp"]), "myapp/.."));
    }

    #[test]
    fn empty_prefixes_reject_everything() {
        assert!(!path_allowed(&[], "anything"));
    }

    #[test]
    fn empty_prefix_entry_matches_nothing() {
        assert!(!path_allowed(&prefixes(&[""]), "anything"));
        assert!(!path_allowed(&prefixes(&[""]), "/anything"));
    }

    #[test]
    fn read_permission_does_not_allow_write() {
        assert!(Permission::Read.allows_read());
        assert!(!Permission::Read.allows_write());
    }

    #[test]
    fn write_permission_does_not_allow_read() {
        assert!(!Permission::Write.allows_read());
        assert!(Permission::Write.allows_write());
    }

    #[test]
    fn read_write_permission_allows_both() {
        assert!(Permission::ReadWrite.allows_read());
        assert!(Permission::ReadWrite.allows_write());
    }
}
