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

#[cfg(test)]
mod tests {
    use super::*;

    fn prefixes(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn path_under_prefix_is_allowed() {
        assert!(path_allowed(&prefixes(&["azmika"]), "azmika/OPENAI_API_KEY"));
    }

    #[test]
    fn exact_prefix_match_is_allowed() {
        assert!(path_allowed(&prefixes(&["azmika"]), "azmika"));
    }

    #[test]
    fn other_prefix_is_rejected() {
        assert!(!path_allowed(&prefixes(&["azmika"]), "other/KEY"));
    }

    #[test]
    fn sibling_sharing_text_prefix_is_rejected() {
        assert!(!path_allowed(&prefixes(&["azmika"]), "azmikaX/KEY"));
    }

    #[test]
    fn empty_path_is_rejected() {
        assert!(!path_allowed(&prefixes(&["azmika"]), ""));
    }

    #[test]
    fn traversal_segment_is_rejected() {
        assert!(!path_allowed(&prefixes(&["azmika"]), "azmika/../root/KEY"));
    }

    #[test]
    fn trailing_traversal_segment_is_rejected() {
        assert!(!path_allowed(&prefixes(&["azmika"]), "azmika/.."));
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
