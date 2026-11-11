//! Process hardening applied at startup by `cofferakd` and the `cofferak`
//! CLI (ADR 0017): keys and plaintext must not end up in a core dump or be
//! readable by a debugger attached by another process of the same user.

/// Disable core dumps and block debugger attachment, best effort. Never
/// fails: on a platform or sandbox where a call is refused, the process
/// keeps running with the protections it could get.
pub fn harden_process() {
    // SAFETY: plain syscalls with valid arguments and no shared state.
    unsafe {
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &none);

        // Not dumpable: no core files, and other processes of the same user
        // can't ptrace this one or read /proc/<pid>/mem.
        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);

        // Refuse debugger attachment from other processes.
        #[cfg(target_os = "macos")]
        libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
    }
}

/// Keep each host's anchor in a second place outside the data directory
/// (ADR 0017): the Keychain on macOS, `$COFFERAK_ANCHOR_DIR` or
/// `/var/lib/cofferak-anchor` on Linux (when that directory exists).
pub fn enable_anchor_mirror() {
    #[cfg(target_os = "macos")]
    cofferak_core::format::set_anchor_mirror(Box::new(cofferak_core::seal::KeychainAnchorMirror));
    #[cfg(target_os = "linux")]
    if let Some(m) = cofferak_core::format::DirAnchorMirror::from_env() {
        cofferak_core::format::set_anchor_mirror(Box::new(m));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn core_dumps_are_disabled_after_hardening() {
        // Only the rlimit part is checked here: PT_DENY_ATTACH would stop
        // the test runner from being debugged.
        let none = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let mut got = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        unsafe {
            libc::setrlimit(libc::RLIMIT_CORE, &none);
            libc::getrlimit(libc::RLIMIT_CORE, &mut got);
        }
        assert_eq!(got.rlim_cur, 0);
    }
}
