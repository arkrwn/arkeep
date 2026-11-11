//! Integration test for the Linux `systemd-creds` `HostSeal` backend.
//!
//! `SystemdCredsSeal` shells out to the real `systemd-creds` binary, so this
//! test only runs meaningfully where that binary exists: on Linux, with
//! systemd installed, AND (see `docs/adr/0009` — this was discovered the
//! first time this test ever ran against real CI, not assumed in advance)
//! running as root. `systemd-creds`'s default "host" scope encrypts against
//! `/var/lib/systemd/credential.secret`, which is root-only; the
//! alternative user-scoped `--uid=` flag only exists in systemd 256+, which
//! Ubuntu 24.04 (this project's primary CI/deployment target, systemd 255)
//! doesn't have — so root is the only broadly-compatible way to exercise
//! this backend's real "host" scope today. `SystemdCredsSeal` itself is
//! `cfg(target_os = "linux")`-gated in `arkeep_core::seal`, so:
//!
//! - On a non-Linux platform (e.g. macOS, where this test typically runs in
//!   development), the test prints a skip message and returns — there is
//!   nothing to exercise, since the type doesn't exist there.
//! - On Linux without the `systemd-creds` binary on `PATH`, the test checks
//!   for it at runtime via [`systemd_creds_available`] and prints a skip
//!   message and returns, rather than failing.
//! - On Linux as a non-root user, the test checks via [`running_as_root`]
//!   and skips with a message explaining why root is required, rather than
//!   failing — this is a real environment fact about `systemd-creds`'s
//!   host scope, not a gap in the test. CI additionally runs this specific
//!   test a second time via `sudo` (see `.github/workflows/ci.yml`) so the
//!   real, privileged path is still proven for real, not merely skipped.
//! - On Linux with `systemd-creds` available AND running as root, the test
//!   does a real seal/unseal round trip and confirms a corrupted sealed
//!   blob fails to unseal (rather than being accepted or panicking).
//!
//! In all skip cases, a skipped/unavailable backend is an expected, correct
//! outcome for this test, not a failure.

/// Returns true iff the `systemd-creds` binary can be spawned on this
/// system (regardless of its exit status — a spawn failure, e.g. "no such
/// file or directory", is what indicates the binary is unavailable).
#[allow(dead_code)]
fn systemd_creds_available() -> bool {
    std::process::Command::new("systemd-creds")
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Returns true iff this process's effective UID is 0 (root). Checked via
/// the `id -u` binary rather than an added `libc` dependency, for one
/// narrowly-scoped test — the output is just the numeric UID, no risk of
/// a misleading platform-specific difference worth a real dependency.
#[allow(dead_code)]
fn running_as_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim() == "0")
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
#[test]
fn seal_unseal_round_trips_and_rejects_corrupted_blob() {
    use arkeep_core::seal::{HostSeal, SealedBlob, SystemdCredsSeal};

    if !systemd_creds_available() {
        println!("skipped: systemd-creds not available");
        return;
    }
    if !running_as_root() {
        println!(
            "skipped: systemd-creds host-scope encryption requires root \
             (see docs/adr/0009); CI re-runs this test as root"
        );
        return;
    }

    let sealer = SystemdCredsSeal {
        name: "arkeep-test-seal-linux".to_string(),
    };

    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(13);
    }

    let sealed = sealer
        .seal(&key)
        .expect("seal should succeed when systemd-creds is available");
    let unsealed = sealer.unseal(&sealed).expect("unseal should round-trip");
    assert_eq!(unsealed, key);

    // Corrupt one byte of the sealed blob and confirm unseal rejects it
    // rather than returning garbage treated as a valid key.
    let mut corrupted = sealed.0.clone();
    let idx = corrupted.len() / 2;
    corrupted[idx] ^= 0xFF;
    let corrupted_blob = SealedBlob(corrupted);

    let result = sealer.unseal(&corrupted_blob);
    assert!(
        result.is_err(),
        "unseal of a corrupted blob must return Err, not garbage key bytes"
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn seal_unseal_round_trips_and_rejects_corrupted_blob() {
    println!(
        "skipped: systemd-creds backend (SystemdCredsSeal) is cfg(target_os = \"linux\")-only; \
         this platform is not Linux"
    );
}
