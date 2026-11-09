//! Integration test for the Linux `systemd-creds` `HostSeal` backend.
//!
//! `SystemdCredsSeal` shells out to the real `systemd-creds` binary, so this
//! test only runs meaningfully where that binary exists: on Linux, with
//! systemd installed. `SystemdCredsSeal` itself is `cfg(target_os =
//! "linux")`-gated in `cofferak_core::seal`, so:
//!
//! - On a non-Linux platform (e.g. macOS, where this test typically runs in
//!   development), the test prints a skip message and returns — there is
//!   nothing to exercise, since the type doesn't exist there.
//! - On Linux without the `systemd-creds` binary on `PATH`, the test checks
//!   for it at runtime via [`systemd_creds_available`] and prints a skip
//!   message and returns, rather than failing.
//! - On Linux with `systemd-creds` available, the test does a real
//!   seal/unseal round trip and confirms a corrupted sealed blob fails to
//!   unseal (rather than being accepted or panicking).
//!
//! In all three cases a skipped/absent backend is an expected, correct
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

#[cfg(target_os = "linux")]
#[test]
fn seal_unseal_round_trips_and_rejects_corrupted_blob() {
    use cofferak_core::seal::{HostSeal, SealedBlob, SystemdCredsSeal};

    if !systemd_creds_available() {
        println!("skipped: systemd-creds not available");
        return;
    }

    let sealer = SystemdCredsSeal {
        name: "cofferak-test-seal-linux".to_string(),
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
