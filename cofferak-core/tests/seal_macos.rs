//! Integration test for the macOS Keychain `HostSeal` backend
//! (`KeychainSeal`).
//!
//! `KeychainSeal` is `cfg(target_os = "macos")`-gated in
//! `cofferak_core::seal`, and this test runs for real on macOS against a
//! real, uniquely-named, test-scoped Keychain item - not a skip, since
//! this backend is exercised on exactly the platform this crate is
//! developed on.

#![cfg(target_os = "macos")]

use cofferak_core::seal::{HostSeal, KeychainSeal, SealError};

/// Delete the keychain item for `service`/`account` out of band from the
/// `HostSeal` API, so the test can simulate a missing/deleted item.
///
/// Private to this test file (not part of cofferak-core's public API):
/// it reuses `security-framework`'s own `delete_generic_password` - the
/// same crate and item kind (a generic password) that `KeychainSeal`
/// itself uses to store/retrieve the key.
fn delete_item(service: &str, account: &str) {
    // Ignore the result: the item may already be absent
    // (`errSecItemNotFound`), which is fine - we only need the item to
    // not exist afterward, not to have actually deleted anything.
    let _ = security_framework::passwords::delete_generic_password(service, account);
}

#[test]
fn seal_unseal_round_trips_and_missing_item_is_invalid() {
    // Unique per test run (pid + nanosecond timestamp) so repeated runs
    // don't collide with, or get confused by, leftover Keychain items
    // from a previous run.
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be after the epoch")
            .as_nanos()
    );
    let service = format!("cofferak-test-seal-macos-service-{suffix}");
    let account = format!("cofferak-test-seal-macos-account-{suffix}");

    // Defensive clean slate in case a previous run of this exact test
    // crashed before its own cleanup ran.
    delete_item(&service, &account);

    let sealer = KeychainSeal {
        service: service.clone(),
        account: account.clone(),
    };

    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(11).wrapping_add(5);
    }

    // Ensure the item is cleaned up at the end of the test even on the
    // happy path, so successful runs don't accumulate Keychain clutter on
    // the developer's machine.
    let result = std::panic::catch_unwind(|| {
        let sealed = sealer.seal(&key).expect("seal should succeed");
        let unsealed = sealer.unseal(&sealed).expect("unseal should round-trip");
        assert_eq!(unsealed, key, "unsealed key must match the original");

        // Delete the keychain item out of band and confirm a second
        // unseal now fails with `SealError::Invalid`, not a panic and not
        // a successful (garbage) key.
        delete_item(&service, &account);

        match sealer.unseal(&sealed) {
            Err(SealError::Invalid(_)) => {}
            Err(other) => panic!("expected SealError::Invalid, got {other:?}"),
            Ok(_) => panic!("unseal of a deleted keychain item must not succeed"),
        }
    });

    // Final cleanup regardless of outcome: by this point the item was
    // already deleted above on the success path, but this also covers a
    // failure that happens before that point.
    delete_item(&service, &account);

    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn the_presence_flag_is_stored_with_the_key_and_does_not_change_it() {
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let service = format!("cofferak-test-presence-{suffix}");
    let account = format!("acct-{suffix}");
    delete_item(&service, &account);
    let sealer = KeychainSeal {
        service: service.clone(),
        account: account.clone(),
    };
    let key = [7u8; 32];
    let result = std::panic::catch_unwind(|| {
        let blob = sealer.seal_with_presence(&key, true).unwrap();
        assert!(sealer.presence_required().unwrap());
        assert_eq!(sealer.unseal(&blob).unwrap(), key);
        let blob = sealer.seal_with_presence(&key, false).unwrap();
        assert!(!sealer.presence_required().unwrap());
        assert_eq!(sealer.unseal(&blob).unwrap(), key);
    });
    delete_item(&service, &account);
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}
