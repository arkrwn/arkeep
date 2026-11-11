//! `arkeep-cli enroll-host <new_host_id>` / `enroll-service <id> --paths
//! <csv> --perm ro|rw`.
//!
//! `enroll-host` adds an *additional* host to a vault that already has at
//! least one host enrolled. This is the two-seal operation `init.rs`'s own
//! module doc explicitly deferred to this task: recovering the DEK
//! requires unsealing the already-enrolled host's own sealed blob with
//! *that host's* `HostSeal` backend, then wrapping the recovered DEK fresh
//! for the new host via the *new* host's own backend. Using the wrong
//! seal for either side is exactly the bug a single-seal signature can't
//! prevent (see `run_init_host_with_seal`'s doc comment for the longer
//! version of this story), so [`run_enroll_host_with_seal`] takes two
//! distinct `&dyn HostSeal` arguments, used only against their own
//! respective host's own sealed blob.
//!
//! `enroll-service` generates a fresh `AccessToken` for a consuming
//! service and persists it (encrypted under the vault DEK) into
//! `vault.services`. Recovering the DEK for this operation only ever
//! requires *reading* an already-enrolled host's own wrap with that same
//! host's own seal (never re-wrapping for a different identity), so it is
//! safe for [`run_enroll_service`] to try every enrolled host's real
//! platform backend in turn and use whichever one actually unseals: an
//! `HostSeal` implementation must fail closed on a blob it didn't
//! produce, so a mismatched attempt is just a clean `Err`, not a
//! correctness risk. [`run_enroll_service_with_seal`] is the test-only
//! seam (same convention as `run_init_host_with_seal`) that takes an
//! explicit `host_id`/seal pair instead of using the real platform
//! backend, so tests don't depend on `systemd-creds`/Keychain being
//! available.

use std::path::Path;

use arkeep_core::acl::{AccessToken, Permission};
use arkeep_core::crypto::{encrypt_entry, unwrap_dek_for_host, wrap_dek_for_host, KeyBytes};
use arkeep_core::format::{VaultFile, VaultMeta};
use arkeep_core::seal::{HostSeal, SealedBlob};

use super::init::{current_host_seal, host_seal_path, meta_path, random_key, vault_path, CliError};

/// Enroll `new_host_id` into a vault that already has `this_host_id`
/// enrolled.
///
/// - Returns `Err(CliError::VaultMissing)` if `data_dir` has no vault yet.
/// - Returns `Err(CliError::HostAlreadyEnrolled)` if `new_host_id` is
///   already in `vault.hosts`.
/// - Returns `Err(CliError::HostNotFound)` if `this_host_id` is *not* in
///   `vault.hosts` (there is nothing to recover the DEK from).
/// - Otherwise: reads `this_host_id`'s sealed blob from
///   `data_dir/hosts/<this_host_id>.seal`, unseals it with
///   `this_host_seal`, unwraps the DEK from `vault.hosts[this_host_id]`,
///   generates a fresh unseal key for `new_host_id`, seals it with
///   `new_host_seal`, persists that sealed blob under
///   `data_dir/hosts/<new_host_id>.seal`, wraps the (same, recovered) DEK
///   for `new_host_id` into `vault.hosts[new_host_id]`, and updates
///   `vault.arkeep` + `meta.json`.
pub fn run_enroll_host_with_seal(
    data_dir: &Path,
    this_host_id: &str,
    new_host_id: &str,
    this_host_seal: &dyn HostSeal,
    new_host_seal: &dyn HostSeal,
) -> Result<(), CliError> {
    let vpath = vault_path(data_dir);
    if !vpath.exists() {
        return Err(CliError::VaultMissing);
    }

    let mut vault = VaultFile::load(&vpath)?;

    if vault.hosts.contains_key(new_host_id) {
        return Err(CliError::HostAlreadyEnrolled);
    }

    let this_wrap = vault
        .hosts
        .get(this_host_id)
        .ok_or(CliError::HostNotFound)?
        .clone();

    let this_sealed_bytes = std::fs::read(host_seal_path(data_dir, this_host_id))?;
    let this_host_key = this_host_seal
        .unseal(&SealedBlob(this_sealed_bytes))
        .map_err(|e| CliError::Io(std::io::Error::other(e)))?;

    let dek = KeyBytes::new(
        unwrap_dek_for_host(&this_wrap, &this_host_key)
            .map_err(|e| CliError::Io(std::io::Error::other(e)))?,
    );

    let new_host_key = KeyBytes::new(random_key());
    let sealed = new_host_seal
        .seal(&new_host_key)
        .map_err(|e| CliError::Io(std::io::Error::other(e)))?;

    std::fs::create_dir_all(data_dir.join("hosts"))?;
    std::fs::write(host_seal_path(data_dir, new_host_id), &sealed.0)?;

    vault.hosts.insert(
        new_host_id.to_string(),
        wrap_dek_for_host(&dek, &new_host_key),
    );

    vault.save(&vpath)?;
    let meta = VaultMeta::from_vault(&vault);
    meta.save(&meta_path(data_dir))?;

    Ok(())
}

/// Enroll a new service, generating a random secret for its `AccessToken`
/// and persisting the token (serialized with `bincode`, encrypted under
/// the vault DEK) into `vault.services[service_id]`.
///
/// Recovers the DEK by trying every already-enrolled host's own sealed
/// blob against that same host's real platform [`HostSeal`] backend (via
/// [`current_host_seal`]), stopping at the first one that successfully
/// unseals — this machine is expected to be one of the vault's enrolled
/// hosts. Returns `Err(CliError::VaultMissing)` if there is no vault, or
/// `Err(CliError::HostNotFound)` if no enrolled host's blob unseals here.
///
/// See [`run_enroll_service_with_seal`] for the test-only seam that skips
/// this real-backend search.
// `#[allow(dead_code)]`: like `init.rs`'s `current_host_seal`/`run_init_host`,
// this file is also included directly (via `#[path]`) into the
// `cli_enroll` integration test binary, which only exercises
// `run_enroll_host_with_seal` and `run_enroll_service_with_seal` (the
// real platform `HostSeal` backend this function searches isn't
// available/stable in CI) — this one is used by the real `arkeep-cli`
// binary's `main.rs`.
#[allow(dead_code)]
pub fn run_enroll_service(
    data_dir: &Path,
    service_id: &str,
    prefixes: Vec<String>,
    permission: Permission,
) -> Result<AccessToken, CliError> {
    let vpath = vault_path(data_dir);
    if !vpath.exists() {
        return Err(CliError::VaultMissing);
    }

    let vault = VaultFile::load(&vpath)?;

    for host_id in vault.hosts.keys() {
        let seal = current_host_seal(host_id);
        if let Ok(token) = run_enroll_service_with_seal(
            data_dir,
            host_id,
            seal.as_ref(),
            service_id,
            prefixes.clone(),
            permission,
        ) {
            return Ok(token);
        }
    }

    Err(CliError::HostNotFound)
}

/// Test-only seam behind [`run_enroll_service`]: takes an explicit
/// `host_id`/`seal` pair instead of searching the real platform backend
/// across every enrolled host, so tests can inject a fake [`HostSeal`].
///
/// - Returns `Err(CliError::VaultMissing)` if `data_dir` has no vault.
/// - Returns `Err(CliError::HostNotFound)` if `host_id` is not in
///   `vault.hosts`.
/// - Otherwise: unseals `host_id`'s own blob with `seal`, unwraps the DEK,
///   builds the `AccessToken` (random 32-byte secret, the given
///   `service_id`/`prefixes`/`permission`), encrypts its `bincode`
///   serialization under the DEK, stores it in `vault.services[service_id]`
///   (overwriting any existing entry for that id), updates `vault.arkeep` +
///   `meta.json`, and returns the token.
pub fn run_enroll_service_with_seal(
    data_dir: &Path,
    host_id: &str,
    seal: &dyn HostSeal,
    service_id: &str,
    prefixes: Vec<String>,
    permission: Permission,
) -> Result<AccessToken, CliError> {
    let vpath = vault_path(data_dir);
    if !vpath.exists() {
        return Err(CliError::VaultMissing);
    }

    let mut vault = VaultFile::load(&vpath)?;

    let wrap = vault
        .hosts
        .get(host_id)
        .ok_or(CliError::HostNotFound)?
        .clone();

    let sealed_bytes = std::fs::read(host_seal_path(data_dir, host_id))?;
    let host_key = seal
        .unseal(&SealedBlob(sealed_bytes))
        .map_err(|e| CliError::Io(std::io::Error::other(e)))?;

    let dek = KeyBytes::new(
        unwrap_dek_for_host(&wrap, &host_key)
            .map_err(|e| CliError::Io(std::io::Error::other(e)))?,
    );

    let token = AccessToken {
        service_id: service_id.to_string(),
        prefixes,
        permission,
        secret: random_key(),
    };

    let plaintext =
        bincode::serialize(&token).map_err(|e| CliError::Io(std::io::Error::other(e)))?;
    let entry = encrypt_entry(&dek, &plaintext);

    vault.services.insert(service_id.to_string(), entry);

    vault.save(&vpath)?;
    let meta = VaultMeta::from_vault(&vault);
    meta.save(&meta_path(data_dir))?;

    Ok(token)
}
