//! User presence for admin commands on macOS (ADR 0017).
//!
//! On macOS the Keychain item holding a host key trusts the cofferak binary,
//! so without this any process running as the same user could run
//! `cofferak export` and read the vault. Hosts created with presence
//! required (the default) make every admin command confirm with Touch ID or
//! the login password before the host key is used. The daemon does not ask:
//! it only serves requests that carry a valid service token.

#[cfg(target_os = "macos")]
use cofferak_core::seal::{HostSeal, SealError, SealedBlob};

/// Set to `1` when creating a host (`init --host`, `enroll-host`,
/// `recover`) to store it without the presence requirement, for CI and
/// headless machines. It only affects hosts being created, so setting it
/// later can't remove the requirement from an existing host.
pub const NO_PRESENCE_ENV: &str = "COFFERAK_NO_USER_PRESENCE";

#[cfg(target_os = "macos")]
pub struct PresenceGatedSeal {
    pub inner: cofferak_core::seal::KeychainSeal,
}

#[cfg(target_os = "macos")]
impl HostSeal for PresenceGatedSeal {
    fn seal(&self, key: &[u8; 32]) -> Result<SealedBlob, SealError> {
        let require = std::env::var(NO_PRESENCE_ENV).as_deref() != Ok("1");
        self.inner.seal_with_presence(key, require)
    }

    fn unseal(&self, blob: &SealedBlob) -> Result<[u8; 32], SealError> {
        if self.inner.presence_required()? {
            confirm(&format!(
                "use the cofferak vault key of host \"{}\"",
                self.inner.account
            ))
            .map_err(|m| SealError::Io(std::io::Error::other(m)))?;
        }
        self.inner.unseal(blob)
    }
}

/// Ask the user to confirm with Touch ID or the login password, at most once
/// per process. Fails closed: no GUI session, cancel or timeout all refuse.
#[cfg(target_os = "macos")]
pub fn confirm(reason: &str) -> Result<(), String> {
    use std::sync::OnceLock;
    static RESULT: OnceLock<Result<(), String>> = OnceLock::new();
    RESULT.get_or_init(|| evaluate(reason)).clone()
}

#[cfg(target_os = "macos")]
fn evaluate(reason: &str) -> Result<(), String> {
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::sync::mpsc;
    use std::time::Duration;

    const REFUSED: &str =
        "this host requires user presence (Touch ID or your login password) for admin commands";
    let policy = LAPolicy::DeviceOwnerAuthentication;
    // SAFETY: plain Objective-C calls on a freshly created context.
    let ctx = unsafe { LAContext::new() };
    if let Err(e) = unsafe { ctx.canEvaluatePolicy_error(policy) } {
        return Err(format!(
            "{REFUSED}, but it can't be confirmed here ({}). Run the command in a logged-in macOS session.",
            e.localizedDescription()
        ));
    }
    let (tx, rx) = mpsc::channel::<Result<(), String>>();
    let block = RcBlock::new(move |ok: Bool, err: *mut NSError| {
        let r = if ok.as_bool() {
            Ok(())
        } else {
            // SAFETY: on failure LocalAuthentication passes a valid NSError
            // (or null), alive for the duration of the callback.
            let why = unsafe { err.as_ref() }
                .map(|e| e.localizedDescription().to_string())
                .unwrap_or_else(|| "not confirmed".to_string());
            Err(format!("{REFUSED}: {why}"))
        };
        let _ = tx.send(r);
    });
    let reason = NSString::from_str(reason);
    // SAFETY: the block and reason outlive the call, the reply runs on a
    // LocalAuthentication queue and only sends on the channel.
    unsafe { ctx.evaluatePolicy_localizedReason_reply(policy, &reason, &block) };
    rx.recv_timeout(Duration::from_secs(120))
        .unwrap_or_else(|_| Err(format!("{REFUSED}: timed out waiting for confirmation")))
}
