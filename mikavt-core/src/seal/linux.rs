//! Linux `HostSeal` backend: shells out to the real `systemd-creds` binary.
//!
//! `systemd-creds encrypt --name=<name> - -` reads raw key bytes on stdin
//! and writes a sealed credential blob to stdout; `systemd-creds decrypt
//! --name=<name> - -` is the inverse, reading a blob on stdin and writing
//! the raw key bytes to stdout. (The two `-` positional arguments — input
//! and output — are mandatory: without them systemd-creds exits with
//! "Too few arguments.") The `name` is bound into the seal by
//! `systemd-creds` itself, so decrypting with a different name (or a
//! tampered blob) fails.

use std::io::Write;
use std::process::{Command, Stdio};

use super::{HostSeal, SealError, SealedBlob};

/// A [`HostSeal`] backend that shells out to the system's `systemd-creds`
/// binary.
pub struct SystemdCredsSeal {
    pub name: String,
}

impl SystemdCredsSeal {
    /// Run `systemd-creds <args>`, feeding `input` on stdin and capturing
    /// stdout.
    ///
    /// Spawn failure (binary missing or not executable) maps to
    /// [`SealError::Unavailable`]; a non-zero exit status or empty stdout
    /// maps to [`SealError::Invalid`]; any other I/O failure while talking
    /// to the child process maps to [`SealError::Io`].
    fn run(&self, args: &[String], input: &[u8]) -> Result<Vec<u8>, SealError> {
        let mut child = Command::new("systemd-creds")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Captured (not discarded) so a real failure — most commonly
            // "Permission denied" reading the root-only host secret when
            // this process isn't root, see docs/adr/0009 — is visible in
            // the returned error instead of a bare "Invalid" that leaves
            // the caller guessing. systemd-creds's own stderr is
            // operational diagnostics, never the key material itself.
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| SealError::Unavailable)?;

        {
            let mut stdin = child.stdin.take().ok_or_else(|| {
                SealError::Io(std::io::Error::other(
                    "failed to open systemd-creds child stdin",
                ))
            })?;
            stdin.write_all(input)?;
            // `stdin` is dropped at the end of this block, closing the pipe
            // so the child process sees EOF on its stdin.
        }

        let output = child.wait_with_output()?;

        if !output.status.success() || output.stdout.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let detail = if stderr.trim().is_empty() {
                format!("systemd-creds {}", output.status)
            } else {
                format!("systemd-creds {}: {}", output.status, stderr.trim())
            };
            return Err(SealError::Invalid(detail));
        }

        Ok(output.stdout)
    }
}

impl HostSeal for SystemdCredsSeal {
    fn seal(&self, key: &[u8; 32]) -> Result<SealedBlob, SealError> {
        let args = vec![
            "encrypt".to_string(),
            format!("--name={}", self.name),
            "-".to_string(),
            "-".to_string(),
        ];
        let stdout = self.run(&args, key)?;
        Ok(SealedBlob(stdout))
    }

    fn unseal(&self, blob: &SealedBlob) -> Result<[u8; 32], SealError> {
        let args = vec![
            "decrypt".to_string(),
            format!("--name={}", self.name),
            "-".to_string(),
            "-".to_string(),
        ];
        let stdout = self.run(&args, &blob.0)?;

        if stdout.len() != 32 {
            return Err(SealError::Invalid(format!(
                "systemd-creds decrypt returned {} bytes, expected 32",
                stdout.len()
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&stdout);
        Ok(key)
    }
}
