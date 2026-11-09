//! Linux `HostSeal` backend: shells out to the real `systemd-creds` binary.
//!
//! `systemd-creds encrypt --name=<name>` reads raw key bytes on stdin and
//! writes a sealed credential blob to stdout; `systemd-creds decrypt
//! --name=<name>` is the inverse, reading a blob on stdin and writing the
//! raw key bytes to stdout. The `name` is bound into the seal by
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
            .stderr(Stdio::null())
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
            return Err(SealError::Invalid);
        }

        Ok(output.stdout)
    }
}

impl HostSeal for SystemdCredsSeal {
    fn seal(&self, key: &[u8; 32]) -> Result<SealedBlob, SealError> {
        let args = vec!["encrypt".to_string(), format!("--name={}", self.name)];
        let stdout = self.run(&args, key)?;
        Ok(SealedBlob(stdout))
    }

    fn unseal(&self, blob: &SealedBlob) -> Result<[u8; 32], SealError> {
        let args = vec!["decrypt".to_string(), format!("--name={}", self.name)];
        let stdout = self.run(&args, &blob.0)?;

        if stdout.len() != 32 {
            return Err(SealError::Invalid);
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&stdout);
        Ok(key)
    }
}
