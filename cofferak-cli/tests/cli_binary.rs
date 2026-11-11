//! Tests that run the real `cofferak` binary, for behaviour that lives in
//! its argument handling rather than in the command functions.

use std::process::{Command, Stdio};

fn cofferak() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cofferak"))
}

#[test]
fn help_never_prints_the_token_from_the_environment() {
    let secret = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    for sub in ["get", "set", "rm", "list"] {
        let out = cofferak()
            .args([sub, "--help"])
            .env("COFFERAK_TOKEN", secret)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains("--token"),
            "{sub} --help should document --token"
        );
        assert!(!text.contains(secret), "{sub} --help leaked COFFERAK_TOKEN");
    }
}

#[test]
fn set_requires_exactly_one_value_source() {
    let base = |args: &[&str]| {
        cofferak()
            .args(args)
            .env("COFFERAK_TOKEN", "00")
            .env("COFFERAK_SOCKET", "/nonexistent/cofferak-test.sock")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    // No value at all: usage error from argument parsing, before any I/O.
    let out = base(&["set", "app/KEY"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    // Two sources at once: usage error.
    let out = base(&["set", "app/KEY", "v", "--stdin"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    let out = base(&["set", "app/KEY", "--stdin", "--from-file", "/etc/hosts"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    // A single source parses fine and only then fails to reach the daemon.
    let out = base(&["set", "app/KEY", "--stdin"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("could not connect"));
}

#[test]
fn set_from_file_rejects_oversized_values_before_connecting() {
    let dir = std::env::temp_dir().join(format!("cofferak-bin-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let big = dir.join("big.bin");
    std::fs::write(&big, vec![0u8; 3 * 1024 * 1024 + 1]).unwrap();
    let out = cofferak()
        .args(["set", "app/BIG", "--from-file"])
        .arg(&big)
        .env("COFFERAK_TOKEN", "00")
        .env("COFFERAK_SOCKET", "/nonexistent/cofferak-test.sock")
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("maximum secret size"));
}
