// The daemon is a binary-only crate, so its modules are compiled in
// directly, same pattern as `audit_integration.rs`.
#[path = "../src/protocol.rs"]
mod protocol;
#[path = "../src/audit.rs"]
mod audit;
#[path = "../src/daemon.rs"]
mod daemon;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use audit::AuditLog;
use daemon::{token_key, Daemon};
use cofferak_core::acl::{AccessToken, Permission};
use cofferak_core::crypto::generate_root_keypair;
use cofferak_core::format::VaultFile;
use protocol::{Request, Response};

fn temp_audit_path(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cofferakd-daemon-it-{}-{}-{}.jsonl",
        tag,
        std::process::id(),
        nanos
    ))
}

const MYAPP_SECRET: [u8; 32] = [0x42; 32];

fn myapp_token() -> AccessToken {
    AccessToken {
        service_id: "myapp".to_string(),
        prefixes: vec!["myapp".to_string()],
        permission: Permission::ReadWrite,
        secret: MYAPP_SECRET,
    }
}

fn myapp_token_wire() -> String {
    token_key(&MYAPP_SECRET)
}

fn build_daemon(tag: &str) -> (Daemon, PathBuf) {
    let (root_pubkey, _root_privkey) = generate_root_keypair();
    let vault = VaultFile::new(root_pubkey);
    let mut tokens = BTreeMap::new();
    tokens.insert(token_key(&MYAPP_SECRET), myapp_token());
    let audit_path = temp_audit_path(tag);
    let audit = AuditLog::open(&audit_path).expect("open audit log");
    let dek = [0x7A; 32];
    (Daemon::new(dek, vault, tokens, audit), audit_path)
}

#[test]
fn known_token_can_set_and_get_under_its_prefix() {
    let (mut daemon, audit_path) = build_daemon("set-get");
    let token = myapp_token_wire();

    let set_resp = daemon.handle_request(Request::Set {
        token: token.clone(),
        path: "myapp/KEY".to_string(),
        value: b"super-secret".to_vec(),
    });
    assert_eq!(set_resp, Response::Ok);

    let get_resp = daemon.handle_request(Request::Get {
        token,
        path: "myapp/KEY".to_string(),
    });
    assert_eq!(get_resp, Response::Value(b"super-secret".to_vec()));

    let _ = std::fs::remove_file(&audit_path);
}

#[test]
fn known_token_outside_its_prefix_is_denied() {
    let (mut daemon, audit_path) = build_daemon("outside-prefix");
    let token = myapp_token_wire();

    let resp = daemon.handle_request(Request::Get {
        token,
        path: "other/KEY".to_string(),
    });
    assert_eq!(resp, Response::Denied);

    let _ = std::fs::remove_file(&audit_path);
}

#[test]
fn unknown_token_is_denied_for_every_request_type() {
    let (mut daemon, audit_path) = build_daemon("unknown-token");
    let bogus = "f".repeat(64);

    assert_eq!(
        daemon.handle_request(Request::Get {
            token: bogus.clone(),
            path: "myapp/KEY".to_string(),
        }),
        Response::Denied
    );
    assert_eq!(
        daemon.handle_request(Request::Set {
            token: bogus.clone(),
            path: "myapp/KEY".to_string(),
            value: b"x".to_vec(),
        }),
        Response::Denied
    );
    assert_eq!(
        daemon.handle_request(Request::Rm {
            token: bogus.clone(),
            path: "myapp/KEY".to_string(),
        }),
        Response::Denied
    );
    assert_eq!(
        daemon.handle_request(Request::List {
            token: bogus,
            prefix: "myapp".to_string(),
        }),
        Response::Denied
    );

    let _ = std::fs::remove_file(&audit_path);
}

#[test]
fn concurrent_requests_on_distinct_paths_never_panic_and_stay_consistent() {
    let (daemon, audit_path) = build_daemon("concurrent");
    let daemon = Arc::new(Mutex::new(daemon));
    let token = myapp_token_wire();
    let num_threads = 8;
    let barrier = Arc::new(Barrier::new(num_threads));

    let mut handles = Vec::new();
    for i in 0..num_threads {
        let daemon = Arc::clone(&daemon);
        let barrier = Arc::clone(&barrier);
        let token = token.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            let path = format!("myapp/thread-{i}");
            for iter in 0..25 {
                let value = format!("v{i}-{iter}").into_bytes();

                let set_resp = daemon.lock().unwrap().handle_request(Request::Set {
                    token: token.clone(),
                    path: path.clone(),
                    value: value.clone(),
                });
                assert_eq!(set_resp, Response::Ok);

                // Sequential checkpoint: the very next Get on this same
                // path, from the same thread, must reflect that Set.
                let get_resp = daemon.lock().unwrap().handle_request(Request::Get {
                    token: token.clone(),
                    path: path.clone(),
                });
                assert_eq!(get_resp, Response::Value(value));
            }
        }));
    }

    for h in handles {
        h.join().expect("thread should not panic");
    }

    let _ = std::fs::remove_file(&audit_path);
}
