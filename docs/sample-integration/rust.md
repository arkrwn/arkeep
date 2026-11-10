# Sample integration: Rust

Crate: [`sdk/rust/mikavt-sdk`](../../sdk/rust/mikavt-sdk). No dependency
on `mikavtd`/`mikavt-core` — just the wire protocol, so it's usable as a
standalone dependency.

```toml
# Cargo.toml
[dependencies]
mikavt-sdk = { path = "path/to/mikavt/sdk/rust/mikavt-sdk" }
# (or, once published) mikavt-sdk = "0.1"
```

```rust
use mikavt_sdk::{Client, SdkError};

fn fetch_db_password() -> Result<Vec<u8>, SdkError> {
    let client = Client::connect("/run/mikavt/mikavtd.sock");
    client.get("<token>", "azmika/DB_PASSWORD")
}

fn main() {
    let client = Client::connect(std::env::var("MIKAVT_SOCKET").unwrap());
    let token = std::env::var("MIKAVT_TOKEN").unwrap();

    client.set(&token, "myapp/DB_PASSWORD", b"s3cr3t").unwrap();
    let value = client.get(&token, "myapp/DB_PASSWORD").unwrap();
    assert_eq!(value, b"s3cr3t");

    match client.get(&token, "someone-elses/SECRET") {
        Err(SdkError::Denied) => println!("correctly denied"),
        other => panic!("expected Denied, got {other:?}"),
    }
}
```

This exact flow is what
[`sdk/rust/mikavt-sdk/examples/smoke.rs`](../../sdk/rust/mikavt-sdk/examples/smoke.rs)
runs for real in CI (`scripts/sdk-smoke.sh`).
