# Sample integration: Rust

Crate: [`sdk/rust/arkeep-sdk`](../../sdk/rust/arkeep-sdk). No dependency
on `arkeepd`/`arkeep-core` — just the wire protocol, so it's usable as a
standalone dependency.

```toml
# Cargo.toml
[dependencies]
arkeep-sdk = { path = "path/to/arkeep/sdk/rust/arkeep-sdk" }
# (or, once published) arkeep-sdk = "0.1"
```

```rust
use arkeep_sdk::{Client, SdkError};

fn fetch_db_password() -> Result<Vec<u8>, SdkError> {
    let client = Client::connect("/run/arkeep/arkeepd.sock");
    client.get("<token>", "myapp/DB_PASSWORD")
}

fn main() {
    let client = Client::connect(std::env::var("ARKEEP_SOCKET").unwrap());
    let token = std::env::var("ARKEEP_TOKEN").unwrap();

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
[`sdk/rust/arkeep-sdk/examples/smoke.rs`](../../sdk/rust/arkeep-sdk/examples/smoke.rs)
runs for real in CI (`scripts/sdk-smoke.sh`).
