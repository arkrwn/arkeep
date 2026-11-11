# Sample integration: Rust

Crate: [`sdk/rust/cofferak-sdk`](../../sdk/rust/cofferak-sdk). No dependency
on `cofferakd`/`cofferak-core` — just the wire protocol, so it's usable as a
standalone dependency.

```toml
# Cargo.toml
[dependencies]
cofferak-sdk = { path = "path/to/cofferak/sdk/rust/cofferak-sdk" }
# (or, once published) cofferak-sdk = "0.1"
```

```rust
use cofferak_sdk::{Client, SdkError};

fn fetch_db_password() -> Result<Vec<u8>, SdkError> {
    let client = Client::connect("/run/cofferak/cofferakd.sock");
    client.get("<token>", "myapp/DB_PASSWORD")
}

fn main() {
    let client = Client::connect(std::env::var("COFFERAK_SOCKET").unwrap());
    let token = std::env::var("COFFERAK_TOKEN").unwrap();

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
[`sdk/rust/cofferak-sdk/examples/smoke.rs`](../../sdk/rust/cofferak-sdk/examples/smoke.rs)
runs for real in CI (`scripts/sdk-smoke.sh`).
