# Sample integration: Rust

Crate: [`sdk/rust/cofferak-sdk`](https://github.com/arkrwn/cofferak/tree/main/sdk/rust/cofferak-sdk). No dependency
on `cofferakd`/`cofferak-core` - just the wire protocol, so it's usable as a
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
[`sdk/rust/cofferak-sdk/examples/smoke.rs`](https://github.com/arkrwn/cofferak/blob/main/sdk/rust/cofferak-sdk/examples/smoke.rs)
runs for real in CI (`scripts/sdk-smoke.sh`).

## Server mode (TLS 1.3 + mutual TLS)

```rust
use cofferak_sdk::{Client, TlsOptions};

let client = Client::connect_tls(TlsOptions {
    addr: "cofferak.example.internal:8443".into(),
    server_name: "cofferak.example.internal".into(),
    ca_cert_path: "/path/to/ca.pem".into(),
    // Mutual TLS is mandatory in cofferakd server mode (ADR 0011).
    client_cert_and_key: Some(("/path/to/client.pem".into(), "/path/to/client.key".into())),
})?;

// Optional: confirm what the handshake negotiated.
if let Some(info) = client.tls_session_info()? {
    println!("{} {} {}", info.protocol_version, info.cipher_suite, info.key_exchange_group);
    // TLSv1_3 TLS13_AES_256_GCM_SHA384 MLKEM1024
}
let value = client.get(&token, "myapp/DB_PASSWORD")?;
```

Uses `rustls` on AWS-LC with the same locked-down settings as the
daemon: TLS 1.3 only, `TLS_AES_256_GCM_SHA384` only, key exchange
ML-KEM-1024 > X25519MLKEM768 > P-384, and trust limited to the CA you
pass (no public root store). Proven by
[`sdk/rust/cofferak-sdk/examples/smoke_tls.rs`](https://github.com/arkrwn/cofferak/blob/main/sdk/rust/cofferak-sdk/examples/smoke_tls.rs),
run by `scripts/server-mode-smoke.sh`, which also asserts the negotiated
parameters shown above.
