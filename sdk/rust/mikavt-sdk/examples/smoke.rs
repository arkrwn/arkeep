//! Smoke test: set a secret, read it back, confirm it round-trips, then
//! confirm a denied path fails cleanly. Run against a real `mikavtd`
//! (see `scripts/sdk-smoke.sh`, which bootstraps one and runs this
//! example for real — this is not a mocked test).
//!
//! Usage: `MIKAVT_SOCKET=/path/to.sock MIKAVT_TOKEN=<token> cargo run
//! --example smoke -p mikavt-sdk -- <allowed-path> <denied-path>`

use mikavt_sdk::{Client, SdkError};

fn main() {
    let socket = std::env::var("MIKAVT_SOCKET").expect("MIKAVT_SOCKET must be set");
    let token = std::env::var("MIKAVT_TOKEN").expect("MIKAVT_TOKEN must be set");
    let args: Vec<String> = std::env::args().skip(1).collect();
    let allowed_path = args
        .first()
        .cloned()
        .unwrap_or_else(|| "sdk-smoke/rust".to_string());
    let denied_path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "other/denied".to_string());

    let client = Client::connect(&socket);

    let value = b"rust-sdk-smoke-value";
    client
        .set(&token, &allowed_path, value)
        .expect("set should succeed for an allowed path");
    let got = client
        .get(&token, &allowed_path)
        .expect("get should succeed for an allowed path");
    assert_eq!(got, value, "round-tripped value must match exactly");

    match client.get(&token, &denied_path) {
        Err(SdkError::Denied) => {}
        other => panic!("expected Denied for a path outside the token's prefix, got {other:?}"),
    }

    println!("rust SDK smoke test passed");
}
