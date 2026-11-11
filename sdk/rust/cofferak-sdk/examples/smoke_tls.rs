//! Smoke test for the TLS/TCP transport (server mode, ADR 0008): set a
//! secret, read it back, confirm it round-trips, then confirm a denied
//! path fails cleanly — over TLS, not the Unix socket. Run against a
//! real daemon serving `$COFFERAK_TLS_ADDR` (see
//! `scripts/sdk-smoke.sh`/`scripts/server-mode-smoke.sh`, which generate
//! a real self-signed CA + server cert and run this for real — this is
//! not a mocked test).
//!
//! Usage: COFFERAK_TLS_ADDR=127.0.0.1:PORT COFFERAK_TLS_SERVER_NAME=name \
//!   COFFERAK_TLS_CA=/path/ca.pem COFFERAK_TOKEN=<token> \
//!   cargo run --example smoke_tls -p cofferak-sdk -- <allowed-path> <denied-path>

use cofferak_sdk::{Client, SdkError, TlsOptions};

fn env_required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

fn main() {
    let addr = env_required("COFFERAK_TLS_ADDR");
    let server_name = env_required("COFFERAK_TLS_SERVER_NAME");
    let ca_cert_path = env_required("COFFERAK_TLS_CA");
    let token = env_required("COFFERAK_TOKEN");

    let args: Vec<String> = std::env::args().skip(1).collect();
    let allowed_path = args
        .first()
        .cloned()
        .unwrap_or_else(|| "sdk-smoke/rust-tls".to_string());
    let denied_path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "other/denied".to_string());

    // An empty-string env var (as opposed to an unset one — the smoke
    // script always exports both, blank when not applicable) must be
    // treated the same as "not set", not as a literal empty path.
    let client_cert_and_key = match (
        std::env::var("COFFERAK_TLS_CLIENT_CERT").unwrap_or_default(),
        std::env::var("COFFERAK_TLS_CLIENT_KEY").unwrap_or_default(),
    ) {
        (cert, key) if !cert.is_empty() && !key.is_empty() => Some((cert.into(), key.into())),
        _ => None,
    };

    let client = Client::connect_tls(TlsOptions {
        addr,
        server_name,
        ca_cert_path: ca_cert_path.into(),
        client_cert_and_key,
    })
    .expect("TLS client config should be valid");

    let value = b"rust-sdk-tls-smoke-value";
    client
        .set(&token, &allowed_path, value)
        .expect("set over TLS should succeed for an allowed path");
    let got = client
        .get(&token, &allowed_path)
        .expect("get over TLS should succeed for an allowed path");
    assert_eq!(got, value, "round-tripped value must match exactly");

    match client.get(&token, &denied_path) {
        Err(SdkError::Denied) => {}
        other => panic!("expected Denied for a path outside the token's prefix, got {other:?}"),
    }

    println!("rust SDK TLS (server mode) smoke test passed");
}
