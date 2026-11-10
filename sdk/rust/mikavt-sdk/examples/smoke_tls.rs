//! Smoke test for the TLS/TCP transport (server mode, ADR 0008): set a
//! secret, read it back, confirm it round-trips, then confirm a denied
//! path fails cleanly — over TLS, not the Unix socket. Run against a
//! real daemon serving `$MIKAVT_TLS_ADDR` (see
//! `scripts/sdk-smoke.sh`/`scripts/server-mode-smoke.sh`, which generate
//! a real self-signed CA + server cert and run this for real — this is
//! not a mocked test).
//!
//! Usage: MIKAVT_TLS_ADDR=127.0.0.1:PORT MIKAVT_TLS_SERVER_NAME=name \
//!   MIKAVT_TLS_CA=/path/ca.pem MIKAVT_TOKEN=<token> \
//!   cargo run --example smoke_tls -p mikavt-sdk -- <allowed-path> <denied-path>

use mikavt_sdk::{Client, SdkError, TlsOptions};

fn env_required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

fn main() {
    let addr = env_required("MIKAVT_TLS_ADDR");
    let server_name = env_required("MIKAVT_TLS_SERVER_NAME");
    let ca_cert_path = env_required("MIKAVT_TLS_CA");
    let token = env_required("MIKAVT_TOKEN");

    let args: Vec<String> = std::env::args().skip(1).collect();
    let allowed_path = args
        .first()
        .cloned()
        .unwrap_or_else(|| "sdk-smoke/rust-tls".to_string());
    let denied_path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "other/denied".to_string());

    let client_cert_and_key = match (
        std::env::var("MIKAVT_TLS_CLIENT_CERT"),
        std::env::var("MIKAVT_TLS_CLIENT_KEY"),
    ) {
        (Ok(cert), Ok(key)) => Some((cert.into(), key.into())),
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
