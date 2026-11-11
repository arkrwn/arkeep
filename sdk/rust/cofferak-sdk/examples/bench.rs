//! End-to-end read benchmark against a running daemon: one `set`, then
//! many `get`s, each a full request/response over a fresh connection
//! (the SDK's real behaviour), reporting throughput and latency
//! percentiles. Used by `scripts/bench.sh`.
//!
//! Unix socket: COFFERAK_SOCKET, COFFERAK_TOKEN.
//! TLS (server mode): additionally COFFERAK_TLS_ADDR, COFFERAK_TLS_SERVER_NAME,
//! COFFERAK_TLS_CA, COFFERAK_TLS_CLIENT_CERT, COFFERAK_TLS_CLIENT_KEY.
//!
//! Usage: bench <path> <requests> [threads]

use std::sync::Arc;
use std::time::{Duration, Instant};

use cofferak_sdk::{Client, TlsOptions};

fn client_from_env() -> (Client, &'static str) {
    match std::env::var("COFFERAK_TLS_ADDR") {
        Ok(addr) if !addr.is_empty() => {
            let var = |n: &str| std::env::var(n).unwrap_or_else(|_| panic!("{n} must be set"));
            let client = Client::connect_tls(TlsOptions {
                addr,
                server_name: var("COFFERAK_TLS_SERVER_NAME"),
                ca_cert_path: var("COFFERAK_TLS_CA").into(),
                client_cert_and_key: Some((
                    var("COFFERAK_TLS_CLIENT_CERT").into(),
                    var("COFFERAK_TLS_CLIENT_KEY").into(),
                )),
            })
            .expect("valid TLS options");
            (client, "TLS 1.3 + mTLS (new handshake per request)")
        }
        _ => (
            Client::connect(std::env::var("COFFERAK_SOCKET").expect("COFFERAK_SOCKET")),
            "Unix socket",
        ),
    }
}

fn pct(sorted: &[Duration], p: f64) -> f64 {
    let i = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[i].as_nanos() as f64 / 1000.0
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = args
        .first()
        .cloned()
        .unwrap_or_else(|| "bench/value".into());
    let requests: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(10_000);
    let threads: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
    let token = Arc::new(std::env::var("COFFERAK_TOKEN").expect("COFFERAK_TOKEN"));

    let (client, transport) = client_from_env();
    let client = Arc::new(client);
    client
        .set(&token, &path, b"benchmark-secret-value-0123456789")
        .expect("set");

    let per_thread = requests / threads;
    let start = Instant::now();
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let (client, token, path) = (Arc::clone(&client), Arc::clone(&token), path.clone());
            std::thread::spawn(move || {
                let mut lat = Vec::with_capacity(per_thread);
                for _ in 0..per_thread {
                    let t = Instant::now();
                    std::hint::black_box(client.get(&token, &path).expect("get"));
                    lat.push(t.elapsed());
                }
                lat
            })
        })
        .collect();
    let mut lat: Vec<Duration> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    let elapsed = start.elapsed();
    lat.sort();

    println!(
        "get over {transport}, {threads} thread(s): {:>9.0} req/s  p50 {:>8.1} µs  p99 {:>8.1} µs  ({} requests)",
        lat.len() as f64 / elapsed.as_secs_f64(),
        pct(&lat, 0.50),
        pct(&lat, 0.99),
        lat.len()
    );
}
