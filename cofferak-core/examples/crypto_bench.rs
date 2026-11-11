//! Crypto micro-benchmark: how fast cofferak's primitives are on this
//! machine. Run with `cargo run --release -p cofferak-core --example
//! crypto_bench` (or `scripts/bench.sh`, which runs everything).
//!
//! - entry encrypt/decrypt: AES-256-GCM-SIV with path-bound associated
//!   data, the operation behind every `set`/`get`;
//! - root wrap/unwrap: the hybrid X25519 + ML-KEM-1024 KEM with
//!   HKDF-SHA-384, used only by `init`, `rotate-dek` and `recover`.

use std::time::{Duration, Instant};

use cofferak_core::crypto::{
    decrypt_entry, encrypt_entry, generate_root_keypair, unwrap_dek_for_root, wrap_dek_for_root,
    Aad,
};

fn rate(n: u32, elapsed: Duration) -> String {
    let per = elapsed / n;
    let ops = n as f64 / elapsed.as_secs_f64();
    format!(
        "{ops:>12.0} ops/s  {:>9.2} µs/op",
        per.as_nanos() as f64 / 1000.0
    )
}

fn main() {
    let dek = [0x42u8; 32];
    let aad = Aad::entry("app/DB_PASSWORD");

    for size in [64usize, 1024, 16 * 1024] {
        let value = vec![0xA5u8; size];
        let n: u32 = if size > 4096 { 50_000 } else { 200_000 };

        let start = Instant::now();
        let mut last = None;
        for _ in 0..n {
            last = Some(encrypt_entry(&dek, &aad, &value));
        }
        let enc = start.elapsed();
        let entry = last.unwrap();

        let start = Instant::now();
        for _ in 0..n {
            let pt = decrypt_entry(&dek, &aad, &entry).unwrap();
            std::hint::black_box(pt);
        }
        let dec = start.elapsed();

        println!("encrypt {size:>6} B (AES-256-GCM-SIV): {}", rate(n, enc));
        println!("decrypt {size:>6} B (AES-256-GCM-SIV): {}", rate(n, dec));
    }

    let n = 500u32;
    let (public, private) = generate_root_keypair().unwrap();
    let start = Instant::now();
    let mut last = None;
    for _ in 0..n {
        last = Some(wrap_dek_for_root(&dek, &public).unwrap());
    }
    let wrap = start.elapsed();
    let w = last.unwrap();
    let start = Instant::now();
    for _ in 0..n {
        std::hint::black_box(unwrap_dek_for_root(&w, &public, &private).unwrap());
    }
    let unwrap = start.elapsed();
    println!("root wrap   (X25519 + ML-KEM-1024):  {}", rate(n, wrap));
    println!("root unwrap (X25519 + ML-KEM-1024):  {}", rate(n, unwrap));
}
