//! `cofferakd`: the cofferak daemon. All logic lives in the library
//! ([`cofferakd::server::run`]) so `cofferak daemon` can run the exact same
//! code from the CLI binary (ADR 0007).

fn main() {
    cofferakd::server::run();
}
