#!/usr/bin/env bash
# Reproducible performance numbers for docs/benchmarks.md: crypto
# primitives, then end-to-end `get` throughput/latency through a real
# daemon over the Unix socket and over TLS 1.3 + mutual TLS.
#
# The daemon is cofferakd/examples/dev-daemon.rs: the same `Daemon`
# request path as the real cofferakd (token lookup, ACL, AES-256-GCM-SIV
# decrypt, audit log append), without host-key sealing, which only
# happens once at startup. Reads never touch vault.cofferak, only writes
# do (fsync'd, ADR 0010), so write latency depends on your disk.
#
# Usage: ./scripts/bench.sh [requests]
set -euo pipefail
# Unattended run: hosts created here must not ask for Touch ID (macOS).
export COFFERAK_NO_USER_PRESENCE=1

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
REQUESTS="${1:-20000}"
WORKDIR="$(mktemp -d)"
SOCKET="$WORKDIR/cofferakd.sock"
TLS_ADDR="127.0.0.1:18944"
SERVER_NAME="cofferak-bench"
DAEMON_PID=""

cleanup() {
  if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

newkey() { openssl ecparam -name secp384r1 -genkey -noout -out "$1" 2>/dev/null; }
sign() { # <name> <cn> [extfile]
  newkey "$WORKDIR/$1.key"
  openssl req -new -sha384 -key "$WORKDIR/$1.key" -subj "/CN=$2" -out "$WORKDIR/$1.csr" 2>/dev/null
  openssl x509 -req -sha384 -in "$WORKDIR/$1.csr" -CA "$WORKDIR/ca.pem" -CAkey "$WORKDIR/ca.key" \
    -CAcreateserial -days 1 ${3:+-extfile "$3"} -out "$WORKDIR/$1.pem" 2>/dev/null
}
newkey "$WORKDIR/ca.key"
openssl req -x509 -new -sha384 -key "$WORKDIR/ca.key" -days 1 -subj "/CN=cofferak-bench-ca" \
  -out "$WORKDIR/ca.pem" 2>/dev/null
printf 'subjectAltName=DNS:%s\n' "$SERVER_NAME" > "$WORKDIR/ext.cnf"
sign server "$SERVER_NAME" "$WORKDIR/ext.cnf"
sign client sdk-smoke-service   # named after the service its token belongs to (ADR 0017)

cargo build --release --quiet -p cofferak-core --example crypto_bench
cargo build --release --quiet -p cofferakd --example dev-daemon
cargo build --release --quiet -p cofferak-sdk --example bench

echo "== machine =="
uname -sm
if [[ "$(uname -s)" == "Darwin" ]]; then sysctl -n machdep.cpu.brand_string; else grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //'; fi
echo

echo "== crypto primitives =="
"$REPO_ROOT/target/release/examples/crypto_bench"
echo

TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
COFFERAK_SOCKET="$SOCKET" COFFERAK_TOKEN_SECRET_HEX="$TOKEN" COFFERAK_TOKEN_PREFIX="bench" \
COFFERAK_TLS_ADDR="$TLS_ADDR" COFFERAK_TLS_CERT="$WORKDIR/server.pem" COFFERAK_TLS_KEY="$WORKDIR/server.key" \
COFFERAK_TLS_CLIENT_CA="$WORKDIR/ca.pem" COFFERAK_TLS_MAX_CONNECTIONS=1024 \
  "$REPO_ROOT/target/release/examples/dev-daemon" >/dev/null &
DAEMON_PID=$!
for _ in $(seq 1 50); do [[ -S "$SOCKET" ]] && break; sleep 0.1; done
sleep 0.3

BENCH="$REPO_ROOT/target/release/examples/bench"
export COFFERAK_TOKEN="$TOKEN"

echo "== end to end: get =="
COFFERAK_SOCKET="$SOCKET" "$BENCH" bench/unix "$REQUESTS" 1
COFFERAK_SOCKET="$SOCKET" "$BENCH" bench/unix "$REQUESTS" 8

export COFFERAK_TLS_ADDR="$TLS_ADDR" COFFERAK_TLS_SERVER_NAME="$SERVER_NAME" \
  COFFERAK_TLS_CA="$WORKDIR/ca.pem" COFFERAK_TLS_CLIENT_CERT="$WORKDIR/client.pem" \
  COFFERAK_TLS_CLIENT_KEY="$WORKDIR/client.key"
TLS_REQUESTS=$(( REQUESTS / 10 ))
"$BENCH" bench/tls "$TLS_REQUESTS" 1
"$BENCH" bench/tls "$TLS_REQUESTS" 8
