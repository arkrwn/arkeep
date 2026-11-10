#!/usr/bin/env bash
# Proves server mode (ADR 0008) for real: generates a real self-signed
# CA + server certificate with openssl, starts mikavtd/examples/
# dev-daemon.rs listening on both the Unix socket AND TLS/TCP, then runs
# the Rust SDK's TLS smoke test against the real TLS listener over a
# real TLS handshake. Not a mocked test — if this script passes, server
# mode actually works.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
WORKDIR="$(mktemp -d)"
SOCKET="$WORKDIR/mikavtd.sock"
TLS_PORT=18943
TLS_ADDR="127.0.0.1:$TLS_PORT"
SERVER_NAME="mikavt-smoke-test"
DAEMON_PID=""

cleanup() {
  if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "== generating a self-signed CA + server cert for $SERVER_NAME =="
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=mikavt-smoke-ca" \
  -keyout "$WORKDIR/ca.key" -out "$WORKDIR/ca.pem" 2>/dev/null

openssl req -newkey rsa:2048 -nodes \
  -subj "/CN=$SERVER_NAME" \
  -keyout "$WORKDIR/server.key" -out "$WORKDIR/server.csr" 2>/dev/null

cat > "$WORKDIR/server-ext.cnf" <<EOF
subjectAltName=DNS:$SERVER_NAME
EOF

openssl x509 -req -in "$WORKDIR/server.csr" \
  -CA "$WORKDIR/ca.pem" -CAkey "$WORKDIR/ca.key" -CAcreateserial \
  -days 1 -extfile "$WORKDIR/server-ext.cnf" \
  -out "$WORKDIR/server.pem" 2>/dev/null

echo "== building workspace (release) =="
cargo build --workspace --release --examples

TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
DEV_DAEMON="$REPO_ROOT/target/release/examples/dev-daemon"

echo "== starting the dev-only daemon with server mode (TLS) enabled =="
MIKAVT_SOCKET="$SOCKET" \
MIKAVT_TOKEN_SECRET_HEX="$TOKEN" \
MIKAVT_TOKEN_PREFIX="sdk-smoke" \
MIKAVT_TLS_ADDR="$TLS_ADDR" \
MIKAVT_TLS_CERT="$WORKDIR/server.pem" \
MIKAVT_TLS_KEY="$WORKDIR/server.key" \
  "$DEV_DAEMON" &
DAEMON_PID=$!

for _ in $(seq 1 50); do
  [[ -S "$SOCKET" ]] && break
  sleep 0.1
done
if [[ ! -S "$SOCKET" ]]; then
  echo "daemon did not create its Unix socket in time" >&2
  exit 1
fi
# The TLS listener logs "listening on ..." right after binding; give it
# a moment too (it's a separate thread started slightly after the Unix
# socket in main()/dev-daemon.rs).
sleep 0.3

echo "== rust SDK TLS smoke test (server mode) =="
MIKAVT_TLS_ADDR="$TLS_ADDR" \
MIKAVT_TLS_SERVER_NAME="$SERVER_NAME" \
MIKAVT_TLS_CA="$WORKDIR/ca.pem" \
MIKAVT_TOKEN="$TOKEN" \
  cargo run --release --example smoke_tls -p mikavt-sdk -- "sdk-smoke/rust-tls" "other/denied"

kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""

echo "== generating a client cert signed by the same CA, for mutual TLS =="
openssl req -newkey rsa:2048 -nodes \
  -subj "/CN=mikavt-smoke-client" \
  -keyout "$WORKDIR/client.key" -out "$WORKDIR/client.csr" 2>/dev/null
openssl x509 -req -in "$WORKDIR/client.csr" \
  -CA "$WORKDIR/ca.pem" -CAkey "$WORKDIR/ca.key" -CAcreateserial \
  -days 1 -out "$WORKDIR/client.pem" 2>/dev/null

echo "== starting the dev-only daemon again, this time requiring client certs (mTLS) =="
MIKAVT_SOCKET="$SOCKET" \
MIKAVT_TOKEN_SECRET_HEX="$TOKEN" \
MIKAVT_TOKEN_PREFIX="sdk-smoke" \
MIKAVT_TLS_ADDR="$TLS_ADDR" \
MIKAVT_TLS_CERT="$WORKDIR/server.pem" \
MIKAVT_TLS_KEY="$WORKDIR/server.key" \
MIKAVT_TLS_CLIENT_CA="$WORKDIR/ca.pem" \
  "$DEV_DAEMON" &
DAEMON_PID=$!
for _ in $(seq 1 50); do
  [[ -S "$SOCKET" ]] && break
  sleep 0.1
done
sleep 0.3

echo "== mTLS: connecting WITHOUT a client cert must fail the handshake =="
if MIKAVT_TLS_ADDR="$TLS_ADDR" \
   MIKAVT_TLS_SERVER_NAME="$SERVER_NAME" \
   MIKAVT_TLS_CA="$WORKDIR/ca.pem" \
   MIKAVT_TOKEN="$TOKEN" \
   cargo run --release --example smoke_tls -p mikavt-sdk -- "sdk-smoke/rust-tls-notls" "other/denied" 2>/tmp/mikavt-mtls-noclient.log; then
  echo "expected the no-client-cert connection to FAIL against an mTLS-only server, but it succeeded" >&2
  cat /tmp/mikavt-mtls-noclient.log >&2
  exit 1
fi
echo "   (correctly rejected, as expected)"

echo "== mTLS: connecting WITH the matching client cert must succeed =="
MIKAVT_TLS_ADDR="$TLS_ADDR" \
MIKAVT_TLS_SERVER_NAME="$SERVER_NAME" \
MIKAVT_TLS_CA="$WORKDIR/ca.pem" \
MIKAVT_TLS_CLIENT_CERT="$WORKDIR/client.pem" \
MIKAVT_TLS_CLIENT_KEY="$WORKDIR/client.key" \
MIKAVT_TOKEN="$TOKEN" \
  cargo run --release --example smoke_tls -p mikavt-sdk -- "sdk-smoke/rust-mtls" "other/denied"

echo "== server mode (TLS + mTLS) smoke test passed =="
