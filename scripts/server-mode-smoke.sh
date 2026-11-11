#!/usr/bin/env bash
# Proves server mode (ADR 0008) for real, for every SDK that implements
# it: generates a real self-signed CA + server certificate with
# openssl, starts arkeepd/examples/dev-daemon.rs listening on both the
# Unix socket AND TLS/TCP, then runs each SDK's TLS smoke test against
# the real TLS listener over a real TLS handshake — including a battery
# of adversarial cases (wrong hostname, no client cert, a client cert
# from an untrusted CA) that must each FAIL, not just the happy path
# that must succeed. Not a mocked test — if this script passes, server
# mode actually works, for every language it claims to support.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
WORKDIR="$(mktemp -d)"
SOCKET="$WORKDIR/arkeepd.sock"
TLS_PORT=18943
TLS_ADDR="127.0.0.1:$TLS_PORT"
SERVER_NAME="arkeep-smoke-test"
DAEMON_PID=""

# Languages whose SDK supports the TLS/TCP transport today (ADR 0008 /
# docs/PROGRESS.md). Add a language here only once its SDK has a real
# `connect_tls`-equivalent AND an `examples/smoke_tls.*` this script can
# run — never add one "to be implemented," per ADR 0005.
TLS_LANGS=(rust go python javascript)

cleanup() {
  if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

# Runs one language's TLS smoke example with the given TLS parameters.
# Every SDK reads the same env var names (ARKEEP_TLS_ADDR,
# ARKEEP_TLS_SERVER_NAME, ARKEEP_TLS_CA, ARKEEP_TLS_CLIENT_CERT,
# ARKEEP_TLS_CLIENT_KEY, ARKEEP_TOKEN) — that consistency is what lets
# this one function drive all four without per-language special-casing
# beyond which binary/interpreter actually runs.
run_tls_smoke() {
  local lang="$1" allowed="$2" denied="$3" server_name="$4" client_cert="${5:-}" client_key="${6:-}"
  export ARKEEP_TLS_ADDR="$TLS_ADDR"
  export ARKEEP_TLS_SERVER_NAME="$server_name"
  export ARKEEP_TLS_CA="$WORKDIR/ca.pem"
  export ARKEEP_TLS_CLIENT_CERT="$client_cert"
  export ARKEEP_TLS_CLIENT_KEY="$client_key"
  export ARKEEP_TOKEN="$TOKEN"
  case "$lang" in
    rust) cargo run --release --example smoke_tls -p arkeep-sdk -- "$allowed" "$denied" ;;
    go) (cd sdk/go/arkeep && go run ./examples/smoke_tls "$allowed" "$denied") ;;
    python) python3 sdk/python/arkeep_sdk/examples/smoke_tls.py "$allowed" "$denied" ;;
    javascript) node sdk/javascript/arkeep-sdk/examples/smoke_tls.js "$allowed" "$denied" ;;
    *) echo "run_tls_smoke: unknown language '$lang'" >&2; return 1 ;;
  esac
}

# Runs run_tls_smoke and requires it to FAIL (used for every adversarial
# case below) — fails this script loudly, with the captured output, if
# the smoke test unexpectedly succeeded.
expect_tls_rejected() {
  local description="$1"; shift
  local lang="$1" log
  log="$(mktemp)"
  if run_tls_smoke "$@" >"$log" 2>&1; then
    echo "expected $description to be REJECTED, but it succeeded:" >&2
    cat "$log" >&2
    rm -f "$log"
    exit 1
  fi
  rm -f "$log"
  echo "   ([$lang] $description: correctly rejected)"
}

echo "== generating a self-signed CA + server cert for $SERVER_NAME =="
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=arkeep-smoke-ca" \
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
ARKEEP_SOCKET="$SOCKET" \
ARKEEP_TOKEN_SECRET_HEX="$TOKEN" \
ARKEEP_TOKEN_PREFIX="sdk-smoke" \
ARKEEP_TLS_ADDR="$TLS_ADDR" \
ARKEEP_TLS_CERT="$WORKDIR/server.pem" \
ARKEEP_TLS_KEY="$WORKDIR/server.key" \
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

for lang in "${TLS_LANGS[@]}"; do
  echo "== [$lang] TLS smoke test (server mode) =="
  run_tls_smoke "$lang" "sdk-smoke/$lang-tls" "other/denied" "$SERVER_NAME"

  echo "== [$lang] hostname verification: wrong expected server name must fail =="
  # Defends against a MITM presenting a different (even CA-signed) cert
  # for a different name. The real server cert's CN/SAN is $SERVER_NAME.
  expect_tls_rejected "a hostname mismatch" \
    "$lang" "sdk-smoke/$lang-tls-wrongname" "other/denied" "not-$SERVER_NAME"
done

kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""

echo "== generating a client cert signed by the same CA, for mutual TLS =="
openssl req -newkey rsa:2048 -nodes \
  -subj "/CN=arkeep-smoke-client" \
  -keyout "$WORKDIR/client.key" -out "$WORKDIR/client.csr" 2>/dev/null
openssl x509 -req -in "$WORKDIR/client.csr" \
  -CA "$WORKDIR/ca.pem" -CAkey "$WORKDIR/ca.key" -CAcreateserial \
  -days 1 -out "$WORKDIR/client.pem" 2>/dev/null

echo "== generating a client cert signed by a DIFFERENT (rogue) CA =="
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=rogue-ca" \
  -keyout "$WORKDIR/rogue-ca.key" -out "$WORKDIR/rogue-ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes \
  -subj "/CN=rogue-client" \
  -keyout "$WORKDIR/rogue-client.key" -out "$WORKDIR/rogue-client.csr" 2>/dev/null
openssl x509 -req -in "$WORKDIR/rogue-client.csr" \
  -CA "$WORKDIR/rogue-ca.pem" -CAkey "$WORKDIR/rogue-ca.key" -CAcreateserial \
  -days 1 -out "$WORKDIR/rogue-client.pem" 2>/dev/null

echo "== starting the dev-only daemon again, this time requiring client certs (mTLS) =="
ARKEEP_SOCKET="$SOCKET" \
ARKEEP_TOKEN_SECRET_HEX="$TOKEN" \
ARKEEP_TOKEN_PREFIX="sdk-smoke" \
ARKEEP_TLS_ADDR="$TLS_ADDR" \
ARKEEP_TLS_CERT="$WORKDIR/server.pem" \
ARKEEP_TLS_KEY="$WORKDIR/server.key" \
ARKEEP_TLS_CLIENT_CA="$WORKDIR/ca.pem" \
  "$DEV_DAEMON" &
DAEMON_PID=$!
for _ in $(seq 1 50); do
  [[ -S "$SOCKET" ]] && break
  sleep 0.1
done
sleep 0.3

for lang in "${TLS_LANGS[@]}"; do
  echo "== [$lang] mTLS: connecting WITHOUT a client cert must fail =="
  expect_tls_rejected "a connection with no client cert against an mTLS-only server" \
    "$lang" "sdk-smoke/$lang-tls-notls" "other/denied" "$SERVER_NAME"

  echo "== [$lang] mTLS: connecting WITH a cert from a DIFFERENT (rogue) CA must fail =="
  expect_tls_rejected "a client cert signed by an untrusted CA" \
    "$lang" "sdk-smoke/$lang-tls-rogue" "other/denied" "$SERVER_NAME" \
    "$WORKDIR/rogue-client.pem" "$WORKDIR/rogue-client.key"

  echo "== [$lang] mTLS: connecting WITH the matching (trusted-CA-signed) client cert must succeed =="
  run_tls_smoke "$lang" "sdk-smoke/$lang-mtls" "other/denied" "$SERVER_NAME" \
    "$WORKDIR/client.pem" "$WORKDIR/client.key"
done

echo "== server mode (TLS + mTLS) smoke test passed for: ${TLS_LANGS[*]} =="
