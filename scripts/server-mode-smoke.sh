#!/usr/bin/env bash
# Proves server mode (ADR 0008, hardened by ADR 0011) for real, for every
# SDK that implements it: generates a real ECDSA P-384 CA, server and
# client certificates with openssl, starts cofferakd/examples/dev-daemon.rs
# listening on both the Unix socket AND TLS/TCP, then runs each SDK's TLS
# smoke test over a real TLS handshake, plus adversarial cases that must
# each FAIL:
#
#   - the daemon refuses to start server mode without a client CA (mTLS
#     is mandatory);
#   - a client with no certificate, a certificate from an untrusted CA,
#     or the wrong expected hostname is rejected, in every SDK;
#   - (where the local openssl is OpenSSL, e.g. Linux CI) TLS 1.2 and the
#     AES-128 cipher suite are refused;
#   - the Rust SDK reports the negotiated parameters, and they must be
#     TLS 1.3 / AES-256-GCM-SHA384 / MLKEM1024 (post-quantum, CNSA 2.0).
#
# Not a mocked test: if this passes, server mode works as documented.
set -euo pipefail
# Unattended run: hosts created here must not ask for Touch ID (macOS).
export COFFERAK_NO_USER_PRESENCE=1

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
WORKDIR="$(mktemp -d)"
SOCKET="$WORKDIR/cofferakd.sock"
TLS_PORT=18943
TLS_ADDR="127.0.0.1:$TLS_PORT"
SERVER_NAME="cofferak-smoke-test"
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
# Every SDK reads the same env var names (COFFERAK_TLS_ADDR,
# COFFERAK_TLS_SERVER_NAME, COFFERAK_TLS_CA, COFFERAK_TLS_CLIENT_CERT,
# COFFERAK_TLS_CLIENT_KEY, COFFERAK_TOKEN) — that consistency is what lets
# this one function drive all four without per-language special-casing
# beyond which binary/interpreter actually runs.
run_tls_smoke() {
  local lang="$1" allowed="$2" denied="$3" server_name="$4" client_cert="${5:-}" client_key="${6:-}"
  export COFFERAK_TLS_ADDR="$TLS_ADDR"
  export COFFERAK_TLS_SERVER_NAME="$server_name"
  export COFFERAK_TLS_CA="$WORKDIR/ca.pem"
  export COFFERAK_TLS_CLIENT_CERT="$client_cert"
  export COFFERAK_TLS_CLIENT_KEY="$client_key"
  export COFFERAK_TOKEN="$TOKEN"
  case "$lang" in
    rust) cargo run --release --example smoke_tls -p cofferak-sdk -- "$allowed" "$denied" ;;
    go) (cd sdk/go/cofferak && go run ./examples/smoke_tls "$allowed" "$denied") ;;
    python) python3 sdk/python/cofferak_sdk/examples/smoke_tls.py "$allowed" "$denied" ;;
    javascript) node sdk/javascript/cofferak-sdk/examples/smoke_tls.js "$allowed" "$denied" ;;
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

# ECDSA P-384 keys and SHA-384 signatures everywhere (CNSA). `ecparam
# -genkey` works with both OpenSSL and LibreSSL (macOS).
newkey() { openssl ecparam -name secp384r1 -genkey -noout -out "$1" 2>/dev/null; }

echo "== generating a P-384 CA, server cert for $SERVER_NAME, and client certs =="
newkey "$WORKDIR/ca.key"
openssl req -x509 -new -sha384 -key "$WORKDIR/ca.key" -days 1 \
  -subj "/CN=cofferak-smoke-ca" -out "$WORKDIR/ca.pem" 2>/dev/null

newkey "$WORKDIR/server.key"
openssl req -new -sha384 -key "$WORKDIR/server.key" -subj "/CN=$SERVER_NAME" \
  -out "$WORKDIR/server.csr" 2>/dev/null
printf 'subjectAltName=DNS:%s\n' "$SERVER_NAME" > "$WORKDIR/server-ext.cnf"
openssl x509 -req -sha384 -in "$WORKDIR/server.csr" \
  -CA "$WORKDIR/ca.pem" -CAkey "$WORKDIR/ca.key" -CAcreateserial \
  -days 1 -extfile "$WORKDIR/server-ext.cnf" -out "$WORKDIR/server.pem" 2>/dev/null

# The client certificate is named after the service its token belongs to:
# the daemon only accepts a token together with its own service's
# certificate (ADR 0017).
make_client_cert() { # <name> <common-name>
  newkey "$WORKDIR/$1.key"
  openssl req -new -sha384 -key "$WORKDIR/$1.key" -subj "/CN=$2" \
    -out "$WORKDIR/$1.csr" 2>/dev/null
  openssl x509 -req -sha384 -in "$WORKDIR/$1.csr" \
    -CA "$WORKDIR/ca.pem" -CAkey "$WORKDIR/ca.key" -CAcreateserial \
    -days 1 -out "$WORKDIR/$1.pem" 2>/dev/null
}
make_client_cert client sdk-smoke-service
make_client_cert other-client some-other-service
make_client_cert revoked-client sdk-smoke-service

# Revoke one of them and publish a CRL.
: > "$WORKDIR/index.txt"
echo 01 > "$WORKDIR/crlnumber"
cat > "$WORKDIR/ca.cnf" <<CNF
[ ca ]
default_ca = CA_default
[ CA_default ]
database = $WORKDIR/index.txt
crlnumber = $WORKDIR/crlnumber
default_md = sha384
default_crl_days = 1
CNF
openssl ca -config "$WORKDIR/ca.cnf" -keyfile "$WORKDIR/ca.key" -cert "$WORKDIR/ca.pem" \
  -revoke "$WORKDIR/revoked-client.pem" >/dev/null 2>&1
openssl ca -config "$WORKDIR/ca.cnf" -keyfile "$WORKDIR/ca.key" -cert "$WORKDIR/ca.pem" \
  -gencrl -out "$WORKDIR/crl.pem" >/dev/null 2>&1

# A client cert signed by a DIFFERENT (rogue) CA: must be refused.
newkey "$WORKDIR/rogue-ca.key"
openssl req -x509 -new -sha384 -key "$WORKDIR/rogue-ca.key" -days 1 \
  -subj "/CN=rogue-ca" -out "$WORKDIR/rogue-ca.pem" 2>/dev/null
newkey "$WORKDIR/rogue-client.key"
openssl req -new -sha384 -key "$WORKDIR/rogue-client.key" -subj "/CN=rogue-client" \
  -out "$WORKDIR/rogue-client.csr" 2>/dev/null
openssl x509 -req -sha384 -in "$WORKDIR/rogue-client.csr" \
  -CA "$WORKDIR/rogue-ca.pem" -CAkey "$WORKDIR/rogue-ca.key" -CAcreateserial \
  -days 1 -out "$WORKDIR/rogue-client.pem" 2>/dev/null

echo "== building workspace (release) =="
cargo build --workspace --release --examples

TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
DEV_DAEMON="$REPO_ROOT/target/release/examples/dev-daemon"

echo "== mTLS is mandatory: server mode without a client CA must refuse to start =="
# Portable "must exit on its own within 10s" (macOS has no `timeout`).
COFFERAK_SOCKET="$WORKDIR/no-ca.sock" COFFERAK_TOKEN_SECRET_HEX="$TOKEN" \
COFFERAK_TOKEN_PREFIX="sdk-smoke" COFFERAK_TLS_ADDR="$TLS_ADDR" \
COFFERAK_TLS_CERT="$WORKDIR/server.pem" COFFERAK_TLS_KEY="$WORKDIR/server.key" \
  "$DEV_DAEMON" >"$WORKDIR/no-ca.log" 2>&1 &
NO_CA_PID=$!
for _ in $(seq 1 100); do
  kill -0 "$NO_CA_PID" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "$NO_CA_PID" 2>/dev/null; then
  kill "$NO_CA_PID" 2>/dev/null || true
  echo "server mode kept running without COFFERAK_TLS_CLIENT_CA; it must refuse" >&2
  cat "$WORKDIR/no-ca.log" >&2
  exit 1
fi
if wait "$NO_CA_PID"; then
  echo "daemon exited successfully without COFFERAK_TLS_CLIENT_CA; it must fail" >&2
  cat "$WORKDIR/no-ca.log" >&2
  exit 1
fi
grep -q "COFFERAK_TLS_CLIENT_CA" "$WORKDIR/no-ca.log" || {
  echo "daemon exited, but not with the expected mTLS-required error:" >&2
  cat "$WORKDIR/no-ca.log" >&2
  exit 1
}
echo "   (correctly refused: $(grep -o 'server mode requires mutual TLS' "$WORKDIR/no-ca.log" | head -1))"

echo "== starting the dev-only daemon with server mode (TLS 1.3 + mandatory mTLS) =="
COFFERAK_SOCKET="$SOCKET" \
COFFERAK_TOKEN_SECRET_HEX="$TOKEN" \
COFFERAK_TOKEN_PREFIX="sdk-smoke" \
COFFERAK_TLS_ADDR="$TLS_ADDR" \
COFFERAK_TLS_CERT="$WORKDIR/server.pem" \
COFFERAK_TLS_KEY="$WORKDIR/server.key" \
COFFERAK_TLS_CLIENT_CA="$WORKDIR/ca.pem" \
COFFERAK_TLS_CRL="$WORKDIR/crl.pem" \
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
# The TLS listener binds on its own thread just after the Unix socket.
sleep 0.3

CLIENT=("$WORKDIR/client.pem" "$WORKDIR/client.key")

for lang in "${TLS_LANGS[@]}"; do
  echo "== [$lang] mTLS with a trusted client cert must succeed =="
  log="$(mktemp)"
  if ! run_tls_smoke "$lang" "sdk-smoke/$lang-mtls" "other/denied" "$SERVER_NAME" "${CLIENT[@]}" | tee "$log"; then
    echo "[$lang] TLS smoke test FAILED" >&2
    exit 1
  fi
  if [[ "$lang" == "rust" ]]; then
    # Both ends are rustls+AWS-LC here, so the strongest group must win.
    grep -q "negotiated: TLSv1_3 TLS13_AES_256_GCM_SHA384 MLKEM1024" "$log" || {
      echo "[rust] expected TLS 1.3 / AES-256-GCM-SHA384 / MLKEM1024, got:" >&2
      grep negotiated "$log" >&2 || true
      exit 1
    }
    echo "   ([rust] negotiated TLS 1.3, AES-256-GCM-SHA384, post-quantum ML-KEM-1024)"
  fi
  rm -f "$log"

  echo "== [$lang] wrong expected server name must fail =="
  expect_tls_rejected "a hostname mismatch" \
    "$lang" "sdk-smoke/$lang-wrongname" "other/denied" "not-$SERVER_NAME" "${CLIENT[@]}"

  echo "== [$lang] no client cert must fail =="
  expect_tls_rejected "a connection with no client cert" \
    "$lang" "sdk-smoke/$lang-nocert" "other/denied" "$SERVER_NAME"

  echo "== [$lang] a valid client cert for another service must fail =="
  expect_tls_rejected "a token used with another service's certificate" \
    "$lang" "sdk-smoke/$lang-othersvc" "other/denied" "$SERVER_NAME" \
    "$WORKDIR/other-client.pem" "$WORKDIR/other-client.key"

  echo "== [$lang] a revoked client cert must fail =="
  expect_tls_rejected "a revoked client certificate" \
    "$lang" "sdk-smoke/$lang-revoked" "other/denied" "$SERVER_NAME" \
    "$WORKDIR/revoked-client.pem" "$WORKDIR/revoked-client.key"

  echo "== [$lang] client cert from an untrusted CA must fail =="
  expect_tls_rejected "a client cert signed by an untrusted CA" \
    "$lang" "sdk-smoke/$lang-rogue" "other/denied" "$SERVER_NAME" \
    "$WORKDIR/rogue-client.pem" "$WORKDIR/rogue-client.key"
done

# Protocol/cipher downgrade checks need OpenSSL's s_client flags; macOS
# ships LibreSSL, so these run on Linux (CI) and skip elsewhere.
if openssl version | grep -q '^OpenSSL'; then
  s_client() {
    openssl s_client -connect "$TLS_ADDR" -servername "$SERVER_NAME" \
      -CAfile "$WORKDIR/ca.pem" -cert "$WORKDIR/client.pem" -key "$WORKDIR/client.key" \
      "$@" </dev/null 2>&1
  }
  echo "== downgrade: TLS 1.2 must be refused =="
  if s_client -tls1_2 | grep -q "^New, TLSv1.2"; then
    echo "server accepted TLS 1.2" >&2; exit 1
  fi
  echo "   (TLS 1.2: correctly refused)"
  echo "== downgrade: TLS 1.3 with only AES-128-GCM must be refused =="
  if s_client -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 | grep -q "^New, TLSv1.3"; then
    echo "server accepted TLS_AES_128_GCM_SHA256" >&2; exit 1
  fi
  echo "   (AES-128: correctly refused)"
  echo "== baseline: TLS 1.3 + AES-256-GCM-SHA384 with a client cert is accepted =="
  s_client -tls1_3 | grep -q "Cipher is TLS_AES_256_GCM_SHA384" || {
    echo "expected an accepted TLS_AES_256_GCM_SHA384 session" >&2
    s_client -tls1_3 | tail -20 >&2
    exit 1
  }
  echo "   (TLS 1.3 / AES-256-GCM-SHA384: accepted)"
else
  echo "== downgrade checks skipped: local openssl is $(openssl version) (they run in Linux CI) =="
fi

echo "== server mode (TLS 1.3 + mandatory mTLS + post-quantum) smoke test passed for: ${TLS_LANGS[*]} =="
