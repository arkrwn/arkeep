#!/usr/bin/env bash
# End-to-end SDK smoke test: proves each language SDK's wire-protocol
# client code works against a real `Daemon` serving a real Unix socket.
#
# Two modes, selected by $MIKAVT_SMOKE_MODE:
#
#   full   (default on Linux CI): builds and runs the REAL `mikavtd` +
#           `mikavt` CLI binaries end to end — real vault bootstrap, real
#           HostSeal (systemd-creds), real enrolled service token loaded
#           from the real vault file. This is the authoritative proof.
#
#   dev    (default on macOS / anywhere real HostSeal cross-process
#           access isn't available — see docs/PROGRESS.md's "Known
#           gaps" entry on macOS Keychain's per-creating-process ACL):
#           runs `mikavtd/examples/dev-daemon.rs`, an in-memory daemon
#           with one pre-provisioned token and no disk persistence or
#           sealing involved. This proves the SDKs' protocol
#           implementations are correct against a real socket-serving
#           daemon; it does not exercise the real CLI-bootstrap or
#           HostSeal path (those are proven separately — see
#           mikavt-core/tests/seal_{linux,macos}.rs and the "full" mode
#           above, which runs for real in CI on ubuntu-latest).
#
# Used both locally and by .github/workflows/ci.yml's sdk-smoke job —
# this script is the single source of truth for "the SDKs actually
# work," not a claim in a doc.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
WORKDIR="$(mktemp -d)"
SOCKET="$WORKDIR/mikavtd.sock"
DAEMON_PID=""
MODE="${MIKAVT_SMOKE_MODE:-}"

if [[ -z "$MODE" ]]; then
  if [[ "$(uname -s)" == "Linux" ]] && command -v systemd-creds >/dev/null 2>&1; then
    MODE="full"
  else
    MODE="dev"
  fi
fi

cleanup() {
  if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "== mode: $MODE =="
echo "== building workspace (release) =="
cargo build --workspace --release

if [[ "$MODE" == "full" ]]; then
  DATA_DIR="$WORKDIR/data"
  HOST_ID="sdk-smoke-host"
  SERVICE_ID="sdk-smoke-service"
  MIKAVT="$REPO_ROOT/target/release/mikavt"
  MIKAVTD="$REPO_ROOT/target/release/mikavtd"

  echo "== bootstrapping a real throwaway vault in $DATA_DIR =="
  mkdir -p "$DATA_DIR"
  "$MIKAVT" init --root --data-dir "$DATA_DIR"
  "$MIKAVT" init --host "$HOST_ID" --data-dir "$DATA_DIR"

  echo "== enrolling a real service '$SERVICE_ID' scoped to sdk-smoke =="
  ENROLL_OUTPUT="$("$MIKAVT" enroll-service "$SERVICE_ID" --paths "sdk-smoke" --perm rw --data-dir "$DATA_DIR")"
  TOKEN="$(echo "$ENROLL_OUTPUT" | grep -E '^[0-9a-f]{64}$')"
  if [[ -z "$TOKEN" ]]; then
    echo "failed to parse the enrolled service's token from:" >&2
    echo "$ENROLL_OUTPUT" >&2
    exit 1
  fi

  echo "== starting the real mikavtd =="
  MIKAVT_DATA_DIR="$DATA_DIR" MIKAVT_SOCKET="$SOCKET" MIKAVT_HOST_ID="$HOST_ID" "$MIKAVTD" &
  DAEMON_PID=$!
else
  TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  DEV_DAEMON="$REPO_ROOT/target/release/examples/dev-daemon"
  if [[ ! -x "$DEV_DAEMON" ]]; then
    cargo build --release --example dev-daemon -p mikavtd
  fi
  echo "== starting the dev-only in-memory daemon (see script header) =="
  MIKAVT_SOCKET="$SOCKET" MIKAVT_TOKEN_SECRET_HEX="$TOKEN" MIKAVT_TOKEN_PREFIX="sdk-smoke" "$DEV_DAEMON" &
  DAEMON_PID=$!
fi

for _ in $(seq 1 50); do
  [[ -S "$SOCKET" ]] && break
  sleep 0.1
done
if [[ ! -S "$SOCKET" ]]; then
  echo "daemon did not create its socket in time" >&2
  exit 1
fi

export MIKAVT_SOCKET="$SOCKET"
export MIKAVT_TOKEN="$TOKEN"
FAILED=0

echo "== rust SDK smoke test =="
if ! cargo run --release --example smoke -p mikavt-sdk -- "sdk-smoke/rust" "other/denied"; then
  echo "rust SDK smoke test FAILED" >&2
  FAILED=1
fi

echo "== go SDK smoke test =="
if ! (cd sdk/go/mikavt && go run ./examples/smoke "sdk-smoke/go" "other/denied"); then
  echo "go SDK smoke test FAILED" >&2
  FAILED=1
fi

echo "== python SDK smoke test =="
if ! python3 sdk/python/mikavt_sdk/examples/smoke.py "sdk-smoke/python" "other/denied"; then
  echo "python SDK smoke test FAILED" >&2
  FAILED=1
fi

echo "== javascript SDK smoke test (compiled TypeScript output) =="
(cd sdk/javascript/mikavt-sdk && npm install --no-audit --no-fund --silent && npm run build --silent)
if ! node sdk/javascript/mikavt-sdk/examples/smoke.js "sdk-smoke/javascript" "other/denied"; then
  echo "javascript SDK smoke test FAILED" >&2
  FAILED=1
fi

if [[ "$FAILED" -ne 0 ]]; then
  echo "== one or more SDK smoke tests FAILED (mode: $MODE) ==" >&2
  exit 1
fi
echo "== all SDK smoke tests passed (mode: $MODE) =="
