#!/usr/bin/env bash
# End-to-end SDK smoke test: proves each language SDK's wire-protocol
# client code works against a real `Daemon` serving a real Unix socket.
#
# Two modes, selected by $COFFERAK_SMOKE_MODE:
#
#   full   (default on Linux with systemd-creds, and on macOS): the REAL
#           `cofferak` CLI and daemon end to end, with real host-key
#           sealing, a real enrolled service token loaded from the real
#           vault file, all four SDKs, and a write proven to survive a
#           daemon restart (ADR 0010).
#           - Linux (needs passwordless sudo), laid out like production
#             (ADR 0009): admin commands run as root (systemd-creds), the
#             daemon runs as a NON-root transient systemd service that
#             receives its host key via LoadCredentialEncrypted=.
#           - macOS: the host key is sealed in the Keychain and the daemon
#             runs as `cofferak daemon`, the same binary that sealed it, so
#             the Keychain serves it without a prompt (ADR 0007). The test
#             Keychain item is deleted on exit.
#
#   dev    (anywhere else, or COFFERAK_SMOKE_MODE=dev): runs
#           `cofferakd/examples/dev-daemon.rs`, an in-memory daemon with one
#           pre-provisioned token and no persistence or sealing. Proves the
#           SDKs' protocol code, not the bootstrap/sealing path.
#
# Used both locally and by .github/workflows/ci.yml's sdk-smoke job -
# this script is the single source of truth for "the SDKs actually
# work," not a claim in a doc.
set -euo pipefail
# Unattended run: hosts created here must not ask for Touch ID (macOS).
export COFFERAK_NO_USER_PRESENCE=1

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
WORKDIR="$(mktemp -d)"
SOCKET="$WORKDIR/cofferakd.sock"
DAEMON_PID=""
MODE="${COFFERAK_SMOKE_MODE:-}"

OS="$(uname -s)"
if [[ -z "$MODE" ]]; then
  if [[ "$OS" == "Linux" ]] && command -v systemd-creds >/dev/null 2>&1; then
    MODE="full"
  elif [[ "$OS" == "Darwin" ]]; then
    MODE="full"
  else
    MODE="dev"
  fi
fi
KEYCHAIN_ITEM=""

UNIT=""

cleanup() {
  if [[ -n "$UNIT" ]]; then
    sudo systemctl stop "$UNIT" 2>/dev/null || true
  fi
  if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  if [[ -n "$KEYCHAIN_ITEM" ]]; then
    security delete-generic-password -s cofferak -a "$KEYCHAIN_ITEM" >/dev/null 2>&1 || true
    security delete-generic-password -s cofferak-anchor -a "$KEYCHAIN_ITEM" >/dev/null 2>&1 || true
  fi
  if [[ -n "$UNIT" ]]; then
    sudo rm -rf "$WORKDIR" 2>/dev/null || true
  else
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

wait_for_socket() {
  for _ in $(seq 1 100); do
    [[ -S "$SOCKET" ]] && return 0
    sleep 0.1
  done
  echo "daemon did not create its socket in time" >&2
  if [[ -n "$UNIT" ]]; then
    sudo journalctl -u "$UNIT" --no-pager -n 50 >&2 || true
  fi
  return 1
}

# Full mode only: run the real cofferakd exactly as production does on Linux
# (ADR 0009) - as an unprivileged user, in a systemd service whose
# LoadCredentialEncrypted= has systemd (as root) decrypt the sealed host key
# into $CREDENTIALS_DIRECTORY. The daemon never touches systemd-creds itself.
start_real_daemon() {
  rm -f "$SOCKET"
  sudo systemd-run --quiet --collect \
    --unit="$UNIT" \
    --uid="$(id -u)" --gid="$(id -g)" \
    -p "LoadCredentialEncrypted=cofferak-$HOST_ID:$DATA_DIR/hosts/$HOST_ID.seal" \
    -p LimitCORE=0 -p NoNewPrivileges=yes \
    --setenv=COFFERAK_DATA_DIR="$DATA_DIR" \
    --setenv=COFFERAK_SOCKET="$SOCKET" \
    --setenv=COFFERAK_HOST_ID="$HOST_ID" \
    "$COFFERAKD"
  wait_for_socket
}

echo "== mode: $MODE =="
echo "== building workspace (release) =="
cargo build --workspace --release

# macOS full mode: the real Keychain-sealed host key and `cofferak daemon`
# (the same binary that sealed the key, so no Keychain prompt, ADR 0007).
start_mac_daemon() {
  rm -f "$SOCKET"
  COFFERAK_DATA_DIR="$DATA_DIR" COFFERAK_SOCKET="$SOCKET" COFFERAK_HOST_ID="$HOST_ID" \
    "$COFFERAK" daemon >"$WORKDIR/daemon.log" 2>&1 &
  DAEMON_PID=$!
  wait_for_socket || { cat "$WORKDIR/daemon.log" >&2; return 1; }
}

if [[ "$MODE" == "full" && "$OS" == "Darwin" ]]; then
  DATA_DIR="$WORKDIR/data"
  HOST_ID="sdk-smoke-host-$$"
  KEYCHAIN_ITEM="$HOST_ID"
  COFFERAK="$REPO_ROOT/target/release/cofferak"
  echo "== bootstrapping a real throwaway vault in $DATA_DIR (macOS Keychain) =="
  "$COFFERAK" init --root --data-dir "$DATA_DIR" >/dev/null
  "$COFFERAK" init --host "$HOST_ID" --data-dir "$DATA_DIR"
  ENROLL_OUTPUT="$("$COFFERAK" enroll-service sdk-smoke-service --paths "sdk-smoke" --perm rw --data-dir "$DATA_DIR")"
  TOKEN="$(echo "$ENROLL_OUTPUT" | grep -E '^[0-9a-f]{64}$')"
  [[ -n "$TOKEN" ]] || { echo "failed to parse the enrolled service's token" >&2; exit 1; }
  echo "== starting the real daemon: cofferak daemon =="
  start_mac_daemon
elif [[ "$MODE" == "full" ]]; then
  DATA_DIR="$WORKDIR/data"
  HOST_ID="sdk-smoke-host"
  SERVICE_ID="sdk-smoke-service"
  COFFERAK="$REPO_ROOT/target/release/cofferak"
  COFFERAKD="$REPO_ROOT/target/release/cofferakd"

  UNIT="cofferak-sdk-smoke-$$"

  # Admin commands seal/unseal the host key, which on Linux needs root
  # (systemd-creds' host secret is root-only, ADR 0009). They hand the
  # files they create back to the data directory's owner afterwards.
  echo "== bootstrapping a real throwaway vault in $DATA_DIR (admin commands as root) =="
  mkdir -p "$DATA_DIR"
  chmod 0700 "$DATA_DIR"
  sudo "$COFFERAK" init --root --data-dir "$DATA_DIR"
  sudo "$COFFERAK" init --host "$HOST_ID" --data-dir "$DATA_DIR"

  echo "== enrolling a real service '$SERVICE_ID' scoped to sdk-smoke =="
  ENROLL_OUTPUT="$(sudo "$COFFERAK" enroll-service "$SERVICE_ID" --paths "sdk-smoke" --perm rw --data-dir "$DATA_DIR")"

  echo "== checking vault files are owned by the daemon's (non-root) user =="
  if find "$DATA_DIR" ! -user "$(id -u)" | grep -q .; then
    echo "files left owned by another user after admin commands:" >&2
    find "$DATA_DIR" ! -user "$(id -u)" -exec ls -ld {} + >&2
    exit 1
  fi
  TOKEN="$(echo "$ENROLL_OUTPUT" | grep -E '^[0-9a-f]{64}$')"
  if [[ -z "$TOKEN" ]]; then
    echo "failed to parse the enrolled service's token from:" >&2
    echo "$ENROLL_OUTPUT" >&2
    exit 1
  fi

  echo "== starting the real cofferakd as a non-root systemd service =="
  start_real_daemon
else
  TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  DEV_DAEMON="$REPO_ROOT/target/release/examples/dev-daemon"
  if [[ ! -x "$DEV_DAEMON" ]]; then
    cargo build --release --example dev-daemon -p cofferakd
  fi
  echo "== starting the dev-only in-memory daemon (see script header) =="
  COFFERAK_SOCKET="$SOCKET" COFFERAK_TOKEN_SECRET_HEX="$TOKEN" COFFERAK_TOKEN_PREFIX="sdk-smoke" "$DEV_DAEMON" &
  DAEMON_PID=$!
  wait_for_socket
fi

export COFFERAK_SOCKET="$SOCKET"
export COFFERAK_TOKEN="$TOKEN"
FAILED=0

echo "== rust SDK smoke test =="
if ! cargo run --release --example smoke -p cofferak-sdk -- "sdk-smoke/rust" "other/denied"; then
  echo "rust SDK smoke test FAILED" >&2
  FAILED=1
fi

echo "== go SDK smoke test =="
if ! (cd sdk/go/cofferak && go run ./examples/smoke "sdk-smoke/go" "other/denied"); then
  echo "go SDK smoke test FAILED" >&2
  FAILED=1
fi

echo "== python SDK smoke test =="
if ! python3 sdk/python/cofferak_sdk/examples/smoke.py "sdk-smoke/python" "other/denied"; then
  echo "python SDK smoke test FAILED" >&2
  FAILED=1
fi

echo "== javascript SDK smoke test (compiled TypeScript output) =="
(cd sdk/javascript/cofferak-sdk && npm install --no-audit --no-fund --silent && npm run build --silent)
if ! node sdk/javascript/cofferak-sdk/examples/smoke.js "sdk-smoke/javascript" "other/denied"; then
  echo "javascript SDK smoke test FAILED" >&2
  FAILED=1
fi

if [[ "$MODE" == "full" && "$FAILED" -eq 0 ]]; then
  # Durability (ADR 0010): a write acknowledged by the daemon must still be
  # there after the daemon restarts, read back from vault.cofferak on disk.
  echo "== durability: write, restart cofferakd, read back =="
  printf 'survives-restart' | "$COFFERAK" set "sdk-smoke/durable" --stdin >/dev/null
  if [[ "$OS" == "Darwin" ]]; then
    kill "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null || true
    start_mac_daemon
  else
    sudo systemctl stop "$UNIT"
    for _ in $(seq 1 50); do
      systemctl is-active --quiet "$UNIT" || break
      sleep 0.1
    done
    start_real_daemon
  fi
  GOT="$("$COFFERAK" get "sdk-smoke/durable")"
  if [[ "$GOT" != "survives-restart" ]]; then
    echo "durability check FAILED: expected 'survives-restart', got '$GOT'" >&2
    FAILED=1
  else
    echo "durability check passed"
  fi
fi

if [[ "$FAILED" -ne 0 ]]; then
  echo "== one or more SDK smoke tests FAILED (mode: $MODE) ==" >&2
  if [[ -n "$UNIT" ]]; then
    sudo journalctl -u "$UNIT" --no-pager -n 50 >&2 || true
  fi
  exit 1
fi
echo "== all SDK smoke tests passed (mode: $MODE) =="
