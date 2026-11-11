#!/usr/bin/env bash
# Runs the README "Quickstart" commands end to end (non-interactively) so
# the documented steps can't silently rot. Same commands, same order, same
# Linux/macOS split as README.md; only the hidden `read -rs` prompt is
# replaced by a pipe, and names are suffixed so it never touches a real
# vault. Used by CI on ubuntu-latest and macos-latest.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --release --quiet
export PATH="$PWD/target/release:$PATH"
WORK="$(mktemp -d /tmp/cfk-qs.XXXX)"
export COFFERAK_DATA_DIR="$WORK/vault"
export COFFERAK_SOCKET="$COFFERAK_DATA_DIR/cofferakd.sock"
HOST="qs-$$"
UNIT="cofferak-qs-$$"
OS="$(uname -s)"
DPID=""

cleanup() {
  if [[ "$OS" == "Linux" ]]; then sudo systemctl stop "$UNIT" 2>/dev/null || true; fi
  [[ -n "$DPID" ]] && kill "$DPID" 2>/dev/null || true
  if [[ "$OS" == "Darwin" ]]; then security delete-generic-password -s cofferak -a "$HOST" >/dev/null 2>&1 || true; fi
  sudo -n rm -rf "$WORK" 2>/dev/null || rm -rf "$WORK"
}
trap cleanup EXIT

step() { echo "== $*"; }

step "1. set up"
mkdir -p "$COFFERAK_DATA_DIR" && chmod 700 "$COFFERAK_DATA_DIR"

step "2. create the vault, enroll this machine and an app"
if [[ "$OS" == "Linux" ]]; then ADMIN="sudo env COFFERAK_DATA_DIR=$COFFERAK_DATA_DIR $(command -v cofferak)"; else ADMIN=cofferak; fi
ROOT_OUT="$($ADMIN init --root)"
grep -q -- "-----BEGIN COFFERAK ROOT PRIVATE KEY-----" <<<"$ROOT_OUT"; unset ROOT_OUT
$ADMIN init --host "$HOST"
TOKEN="$($ADMIN enroll-service myapp --paths myapp --perm rw | grep -E '^[0-9a-f]{64}$')"
[[ -n "$TOKEN" ]]

step "3. start the daemon"
if [[ "$OS" == "Linux" ]]; then
  sudo systemd-run --unit="$UNIT" --uid="$(id -u)" --gid="$(id -g)" \
    -p "LoadCredentialEncrypted=cofferak-$HOST:$COFFERAK_DATA_DIR/hosts/$HOST.seal" \
    --setenv=COFFERAK_DATA_DIR="$COFFERAK_DATA_DIR" --setenv=COFFERAK_SOCKET="$COFFERAK_SOCKET" \
    --setenv=COFFERAK_HOST_ID="$HOST" "$(command -v cofferak)" daemon
else
  cofferak daemon >"$WORK/daemon.log" 2>&1 &
  DPID=$!
fi
for _ in $(seq 1 100); do [[ -S "$COFFERAK_SOCKET" ]] && break; sleep 0.1; done
[[ -S "$COFFERAK_SOCKET" ]] || { echo "daemon did not start" >&2; [[ "$OS" == "Linux" ]] && sudo journalctl -u "$UNIT" -n 30 >&2; cat "$WORK/daemon.log" 2>/dev/null >&2; exit 1; }

step "4. store and read secrets"
export COFFERAK_TOKEN="$TOKEN"
printf 'p@ss w0rd' | cofferak set myapp/DB_PASSWORD --stdin
[[ "$(cofferak get myapp/DB_PASSWORD)" == "p@ss w0rd" ]]
ssh-keygen -q -t ed25519 -N '' -C qs -f "$WORK/id_test"
cofferak set myapp/ssh/id_ed25519 --from-file "$WORK/id_test"
cmp <(cofferak get myapp/ssh/id_ed25519) "$WORK/id_test"
cofferak get myapp/ssh/id_ed25519 -o "$WORK/id_back" && cmp "$WORK/id_test" "$WORK/id_back"
[[ "$(cofferak list myapp | wc -l | tr -d ' ')" == "2" ]]
if cofferak get other/thing 2>/dev/null; then echo "expected denial" >&2; exit 1; fi

step "5. use a secret without a .env file"
[[ "$(DB_PASSWORD="$(cofferak get myapp/DB_PASSWORD)" sh -c 'printf %s "$DB_PASSWORD"')" == "p@ss w0rd" ]]

echo "== README quickstart: all steps passed ($OS)"
