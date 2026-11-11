#!/usr/bin/env bash
# Runs the README "Quickstart" commands end to end (non-interactively) so
# the documented steps can't silently rot. Same commands, same order, same
# Linux/macOS split as README.md; only the hidden `read -rs` prompt is
# replaced by a pipe, and names are suffixed so it never touches a real
# vault. Used by CI on ubuntu-latest and macos-latest.
set -euo pipefail
# Unattended run: hosts created here must not ask for Touch ID (macOS).
export COFFERAK_NO_USER_PRESENCE=1

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
  if [[ "$OS" == "Darwin" ]]; then
    security delete-generic-password -s cofferak -a "$HOST" >/dev/null 2>&1 || true
    security delete-generic-password -s cofferak-anchor -a "$HOST" >/dev/null 2>&1 || true
    security delete-generic-password -s cofferak -a "qsb-$$" >/dev/null 2>&1 || true
    security delete-generic-password -s cofferak-anchor -a "qsb-$$" >/dev/null 2>&1 || true
  fi
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

step "6. import a .env file, run an app with it, export it again"
cat > "$WORK/app.env" <<'ENVEOF'
export DB_HOST=db.internal
DB_PASSWORD="p@ss \"q\" w0rd"
API_KEY=abc=123   # comment
ENVEOF
cofferak import-env "$WORK/app.env" --prefix myapp/env | tail -1
[[ "$(cofferak get myapp/env/DB_PASSWORD)" == 'p@ss "q" w0rd' ]]
[[ "$(cofferak run --prefix myapp/env -- sh -c 'printf "%s|%s|%s" "$DB_HOST" "$API_KEY" "${COFFERAK_TOKEN:-none}"')" == "db.internal|abc=123|none" ]]
cofferak export-env --prefix myapp/env -o "$WORK/out.env" >/dev/null
grep -q '^DB_PASSWORD="p@ss \\"q\\" w0rd"$' "$WORK/out.env"

step "7. export the vault to an encrypted bundle and import it back"
printf 'correct horse battery staple\n' > "$WORK/pass"
$ADMIN export -o "$WORK/backup.cfk" --passphrase-file "$WORK/pass"
if LC_ALL=C grep -a -q 'p@ss' "$WORK/backup.cfk"; then echo "plaintext in bundle" >&2; exit 1; fi
OUT="$($ADMIN import "$WORK/backup.cfk" --passphrase-file "$WORK/pass" --dry-run)"
grep -q "0 new, 0 replaced, 5 kept" <<<"$OUT"

step "8. coffer-to-coffer transfer with identities (no passphrase), both directions"
B_DIR="$WORK/vault-b"; B_HOST="qsb-$$"
mkdir -p "$B_DIR" && chmod 700 "$B_DIR"
if [[ "$OS" == "Linux" ]]; then ADMIN_B="sudo env COFFERAK_DATA_DIR=$B_DIR $(command -v cofferak)"; else ADMIN_B="env COFFERAK_DATA_DIR=$B_DIR cofferak"; fi
$ADMIN_B init --root >/dev/null
$ADMIN_B init --host "$B_HOST"
$ADMIN identity -o "$WORK/a.id" >/dev/null
$ADMIN_B identity -o "$WORK/b.id" >/dev/null
$ADMIN peer add b "$WORK/b.id" >/dev/null
$ADMIN_B peer add a "$WORK/a.id" >/dev/null
OUT="$($ADMIN export --to b --prefix myapp/env -o "$WORK/a2b.cfk")"
grep -q "for peer 'b'" <<<"$OUT"
OUT="$($ADMIN_B import "$WORK/a2b.cfk")"
grep -q "from peer 'a' (signature verified): secrets 3 new" <<<"$OUT"
$ADMIN_B export --to a -o "$WORK/b2a.cfk" >/dev/null
OUT="$($ADMIN import "$WORK/b2a.cfk")"
grep -q "from peer 'b' (signature verified): secrets 0 new, 0 replaced, 3 kept" <<<"$OUT"
# A file made for B must not open on A, and B must refuse an untrusted sender.
if $ADMIN import "$WORK/a2b.cfk" 2>/dev/null; then echo "A imported a bundle addressed to B" >&2; exit 1; fi
if $ADMIN_B import "$WORK/a2b.cfk" 2>/dev/null; then echo "B accepted the same transfer twice (replay)" >&2; exit 1; fi
$ADMIN_B peer rm a >/dev/null
if $ADMIN_B import "$WORK/a2b.cfk" 2>/dev/null; then echo "B accepted an untrusted sender" >&2; exit 1; fi

step "9. back up the vault, check health, survive an accidental delete"
for _ in 1 2 3; do cofferak backup --dir "$WORK/backups" --keep 2 >/dev/null; done
[[ "$(ls "$WORK/backups" | grep -c '^cofferak-vault-')" == "2" ]]
set +e
DOCTOR_OUT="$(cofferak doctor --backup-dir "$WORK/backups")"; DOCTOR_RC=$?
set -e
[[ $DOCTOR_RC -le 1 ]] || { echo "doctor reported a failure:" >&2; echo "$DOCTOR_OUT" >&2; exit 1; }
grep -q "daemon is listening" <<<"$DOCTOR_OUT"
rm "$COFFERAK_DATA_DIR/vault.cofferak"                       # oops
[[ "$(cofferak get myapp/DB_PASSWORD)" == "p@ss w0rd" ]]     # the daemon puts it back
[[ -f "$COFFERAK_DATA_DIR/vault.cofferak" ]]

step "10. an older copy of the vault put back is refused, accept-restore accepts it on purpose"
cp "$COFFERAK_DATA_DIR/vault.cofferak" "$WORK/old.cofferak"
printf 'newer' | cofferak set myapp/ROLLBACK --stdin
cp "$WORK/old.cofferak" "$COFFERAK_DATA_DIR/vault.cofferak.restore"
mv "$COFFERAK_DATA_DIR/vault.cofferak.restore" "$COFFERAK_DATA_DIR/vault.cofferak"
[[ "$(cofferak get myapp/ROLLBACK)" == "newer" ]]   # the daemon keeps the last verified state
if printf x | cofferak set myapp/AFTER --stdin 2>/dev/null; then echo "daemon wrote over an older copy" >&2; exit 1; fi
RESTORE_OUT="$($ADMIN accept-restore)"   # captured: grep -q in a pipe can SIGPIPE the writer
grep -q "accepted the restored vault" <<<"$RESTORE_OUT"

echo "== README quickstart: all steps passed ($OS)"
