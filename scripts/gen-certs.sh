#!/usr/bin/env bash
# Generate everything server mode needs, with ECDSA P-384 / SHA-384 keys
# (CNSA): a private CA, a server certificate, and one client certificate
# per name you pass. Good for a lab, a homelab or a small deployment; use
# your organisation's PKI if you have one.
#
# Usage: scripts/gen-certs.sh <out-dir> <server-dns-name> [client-name...]
#   scripts/gen-certs.sh ./tls cofferak.internal app1 app2
#
# Produces in <out-dir> (keys are 0600):
#   ca.pem ca.key                  the CA (keep ca.key offline once done)
#   server.pem server.key          for COFFERAK_TLS_CERT / COFFERAK_TLS_KEY
#   <client>.pem <client>.key      one pair per client, for the SDKs
# and COFFERAK_TLS_CLIENT_CA=<out-dir>/ca.pem (the same CA signs clients).
#
# Certificates are valid for 825 days. Re-run with a new <out-dir> to
# rotate.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi

OUT="$1"; SERVER="$2"; shift 2
CLIENTS=("$@")
[[ ${#CLIENTS[@]} -gt 0 ]] || CLIENTS=(client)
DAYS=825

mkdir -p "$OUT"
umask 077
newkey() { openssl ecparam -name secp384r1 -genkey -noout -out "$1" 2>/dev/null; }

if [[ -e "$OUT/ca.key" ]]; then
  echo "$OUT/ca.key exists; reusing that CA"
else
  newkey "$OUT/ca.key"
  openssl req -x509 -new -sha384 -key "$OUT/ca.key" -days "$DAYS" \
    -subj "/CN=cofferak private CA" -out "$OUT/ca.pem" 2>/dev/null
fi

sign() { # <name> <cn> <extfile>
  newkey "$OUT/$1.key"
  openssl req -new -sha384 -key "$OUT/$1.key" -subj "/CN=$2" -out "$OUT/$1.csr" 2>/dev/null
  openssl x509 -req -sha384 -in "$OUT/$1.csr" -CA "$OUT/ca.pem" -CAkey "$OUT/ca.key" \
    -CAcreateserial -days "$DAYS" -extfile "$3" -out "$OUT/$1.pem" 2>/dev/null
  rm -f "$OUT/$1.csr"
}

printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$SERVER" > "$OUT/.server.ext"
sign server "$SERVER" "$OUT/.server.ext"
printf 'extendedKeyUsage=clientAuth\n' > "$OUT/.client.ext"
for c in "${CLIENTS[@]}"; do
  sign "$c" "$c" "$OUT/.client.ext"
done
rm -f "$OUT/.server.ext" "$OUT/.client.ext" "$OUT/ca.srl"
chmod 644 "$OUT"/*.pem

echo "Wrote to $OUT:"
ls -1 "$OUT"
cat <<EOF

Daemon:
  COFFERAK_TLS_ADDR=0.0.0.0:8443
  COFFERAK_TLS_CERT=$OUT/server.pem
  COFFERAK_TLS_KEY=$OUT/server.key
  COFFERAK_TLS_CLIENT_CA=$OUT/ca.pem
Clients: server name "$SERVER", CA $OUT/ca.pem, and their own <name>.pem / <name>.key.
Move $OUT/ca.key offline once you have issued the certificates you need.
EOF
