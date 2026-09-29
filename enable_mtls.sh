#!/usr/bin/env bash
# One-time setup to enable mTLS on the mtls.test.local route:
#  1. reissue the server cert so it covers mtls.test.local (else the TLS handshake
#     fails before mTLS is even reached),
#  2. issue a CLIENT cert + write openbao-ca.pem (the CA Traefik verifies clients
#     against, and curl trusts the server with),
#  3. remind you to add mtls.test.local to /etc/hosts.
# traefik/dynamic/mtls.yml is already in place; Traefik hot-reloads it.
set -euo pipefail

COMPOSE="docker compose -f compose.yaml -f compose.postgres.yaml"
if [ -f .env ]; then set -a; . ./.env; set +a; fi
: "${OPENBAO_ADDR:=http://127.0.0.1:8200}"
OUT="${OUT_DIR:-./traefik/dynamic}"
CN="${CLIENT_CN:-mtls.test.local}"

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
note() { printf '  \033[33m•\033[0m %s\n' "$1"; }

if [ -z "${OPENBAO_TOKEN:-}" ]; then
  OPENBAO_TOKEN="$($COMPOSE exec -T openbao sh -c \
    'sed -n "s/.*\"root_token\":[[:space:]]*\"\([^\"]*\)\".*/\1/p" /openbao/data/bao-init.json | tr -d "\n"' 2>/dev/null || true)"
fi
[ -n "${OPENBAO_TOKEN:-}" ] || { echo "could not read OPENBAO_TOKEN (is openbao up?)"; exit 1; }
export OPENBAO_ADDR OPENBAO_TOKEN
pass "OpenBao token acquired"

echo "1. Reissuing the server cert (now covers mtls.test.local)..."
python3 openbao_traefik_cert.py >/dev/null
pass "server cert reissued (SANs include mtls.test.local)"

echo "2. Issuing a client cert (CN=$CN) + writing the CA..."
python3 openbao_traefik_cert.py --client-cert "$CN" --out-dir "$OUT" >/dev/null
[ -f "$OUT/openbao-ca.pem" ] || { echo "openbao-ca.pem was not written"; exit 1; }
pass "client cert + openbao-ca.pem written to $OUT"

echo "3. Checking /etc/hosts..."
if grep -q "mtls.test.local" /etc/hosts 2>/dev/null; then
  pass "mtls.test.local is in /etc/hosts"
else
  note "add this line to /etc/hosts (needs sudo):"
  echo "      127.0.0.1 mtls.test.local"
fi

echo ""
echo "Done. Traefik hot-reloads traefik/dynamic/. Now run:  ./test-mtls.sh"
