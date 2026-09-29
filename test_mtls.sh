#!/usr/bin/env bash
# Verify mTLS at the edge: a request WITHOUT a client cert is rejected by Traefik,
# and the SAME request WITH a valid client cert succeeds. Run after ./enable-mtls.sh
# and adding `127.0.0.1 mtls.test.local` to /etc/hosts.
#   ./test-mtls.sh
set -euo pipefail

COMPOSE="docker compose -f compose.yaml -f compose.postgres.yaml"
if [ -f .env ]; then set -a; . ./.env; set +a; fi
: "${OPENBAO_ADDR:=http://127.0.0.1:8200}"
URL="${MTLS_URL:-https://mtls.test.local/health/live}"
OUT="${OUT_DIR:-./traefik/dynamic}"
CN="${CLIENT_CN:-mtls.test.local}"

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; exit 1; }

# Pull the OpenBao token from the container if not set (to issue the client cert).
if [ -z "${OPENBAO_TOKEN:-}" ]; then
  OPENBAO_TOKEN="$($COMPOSE exec -T openbao sh -c \
    'sed -n "s/.*\"root_token\":[[:space:]]*\"\([^\"]*\)\".*/\1/p" /openbao/data/bao-init.json | tr -d "\n"' 2>/dev/null || true)"
fi
export OPENBAO_ADDR OPENBAO_TOKEN

CERT="$OUT/client-$CN.pem"; KEY="$OUT/client-$CN-key.pem"; CA="$OUT/openbao-ca.pem"
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
  echo "Client cert not found — issuing one (CN=$CN)..."
  [ -n "${OPENBAO_TOKEN:-}" ] || fail "no client cert and no OPENBAO_TOKEN to issue one (run ./enable-mtls.sh)"
  python3 openbao_traefik_cert.py --client-cert "$CN" --out-dir "$OUT" >/dev/null
fi
[ -f "$CERT" ] && [ -f "$KEY" ] && [ -f "$CA" ] || fail "client cert/key/CA missing (run ./enable-mtls.sh)"
pass "client cert present: $CERT"

echo "1. Request WITHOUT a client cert should be REJECTED..."
if curl -sf --cacert "$CA" "$URL" >/dev/null 2>&1; then
  fail "request without a client cert SUCCEEDED — mTLS is not enforced on this host"
else
  pass "request without a client cert was rejected (as expected)"
fi

echo "2. Request WITH the client cert should SUCCEED..."
code="$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CA" \
        --cert "$CERT" --key "$KEY" "$URL" 2>/dev/null || echo 000)"
if [ "$code" = "000" ]; then
  fail "TLS handshake failed even WITH the client cert (check caFiles / cert chain / hostname)"
else
  pass "mTLS handshake succeeded with the client cert (HTTP $code past the TLS layer)"
fi

echo "3. Plain HTTP (port 80) must NOT reach the app (mTLS bypass guard)..."
http_code="$(curl -s -o /dev/null -w '%{http_code}' "http://mtls.test.local/health/live" 2>/dev/null || echo 000)"
if [ "$http_code" = "200" ]; then
  fail "plain HTTP reached the app — the mtls router is on web:80 too (entryPoints bug)"
else
  pass "plain HTTP does not reach the app (HTTP $http_code — router is websecure-only)"
fi

echo ""
echo "mTLS verified: rejected without a client cert, accepted with one, no HTTP bypass."
