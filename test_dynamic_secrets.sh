#!/usr/bin/env bash
# End-to-end proof of OpenBao dynamic database secrets against the real Postgres.
# Self-sufficient: pulls the OpenBao root token from the container (like
# provision.sh) and runs psql INSIDE the postgres container — so you need neither
# a local psql nor a manually-set token.
#
# Run after: docker compose -f compose.yaml -f compose.postgres.yaml up -d postgres
#   ./test-dynamic-secrets.sh
set -euo pipefail

COMPOSE="docker compose -f compose.yaml -f compose.postgres.yaml"
if [ -f .env ]; then set -a; . ./.env; set +a; fi

: "${OPENBAO_ADDR:=http://127.0.0.1:8200}"
# Must match what postgres was created with (compose default if you didn't set it).
: "${POSTGRES_ADMIN_PASSWORD:=change-me-in-env}"
ROLE="${DB_DYNAMIC_ROLE:-app-readonly}"

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; exit 1; }

# Pull the root token from the OpenBao container if not already provided.
if [ -z "${OPENBAO_TOKEN:-}" ]; then
  OPENBAO_TOKEN="$($COMPOSE exec -T openbao sh -c \
    'sed -n "s/.*\"root_token\":[[:space:]]*\"\([^\"]*\)\".*/\1/p" /openbao/data/bao-init.json | tr -d "\n"' 2>/dev/null || true)"
fi
[ -n "${OPENBAO_TOKEN:-}" ] || fail "could not read OPENBAO_TOKEN (is the openbao container up + initialized?)"
export OPENBAO_ADDR OPENBAO_TOKEN POSTGRES_ADMIN_PASSWORD
pass "OpenBao token acquired from the container"

echo "1. Provisioning the database engine + role..."
python3 provision_dynamic_secrets.py

echo "2. Requesting a dynamic credential for role '$ROLE'..."
CREDS_JSON="$(curl -sf -H "X-Vault-Token: $OPENBAO_TOKEN" \
  "$OPENBAO_ADDR/v1/database/creds/$ROLE")" || fail "credential request failed"
py() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)"; }
DB_USER="$(echo "$CREDS_JSON" | py '["data"]["username"]')"
DB_PASS="$(echo "$CREDS_JSON" | py '["data"]["password"]')"
LEASE_ID="$(echo "$CREDS_JSON" | py '["lease_id"]')"
if [ -n "$DB_USER" ]; then pass "issued ephemeral user: $DB_USER"; else fail "no username returned"; fi

# psql INSIDE the postgres container — no local psql needed.
login() {
  $COMPOSE exec -T -e PGPASSWORD="$DB_PASS" postgres \
    psql -U "$1" -h 127.0.0.1 -d appdb -tAc 'SELECT 1;' >/dev/null 2>&1
}

echo "3. Logging into Postgres with the issued credential..."
if login "$DB_USER"; then
  pass "the dynamic credential authenticates to Postgres"
else
  fail "dynamic credential could NOT log in (check the role GRANTs / connection_url)"
fi

echo "4. Revoking the lease..."
curl -sf -H "X-Vault-Token: $OPENBAO_TOKEN" -X PUT \
  -d "{\"lease_id\":\"$LEASE_ID\"}" "$OPENBAO_ADDR/v1/sys/leases/revoke" >/dev/null \
  || fail "revoke request failed"

echo "5. Confirming the revoked credential no longer works..."
sleep 2
if login "$DB_USER"; then
  fail "revoked credential STILL works — revocation did not drop the DB user"
else
  pass "revoked credential is dead — lease lifecycle verified end to end"
fi

echo ""
echo "All dynamic-secrets checks passed."
