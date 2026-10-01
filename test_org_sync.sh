#!/usr/bin/env bash
# Live proof of Auth0 org-sync: create a test org in Auth0, sync it into Keycloak,
# confirm the group appears, then clean up (delete the test org + group).
# Needs the app image rebuilt with auth0_org_sync.py:
#   docker compose -f compose.yaml -f compose.postgres.yaml up -d --build app
#   ./test-org-sync.sh
set -euo pipefail

COMPOSE="docker compose -f compose.yaml -f compose.postgres.yaml"
if [ -f .env ]; then set -a; . ./.env; set +a; fi
: "${AUTH0_DOMAIN:?set AUTH0_DOMAIN in .env}"
: "${AUTH0_CLIENT_ID:?}"; : "${AUTH0_CLIENT_SECRET:?}"
TEST_ORG="${TEST_ORG:-livetest-org}"

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; exit 1; }
cleanup() {
  [ -n "${ORG_ID:-}" ] && curl -s -X DELETE \
    "https://$AUTH0_DOMAIN/api/v2/organizations/$ORG_ID" \
    -H "Authorization: Bearer $MGMT" >/dev/null 2>&1 || true
  $COMPOSE exec -T -e G="$TEST_ORG" app python3 - <<'PY' >/dev/null 2>&1 || true
import os
from main import _build_keycloak_admin
a = _build_keycloak_admin()
for g in a.get_groups():
    if g.get("name") == os.environ["G"]:
        a.delete_group(g["id"])
PY
}
trap cleanup EXIT

# 1. Auth0 Management token
MGMT="$(curl -s "https://$AUTH0_DOMAIN/oauth/token" \
  --data-urlencode "client_id=$AUTH0_CLIENT_ID" \
  --data-urlencode "client_secret=$AUTH0_CLIENT_SECRET" \
  --data-urlencode "audience=https://$AUTH0_DOMAIN/api/v2/" \
  --data-urlencode "grant_type=client_credentials" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token") or "")')"
[ -n "$MGMT" ] || fail "no Auth0 Management token (is the M2M app authorized for the Management API?)"
pass "Auth0 Management token acquired"

# 2. create the test org
RESP="$(curl -s -X POST "https://$AUTH0_DOMAIN/api/v2/organizations" \
  -H "Authorization: Bearer $MGMT" -H 'content-type: application/json' \
  -d "{\"name\":\"$TEST_ORG\",\"display_name\":\"Live Test Org\"}")"
ORG_ID="$(printf '%s' "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))')"
[ -n "$ORG_ID" ] || fail "could not create Auth0 org (response: $RESP)"
pass "created Auth0 org '$TEST_ORG' ($ORG_ID)"

# 3. run the sync INSIDE the app container (env + Keycloak reachable there)
echo "Running org-sync..."
OUT="$($COMPOSE exec -T app python3 -c 'from auth0_org_sync import run_sync; import json; print(json.dumps(run_sync()))')"
printf '  sync result: %s\n' "$OUT"
if printf '%s' "$OUT" | TEST_ORG="$TEST_ORG" python3 -c \
  'import sys,json,os; s=json.load(sys.stdin); sys.exit(0 if os.environ["TEST_ORG"] in s["created"]+s["adopted"] else 1)'
then pass "'$TEST_ORG' appears in the sync result"; else fail "'$TEST_ORG' not synced"; fi

# 4. confirm the Keycloak group actually exists
if $COMPOSE exec -T -e G="$TEST_ORG" app python3 - <<'PY'
import os, sys
from main import _build_keycloak_admin
names = [g.get("name") for g in _build_keycloak_admin().get_groups()]
sys.exit(0 if os.environ["G"] in names else 1)
PY
then pass "Keycloak group '$TEST_ORG' exists"; else fail "Keycloak group '$TEST_ORG' not found"; fi

echo ""
echo "Auth0 org-sync verified end to end (cleanup runs on exit)."
