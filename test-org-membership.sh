#!/usr/bin/env bash
# Live proof of Auth0 org MEMBERSHIP sync: create a test org + a test Auth0 user,
# add the user to the org, create a matching Keycloak user, run org-sync then
# member-sync, and confirm the Keycloak user landed in the org's group. Cleans up.
#
# Needs the app rebuilt with auth0_org_sync.py, and the M2M app scoped for:
#   read/create/delete:organizations, read/create:organization_members,
#   create/read/delete:users
#   ./test-org-membership.sh
set -euo pipefail

COMPOSE="docker compose -f compose.yaml -f compose.postgres.yaml"
if [ -f .env ]; then set -a; . ./.env; set +a; fi
: "${AUTH0_DOMAIN:?set AUTH0_DOMAIN in .env}"
: "${AUTH0_CLIENT_ID:?}"; : "${AUTH0_CLIENT_SECRET:?}"
TEST_ORG="${TEST_ORG:-memtest-org}"
CONN="${AUTH0_DB_CONNECTION:-Username-Password-Authentication}"
EMAIL="memtest-$$@example.com"
MGMT=""; ORG_ID=""; USER_ID=""

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; exit 1; }
jget() { python3 -c "import sys,json;print(json.load(sys.stdin).get('$1') or '')"; }

cleanup() {
  [ -n "$USER_ID" ] && curl -s -X DELETE "https://$AUTH0_DOMAIN/api/v2/users/$USER_ID" \
    -H "Authorization: Bearer $MGMT" >/dev/null 2>&1 || true
  [ -n "$ORG_ID" ] && curl -s -X DELETE "https://$AUTH0_DOMAIN/api/v2/organizations/$ORG_ID" \
    -H "Authorization: Bearer $MGMT" >/dev/null 2>&1 || true
  $COMPOSE exec -T -e EMAIL="$EMAIL" -e G="$TEST_ORG" app python3 - <<'PY' >/dev/null 2>&1 || true
import os
from main import _build_keycloak_admin
a = _build_keycloak_admin()
for u in a.get_users({"email": os.environ["EMAIL"], "exact": True}):
    a.delete_user(u["id"])
for g in a.get_groups():
    if g.get("name") == os.environ["G"]:
        a.delete_group(g["id"])
PY
}
trap cleanup EXIT

MGMT="$(curl -s "https://$AUTH0_DOMAIN/oauth/token" \
  --data-urlencode "client_id=$AUTH0_CLIENT_ID" \
  --data-urlencode "client_secret=$AUTH0_CLIENT_SECRET" \
  --data-urlencode "audience=https://$AUTH0_DOMAIN/api/v2/" \
  --data-urlencode "grant_type=client_credentials" | jget access_token)"
[ -n "$MGMT" ] || fail "no Auth0 Management token"
pass "Auth0 Management token acquired"

ORG_ID="$(curl -s -X POST "https://$AUTH0_DOMAIN/api/v2/organizations" \
  -H "Authorization: Bearer $MGMT" -H 'content-type: application/json' \
  -d "{\"name\":\"$TEST_ORG\",\"display_name\":\"Member Test\"}" | jget id)"
[ -n "$ORG_ID" ] || fail "could not create org"
pass "created org '$TEST_ORG' ($ORG_ID)"

USER_ID="$(curl -s -X POST "https://$AUTH0_DOMAIN/api/v2/users" \
  -H "Authorization: Bearer $MGMT" -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"Test!2345pw\",\"connection\":\"$CONN\",\"email_verified\":true}" \
  | jget user_id)"
[ -n "$USER_ID" ] || fail "could not create Auth0 user (needs create:users + DB connection '$CONN')"
pass "created Auth0 user $EMAIL"

curl -s -X POST "https://$AUTH0_DOMAIN/api/v2/organizations/$ORG_ID/members" \
  -H "Authorization: Bearer $MGMT" -H 'content-type: application/json' \
  -d "{\"members\":[\"$USER_ID\"]}" >/dev/null
pass "added user to the org"

$COMPOSE exec -T -e EMAIL="$EMAIL" app python3 - <<'PY'
import os
from main import _build_keycloak_admin
a = _build_keycloak_admin()
e = os.environ["EMAIL"]
if not a.get_users({"email": e, "exact": True}):
    a.create_user({"email": e, "username": e, "enabled": True})
PY
pass "created matching Keycloak user"

echo "Running org-sync then member-sync..."
OUT="$($COMPOSE exec -T app python3 -c 'from auth0_org_sync import run_sync, run_member_sync; import json; run_sync(); print(json.dumps(run_member_sync()))')"
printf '  member-sync result: %s\n' "$OUT"
if printf '%s' "$OUT" | EMAIL="$EMAIL" python3 -c \
  'import sys,json,os; s=json.load(sys.stdin); sys.exit(0 if os.environ["EMAIL"] in s["added"] else 1)'
then pass "sync reports the member added"; else fail "member not in sync result"; fi

if $COMPOSE exec -T -e EMAIL="$EMAIL" -e G="$TEST_ORG" app python3 - <<'PY'
import os, sys
from main import _build_keycloak_admin
a = _build_keycloak_admin()
g = next((x for x in a.get_groups() if x.get("name") == os.environ["G"]), None)
if not g:
    sys.exit(1)
members = a.get_group_members(g["id"])
sys.exit(0 if any(u.get("email") == os.environ["EMAIL"] for u in members) else 1)
PY
then pass "Keycloak user is a member of group '$TEST_ORG'"; else fail "user not in the Keycloak group"; fi

echo ""
echo "Auth0 org membership sync verified end to end (cleanup runs on exit)."
