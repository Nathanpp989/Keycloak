#!/usr/bin/env bash
# smoke_test.sh — curl-based end-to-end check of the auth broker on the live
# stack. Exercises the paths built across this project:
#   1. health over HTTPS (the .test.local Command Center host)
#   2. fetch the app client secret from Keycloak (admin)
#   3. machine-to-machine token via /token/client
#   4. that M2M token is accepted on /protected
#   5. user password-grant via /token, accepted on /protected
# Prints PASS/FAIL per step and exits non-zero if any step fails.
#
# USAGE:
#   ./smoke-test.sh
#   BASE=https://app.localhost KC=https://keycloak.localhost ./smoke-test.sh
#   ADMIN_USER=admin ADMIN_PASS=admin TEST_PASS=... ./smoke-test.sh
#
# Uses `curl -k` (skips cert validation) so it works before or without CA trust.
# curl does the HTTP; python3 parses JSON (robust, vs fragile sed-on-JSON).

set -uo pipefail

BASE="${BASE:-https://app.test.local}"
KC="${KC:-https://keycloak.test.local}"
REALM="${REALM:-Premkey}"
CLIENT="${CLIENT:-Hello-World-app}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"
TEST_USER="${TEST_USER:-user}"
TEST_PASS="${TEST_PASS:-${DEFAULT_USER_PASSWORD:-changeme}}"

command -v curl >/dev/null 2>&1 || { echo "error: curl not found"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "error: python3 not found (used to parse JSON)"; exit 1; }

pass=0; fail=0
ok() { echo "  PASS: $1"; pass=$((pass + 1)); }
no() { echo "  FAIL: $1"; fail=$((fail + 1)); }

# jget <python-index-expr> : read stdin JSON, print d<expr>, empty on any error.
# e.g. ... | jget "['access_token']"   ... | jget "[0]['id']"
jget() { python3 -c "import sys,json
try:
    d=json.load(sys.stdin); print(d$1)
except Exception:
    pass" 2>/dev/null; }

echo "Smoke test against $BASE (Keycloak $KC)"
echo "------------------------------------------------------------"

# 1. health ------------------------------------------------------------------
code=$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/health/live")
if [ "$code" = "200" ]; then ok "health/live -> 200"; else no "health/live -> $code"; fi

# 2. admin token + client secret ---------------------------------------------
ADMIN_TOKEN=$(curl -sk "$KC/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli \
  -d "username=$ADMIN_USER" -d "password=$ADMIN_PASS" | jget "['access_token']")

SECRET=""
if [ -z "$ADMIN_TOKEN" ]; then
  no "admin token (can't reach Keycloak admin at $KC) — M2M steps skipped"
else
  ok "admin token acquired"
  CUUID=$(curl -sk "$KC/admin/realms/$REALM/clients?clientId=$CLIENT" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | jget "[0]['id']")
  SECRET=$(curl -sk "$KC/admin/realms/$REALM/clients/$CUUID/client-secret" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | jget "['value']")
  if [ -n "$SECRET" ]; then ok "client secret fetched for $CLIENT"; else no "client secret fetch"; fi
fi

# 3-4. M2M token + protected -------------------------------------------------
if [ -n "$SECRET" ]; then
  TOKEN=$(curl -sk "$BASE/token/client" \
    -d "client_id=$CLIENT" -d "client_secret=$SECRET" | jget "['access_token']")
  if [ -n "$TOKEN" ]; then
    ok "/token/client -> M2M access_token"
    code=$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/protected" \
      -H "Authorization: Bearer $TOKEN")
    if [ "$code" = "200" ]; then ok "M2M token on /protected -> 200"; else no "M2M token on /protected -> $code"; fi
  else
    no "/token/client returned no token (client secret? service accounts enabled?)"
  fi
fi

# 5. user password grant -----------------------------------------------------
UTOKEN=$(curl -sk "$BASE/token" \
  -d "username=$TEST_USER" -d "password=$TEST_PASS" | jget "['access_token']")
if [ -n "$UTOKEN" ]; then
  ok "/token (password grant) -> access_token"
  code=$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/protected" \
    -H "Authorization: Bearer $UTOKEN")
  if [ "$code" = "200" ]; then ok "user token on /protected -> 200"; else no "user token on /protected -> $code"; fi
else
  no "/token (password grant) — check TEST_USER/TEST_PASS (set TEST_PASS=...)"
fi

echo "------------------------------------------------------------"
echo "Result: PASS=$pass  FAIL=$fail"
if [ "$fail" -eq 0 ]; then echo "ALL SMOKE CHECKS PASSED"; exit 0; else exit 1; fi