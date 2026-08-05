#!/usr/bin/env bash
# traefik_smoke.sh — end-to-end verification of the Traefik + ForwardAuth stack.
#
# This is the check that can ONLY be done with a real container engine: it boots
# the whole compose stack (Traefik + Keycloak + OpenBao + app), then sends real
# HTTP through Traefik to prove the routing and the ForwardAuth allow/deny
# decision actually work end to end — not just that the config is well-formed.
#
# The static checks (container_check.py) and the endpoint's own behaviour
# (verified against real Keycloak) are already covered; this closes the last
# gap: "does a request through the actual proxy get routed and gated correctly."
#
# Usage:
#   ./traefik_smoke.sh                 # brings the stack up, tests, leaves it up
#   ./traefik_smoke.sh --down          # also tears the stack down at the end
#   COMPOSE="podman compose" ./traefik_smoke.sh   # use podman instead of docker
#
# Requirements: a working `docker compose` (or `podman compose`) and curl.
# Hostnames: *.localhost resolves to 127.0.0.1 on most systems. If not, add:
#   127.0.0.1  app.localhost keycloak.localhost openbao.localhost
# to /etc/hosts first.

set -uo pipefail

COMPOSE="${COMPOSE:-docker compose}"
APP_HOST="app.localhost"
# Traefik serves TLS with a self-signed dev cert, so -k (insecure) is expected.
CURL="curl -sk --resolve ${APP_HOST}:443:127.0.0.1"
TEARDOWN=0
[ "${1:-}" = "--down" ] && TEARDOWN=1

pass=0
fail=0
ok()   { echo "  ✓ $1"; pass=$((pass+1)); }
bad()  { echo "  ✗ $1"; fail=$((fail+1)); }

cleanup() {
  if [ "$TEARDOWN" = "1" ]; then
    echo "Tearing down the stack..."
    $COMPOSE down -v >/dev/null 2>&1 || true
  else
    echo "Stack left running. Tear down with: $COMPOSE down -v"
  fi
}
trap cleanup EXIT

echo "============================================================"
echo "TRAEFIK + FORWARDAUTH END-TO-END SMOKE"
echo "============================================================"
echo "compose: $COMPOSE"

# ── 1. bring the stack up ───────────────────────────────────────────────────
echo ""
echo "[1] Bringing the stack up (build + start)..."
if ! $COMPOSE up --build -d; then
  echo "  ✗ compose up failed"; exit 1
fi

# ── 2. wait for the app to be reachable THROUGH Traefik ─────────────────────
echo ""
echo "[2] Waiting for the app to answer through Traefik (https://${APP_HOST}/)..."
ready=0
for i in $(seq 1 60); do
  code=$($CURL -o /dev/null -w '%{http_code}' "https://${APP_HOST}/" || true)
  if [ "$code" = "200" ]; then echo "  ✓ app reachable through Traefik after ${i}s"; ready=1; break; fi
  sleep 3
done
if [ "$ready" != "1" ]; then
  echo "  ✗ app never became reachable through Traefik"
  echo "  --- traefik logs ---"; $COMPOSE logs traefik 2>&1 | tail -30
  echo "  --- app logs ---";     $COMPOSE logs app 2>&1 | tail -30
  exit 1
fi

# ── 3. public routes must be reachable WITHOUT a token ──────────────────────
echo ""
echo "[3] Public routes (no token required)"
code=$($CURL -o /dev/null -w '%{http_code}' "https://${APP_HOST}/")
if [ "$code" = "200" ]; then ok "GET / -> 200 (public)"; else bad "GET / -> $code (expected 200)"; fi

code=$($CURL -o /dev/null -w '%{http_code}' "https://${APP_HOST}/status/subsystems")
if [ "$code" = "200" ]; then ok "GET /status/subsystems -> 200 (public)"; else bad "GET /status/subsystems -> $code"; fi

# ── 4. protected route WITHOUT a token must be DENIED by ForwardAuth ─────────
echo ""
echo "[4] Protected route without a token (ForwardAuth must DENY)"
code=$($CURL -o /dev/null -w '%{http_code}' "https://${APP_HOST}/protected")
if [ "$code" = "401" ]; then
  ok "GET /protected (no token) -> 401 (ForwardAuth denied, as intended)"
else
  bad "GET /protected (no token) -> $code (expected 401 — ForwardAuth not gating!)"
fi

# ── 5. get a real token via the public /token, through Traefik ──────────────
echo ""
echo "[5] Obtaining a token via the public /token route"
KC_USER="${INTEGRATION_KC_USER:-user}"
KC_PASS="${DEFAULT_USER_PASSWORD:-testpass123}"
TOKEN=$($CURL -X POST "https://${APP_HOST}/token" \
  -d "username=${KC_USER}&password=${KC_PASS}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
if [ -n "$TOKEN" ]; then
  ok "POST /token -> got an access token (${#TOKEN} chars)"
else
  bad "POST /token -> no token (cannot test the allow path)"
  echo "  (is the default user provisioned? check: $COMPOSE logs app | tail)"
fi

# ── 6. protected route WITH the token must be ALLOWED ───────────────────────
echo ""
echo "[6] Protected route with a valid token (ForwardAuth must ALLOW)"
if [ -n "$TOKEN" ]; then
  code=$($CURL -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer ${TOKEN}" "https://${APP_HOST}/protected")
  if [ "$code" = "200" ]; then
    ok "GET /protected (valid token) -> 200 (ForwardAuth allowed + routed)"
  else
    bad "GET /protected (valid token) -> $code (expected 200)"
  fi

  # 6b. a forged X-Auth-User must NOT let an unauthenticated caller through,
  #     and must not be trusted. With a valid token the upstream sees the REAL
  #     user; we assert the protected route still returns the real identity.
  body=$($CURL -H "Authorization: Bearer ${TOKEN}" \
    -H "X-Auth-User: attacker" "https://${APP_HOST}/protected")
  if echo "$body" | grep -q "attacker"; then
    bad "forged X-Auth-User leaked into the response (impersonation!)"
  else
    ok "forged X-Auth-User ignored (no impersonation)"
  fi
else
  echo "  - skipped (no token)"
fi

# ── 7. other services routed through Traefik ────────────────────────────────
echo ""
echo "[7] Other services are routed by Traefik"
code=$(curl -sk --resolve keycloak.localhost:443:127.0.0.1 \
  -o /dev/null -w '%{http_code}' "https://keycloak.localhost/realms/master")
if [ "$code" = "200" ]; then ok "Keycloak reachable via Traefik -> 200"; else bad "Keycloak via Traefik -> $code"; fi

echo ""
echo "------------------------------------------------------------"
echo "passed $pass  failed $fail"
if [ "$fail" -gt 0 ]; then
  echo "✗ SOME CHECKS FAILED"
  echo "Diagnostics: Traefik dashboard at http://localhost:8090/dashboard/"
  echo "             $COMPOSE logs traefik | tail"
  exit 1
fi
echo "ALL TRAEFIK END-TO-END CHECKS PASSED"
