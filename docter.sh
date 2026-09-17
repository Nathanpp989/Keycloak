#!/usr/bin/env bash
# doctor.sh — one-shot health check of the whole auth-broker stack. Consolidates
# the diagnostics you'd otherwise run by hand when something's off: Docker up,
# containers healthy, OpenBao reachable+unsealed, Keycloak+Auth0 discovery,
# the app's health endpoint, the Traefik cert, and .env sanity.
#
# Each line is PASS / FAIL / WARN. Exits non-zero if any hard check FAILs, so it
# doubles as a preflight in scripts/CI.  Read-only: changes nothing.
#
# USAGE:  ./doctor.sh

set -uo pipefail
OPENBAO_ADDR="${OPENBAO_ADDR:-http://127.0.0.1:8200}"
APP_ADDR="${APP_ADDR:-http://127.0.0.1:8000}"
fails=0; warns=0

_pass() { printf '  PASS  %s\n' "$1"; }
_fail() { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }
_warn() { printf '  WARN  %s\n' "$1"; warns=$((warns + 1)); }

_code() { _o="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$1" 2>/dev/null)"; echo "${_o:-000}"; }

echo "=============================================================="
echo " auth-broker doctor"
echo "=============================================================="

# 1. Docker daemon
if docker info >/dev/null 2>&1; then _pass "Docker daemon running"
else _fail "Docker daemon not running — start Docker Desktop"; fi

# 2. compose services present + not exited/restarting
if docker compose ps >/dev/null 2>&1; then
  unhealthy="$(docker compose ps --format '{{.Service}} {{.Status}}' 2>/dev/null \
              | grep -iE 'exit|restart|unhealthy' || true)"
  if [ -z "$unhealthy" ]; then
    n="$(docker compose ps --services 2>/dev/null | wc -l | tr -d ' ')"
    _pass "compose services up (${n} services, none exited/unhealthy)"
  else
    _fail "some services are down/unhealthy:"; printf '        %s\n' "$unhealthy"
  fi
else _warn "not in a compose project dir (or compose unavailable)"; fi

# 3. OpenBao reachable + UNSEALED
sealed="$(curl -s --max-time 5 "$OPENBAO_ADDR/v1/sys/health" 2>/dev/null \
         | sed -n 's/.*"sealed":\([a-z]*\).*/\1/p')"
case "$sealed" in
  false) _pass "OpenBao reachable and unsealed ($OPENBAO_ADDR)" ;;
  true)  _fail "OpenBao is SEALED — it won't serve secrets" ;;
  *)     _fail "OpenBao not reachable at $OPENBAO_ADDR" ;;
esac

# 4. App health endpoint
c="$(_code "$APP_ADDR/health/live")"
if [ "$c" = "200" ]; then _pass "app /health/live -> 200"; else _fail "app /health/live -> $c"; fi

# 5. Keycloak discovery (via the internal container path if the alias is set,
#    else the host published port); we just need SOMETHING to answer 200.
kc=""
for u in "http://keycloak.localhost/realms/Premkey/.well-known/openid-configuration" \
         "http://localhost:8080/realms/Premkey/.well-known/openid-configuration"; do
  [ "$(_code "$u")" = "200" ] && { kc="$u"; break; }
done
if [ -n "$kc" ]; then _pass "Keycloak discovery reachable"; else _warn "Keycloak discovery not reachable on known hosts"; fi

# 6. Auth0 discovery (needs AUTH0_DOMAIN)
if [ -n "${AUTH0_DOMAIN:-}" ]; then
  if [ "$(_code "https://$AUTH0_DOMAIN/.well-known/openid-configuration")" = "200" ]; then
    _pass "Auth0 discovery reachable ($AUTH0_DOMAIN)"
  else _warn "Auth0 discovery not reachable ($AUTH0_DOMAIN)"; fi
else _warn "AUTH0_DOMAIN not set — skipping Auth0 discovery check"; fi

# 7. Traefik cert present + from the internal CA
CERT="traefik/dynamic/openbao-cert.pem"
if [ -f "$CERT" ]; then
  if command -v openssl >/dev/null 2>&1; then
    iss="$(openssl x509 -in "$CERT" -noout -issuer 2>/dev/null)"
    case "$iss" in
      *"Auth Broker Internal Root CA"*) _pass "Traefik cert present, issued by internal CA" ;;
      *) _warn "Traefik cert present but issuer unexpected: ${iss#issuer=}" ;;
    esac
  else _pass "Traefik cert present ($CERT)"; fi
else _warn "no Traefik cert at $CERT (run ./bootstrap.sh to issue one)"; fi

# 8. .env sanity (reuse check-env if present, either naming)
for ce in ./check-env.sh ./check_env.sh; do
  if [ -x "$ce" ] && [ -f .env ]; then
    if "$ce" .env >/dev/null 2>&1; then _pass ".env passes check-env"
    else _fail ".env has problems (run $ce)"; fi
    break
  fi
done

echo "--------------------------------------------------------------"
if [ "$fails" -eq 0 ]; then
  echo "OK: no failures ($warns warning(s))."; exit 0
fi
echo "FAIL: $fails failure(s), $warns warning(s)."; exit 1
