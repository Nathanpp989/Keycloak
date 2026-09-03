#!/usr/bin/env bash
# bootstrap.sh — bring the WHOLE stack up and make the .test.local hosts serve.
#
# Fixes the recurring foot-guns:
#   - `docker compose up -d --build app` only starts app + deps, NOT Traefik, so
#     .test.local goes unreachable (000). This always brings up the full stack.
#   - After a fresh OpenBao (empty volume -> new CA) the cert must be re-issued.
#     This issues it from the CURRENT CA and reloads Traefik every run (idempotent).
#
# What it does, in order:
#   1. Clear port conflicts + bring up the FULL stack (stack_up.sh / docker compose).
#   2. Wait for openbao + app to be healthy.
#   3. Issue the Traefik cert from OpenBao's current CA and reload Traefik.
#   4. Print the one-time steps (hosts entry, trust the CA) and how to verify.
#
# USAGE:
#   ./bootstrap.sh            # up + cert
#   ./bootstrap.sh --no-cert  # up only (skip cert issuance)
#
# macOS Bash 3.2 safe.

set -uo pipefail

DO_CERT=1
[ "${1:-}" = "--no-cert" ] && DO_CERT=0

command -v docker >/dev/null 2>&1 || { echo "error: docker not found"; exit 1; }
docker info >/dev/null 2>&1 || { echo "error: Docker daemon not running — start Docker Desktop first."; exit 1; }
[ -f compose.yaml ] || [ -f docker-compose.yml ] || { echo "error: run from the stack directory (no compose file here)"; exit 1; }

# ── 1. full stack up (prefer stack_up.sh, which also clears port conflicts) ──
echo "==> Bringing up the FULL stack..."
if [ -x ./stack_up.sh ]; then
  ./stack_up.sh -y --up
elif [ -x ./stack-up.sh ]; then
  ./stack-up.sh -y --up
else
  docker compose up -d
fi

# ── 2. wait for the services the .test.local path depends on ────────────────
wait_healthy() {
  # wait_healthy <service> <seconds>
  svc="$1"; max="$2"; i=0
  while [ "$i" -lt "$max" ]; do
    h="$(docker compose ps "$svc" --format '{{.Health}}' 2>/dev/null)"
    [ "$h" = "healthy" ] && return 0
    # some compose versions don't fill {{.Health}}; fall back to Status text
    docker compose ps "$svc" 2>/dev/null | grep -q "healthy" && return 0
    i=$((i + 1)); sleep 2
  done
  return 1
}

echo "==> Waiting for openbao + app to be healthy..."
wait_healthy openbao 30 || { echo "openbao did not become healthy — check: docker compose logs openbao"; exit 1; }
wait_healthy app 60    || { echo "app did not become healthy — check: docker compose logs app"; exit 1; }
echo "    openbao + app healthy."

# ── 3. issue the Traefik cert from OpenBao's CURRENT CA + reload Traefik ─────
if [ "$DO_CERT" -eq 1 ]; then
  echo "==> Issuing the Traefik cert from OpenBao's current CA..."
  ROOT="$(docker compose exec -T openbao sh -c 'sed -n "s/.*\"root_token\":[[:space:]]*\"\([^\"]*\)\".*/\1/p" /openbao/data/bao-init.json | tr -d "\n"' 2>/dev/null)"
  if [ -z "$ROOT" ]; then
    echo "    could not read the root token from the openbao volume; skipping cert."
  else
    if OPENBAO_ADDR=http://127.0.0.1:8200 OPENBAO_TOKEN="$ROOT" python3 ./openbao_traefik_cert.py; then
      docker compose up -d --force-recreate traefik >/dev/null 2>&1 || \
        docker compose restart traefik >/dev/null 2>&1 || true
      echo "    cert issued and Traefik reloaded."
    else
      echo "    cert issuance failed (see output above) — stack is up, TLS may be stale."
    fi
  fi
fi

# ── 4. one-time steps + how to verify ───────────────────────────────────────
cat <<'EOF'

======================================================================
Stack is up. To reach the .test.local hosts over trusted HTTPS, ONE TIME:

  1. hosts entry (only if not already present):
       grep -q app.test.local /etc/hosts || echo \
         "127.0.0.1  app.test.local keycloak.test.local openbao.test.local traefik.test.local" \
         | sudo tee -a /etc/hosts

  2. trust the OpenBao CA (only after a NEW CA / first run):
       curl -s http://127.0.0.1:8200/v1/pki/ca/pem -o /tmp/openbao-ca.pem
       sudo security add-trusted-cert -d -r trustRoot \
         -k /Library/Keychains/System.keychain /tmp/openbao-ca.pem

Verify (use the SYSTEM curl, which trusts the keychain):
  /usr/bin/curl -s https://app.test.local/health/live -o /dev/null -w "%{http_code}\n"
  TEST_PASS=<your DEFAULT_USER_PASSWORD> ./smoke_test.sh
======================================================================
EOF
