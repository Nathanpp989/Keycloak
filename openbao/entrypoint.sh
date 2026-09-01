#!/bin/sh
set -u

BAO_CONFIG="${BAO_CONFIG:-/openbao/config.hcl}"
BAO_DATA="${BAO_DATA:-/openbao/data}"
INIT_FILE="${INIT_FILE:-$BAO_DATA/bao-init.json}"
export BAO_ADDR="${BAO_ADDR:-http://127.0.0.1:8200}"

log() { echo "[entrypoint] $*"; }
die() { echo "[entrypoint] ERROR: $*" >&2; exit 1; }

command -v bao >/dev/null 2>&1 || die "'bao' binary not found on PATH ($PATH)"
[ -r "$BAO_CONFIG" ] || die "config not readable: $BAO_CONFIG (is it mounted?)"
mkdir -p "$BAO_DATA" 2>/dev/null || true
if ! ( : > "$BAO_DATA/.wtest" ) 2>/dev/null; then
  die "data dir not writable: $BAO_DATA (volume permissions)"
fi
rm -f "$BAO_DATA/.wtest" 2>/dev/null || true

log "starting OpenBao server (config: $BAO_CONFIG, data: $BAO_DATA)"
bao server -config="$BAO_CONFIG" &
SERVER_PID=$!

i=0
while [ "$i" -lt 30 ]; do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    die "OpenBao server exited during startup — see its log lines above"
  fi
  bao status >/dev/null 2>&1
  rc=$?
  if [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; then break; fi
  i=$((i + 1))
  sleep 1
done
[ "$i" -lt 30 ] || die "OpenBao API did not come up within 30s"
log "server is up"

if ! bao operator init -status >/dev/null 2>&1; then
  log "initializing OpenBao (first run)"
  bao operator init -key-shares=1 -key-threshold=1 -format=json > "$INIT_FILE" || die "operator init failed"
  chmod 600 "$INIT_FILE" 2>/dev/null || true
else
  log "already initialized (reusing $INIT_FILE)"
fi

UNSEAL="$(tr -d '\n' < "$INIT_FILE" 2>/dev/null | sed -n 's/.*"unseal_keys_b64":[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p')"
[ -n "$UNSEAL" ] || die "no unseal key in $INIT_FILE (remove the openbao-data volume and re-up)"
bao operator unseal "$UNSEAL" >/dev/null 2>&1 || true

if bao status >/dev/null 2>&1; then
  log "unsealed — OpenBao is ready"
else
  die "unseal did not take (still sealed). Remove the openbao-data volume and re-up."
fi

wait "$SERVER_PID"
