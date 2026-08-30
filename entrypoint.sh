#!/bin/sh
# Persistent OpenBao entrypoint: start the file-backed server, initialize it
# once, and unseal it on every boot — so `docker compose up` is as convenient as
# dev mode was, but the data (PKI CA included) survives restarts.
#
# *** DEV / LOCAL USE ONLY ***
# To auto-unseal, this stores the unseal key AND root token in PLAINTEXT in the
# data volume (bao-init.json). That is acceptable for a local dev stack but is
# NOT secure for production — a real deployment uses auto-unseal via a KMS/transit
# seal and never persists the unseal material next to the data.
#
# POSIX sh (the OpenBao image is Alpine — no bash). Paths are overridable via env
# so the same script is testable outside the container.
# NOT `set -e`: several checks below (`bao status`, `operator init -status`)
# intentionally exit non-zero (sealed / not-initialized), and set -e would kill
# the entrypoint before it could init/unseal. set -u catches unset-var typos.
set -u

BAO_CONFIG="${BAO_CONFIG:-/openbao/config.hcl}"
BAO_DATA="${BAO_DATA:-/openbao/data}"
INIT_FILE="${INIT_FILE:-$BAO_DATA/bao-init.json}"
export BAO_ADDR="${BAO_ADDR:-http://127.0.0.1:8200}"

mkdir -p "$BAO_DATA"

# Start the server in the background; keep its PID so we can hand off to it.
bao server -config="$BAO_CONFIG" &
SERVER_PID=$!

# Wait until the API answers. `bao status` exits 0 (unsealed) or 2 (sealed) once
# the listener is up; anything else means it isn't reachable yet.
i=0
while [ "$i" -lt 30 ]; do
  bao status >/dev/null 2>&1
  rc=$?
  if [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; then
    break
  fi
  i=$((i + 1))
  sleep 1
done

# Initialize once. `bao operator init -status` exits 0 if already initialized,
# 2 if not — so a non-zero status means "needs init".
if ! bao operator init -status >/dev/null 2>&1; then
  echo "[entrypoint] initializing OpenBao (first run)"
  bao operator init -key-shares=1 -key-threshold=1 -format=json > "$INIT_FILE"
  chmod 600 "$INIT_FILE" 2>/dev/null || true
fi

# Unseal (idempotent — unsealing an already-unsealed server is a harmless no-op).
# `bao ... -format=json` is pretty-printed (multi-line), so flatten newlines
# first, then pull the key out — no jq/python needed (not in the Alpine image).
UNSEAL="$(tr -d '\n' < "$INIT_FILE" 2>/dev/null | sed -n 's/.*"unseal_keys_b64":[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p')"
if [ -n "$UNSEAL" ]; then
  bao operator unseal "$UNSEAL" >/dev/null 2>&1 || true
  echo "[entrypoint] unsealed"
else
  echo "[entrypoint] WARNING: no unseal key found in $INIT_FILE" >&2
fi

# Hand off to the server process so signals propagate and the container stays up.
wait "$SERVER_PID"