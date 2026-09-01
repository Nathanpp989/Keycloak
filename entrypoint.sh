#!/bin/sh
# Persistent OpenBao entrypoint: start the file-backed server, initialize it
# once, and unseal it on every boot — so `docker compose up` is as convenient as
# dev mode was, but the data (PKI CA included) survives restarts.
#
# *** DEV / LOCAL USE ONLY ***
# To auto-unseal, this stores the unseal key AND root token in PLAINTEXT in the
# data volume (bao-init.json). Fine for a local dev stack; NOT secure for
# production — production uses a KMS/transit auto-unseal and never persists the
# unseal material next to the data.
#
# POSIX sh (the OpenBao image is Alpine — no bash). Fails LOUDLY (clear message +
# non-zero exit) at each step so `docker compose logs openbao` pinpoints any
# problem. Paths are overridable via env so the same script is testable outside
# the container.
#
# NOT `set -e`: `bao status` / `operator init -status` intentionally exit
# non-zero (sealed / not-initialized), and set -e would kill us before we could
# act. set -u catches unset-var typos.
set -u

BAO_CONFIG="${BAO_CONFIG:-/openbao/config.hcl}"
BAO_DATA="${BAO_DATA:-/openbao/data}"
INIT_FILE="${INIT_FILE:-$BAO_DATA/bao-init.json}"
export BAO_ADDR="${BAO_ADDR:-http://127.0.0.1:8200}"

log() { echo "[entrypoint] $*"; }
die() { echo "[entrypoint] ERROR: $*" >&2; exit 1; }

# ── preflight: the tools and paths we depend on must exist ──────────────────
command -v bao >/dev/null 2>&1 || die "'bao' binary not found on PATH ($PATH)"
[ -r "$BAO_CONFIG" ] || die "config not readable: $BAO_CONFIG (is it mounted?)"
mkdir -p "$BAO_DATA" 2>/dev/null || true
# Prove the data dir is writable — the #1 cause of a persistent-OpenBao that
# won't boot is a data volume the container user can't write.
if ! ( : > "$BAO_DATA/.wtest" ) 2>/dev/null; then
  die "data dir not writable: $BAO_DATA (volume permissions — compose runs this container as root for this reason; check the mount)"
fi
rm -f "$BAO_DATA/.wtest" 2>/dev/null || true

# ── start the server in the background; hand off to it at the end ────────────
log "starting OpenBao server (config: $BAO_CONFIG, data: $BAO_DATA)"
bao server -config="$BAO_CONFIG" &
SERVER_PID=$!

# ── wait for the API, detecting an early server crash (e.g. bad config) ─────
i=0
while [ "$i" -lt 30 ]; do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    die "OpenBao server exited during startup — see its log lines above (likely a config error or unwritable storage)"
  fi
  bao status >/dev/null 2>&1
  rc=$?
  if [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; then
    break
  fi
  i=$((i + 1))
  sleep 1
done
[ "$i" -lt 30 ] || die "OpenBao API did not come up within 30s"
log "server is up"

# ── initialize once ─────────────────────────────────────────────────────────
if ! bao operator init -status >/dev/null 2>&1; then
  log "initializing OpenBao (first run)"
  if ! bao operator init -key-shares=1 -key-threshold=1 -format=json > "$INIT_FILE"; then
    die "operator init failed — see the log lines above"
  fi
  chmod 600 "$INIT_FILE" 2>/dev/null || true
else
  log "already initialized (reusing $INIT_FILE)"
fi

# ── unseal ──────────────────────────────────────────────────────────────────
UNSEAL="$(tr -d '\n' < "$INIT_FILE" 2>/dev/null | sed -n 's/.*"unseal_keys_b64":[[:space:]]*\[[[:space:]]*"\([^"]*\)".*/\1/p')"
[ -n "$UNSEAL" ] || die "no unseal key in $INIT_FILE (init failed, or the file is stale — remove the openbao-data volume and re-up)"
bao operator unseal "$UNSEAL" >/dev/null 2>&1 || true

if bao status >/dev/null 2>&1; then
  log "unsealed — OpenBao is ready"
else
  die "unseal did not take (still sealed). The key in $INIT_FILE likely doesn't match the stored data — remove the openbao-data volume and re-up to reinitialize."
fi

# ── hand off: keep the server in the foreground so signals propagate ────────
wait "$SERVER_PID"
