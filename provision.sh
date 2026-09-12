#!/usr/bin/env bash
# provision.sh — one-shot, idempotent provisioning of the OpenBao AppRole + KV
# engine, writing the resulting role_id/secret_id into .env. Turns the manual
# "run approle, copy two IDs, paste into .env" dance into one command a fresh
# stack can run. Safe to re-run (re-provisions and rewrites the two .env lines).
#
# USAGE:  ./provision.sh        (stack must be up; openbao healthy)

set -uo pipefail
ADDR="${OPENBAO_ADDR:-http://127.0.0.1:8200}"
ENVFILE="${ENVFILE:-.env}"

# 1. root token from the persistent container's volume
ROOT="$(docker compose exec -T openbao sh -c 'sed -n "s/.*\"root_token\":[[:space:]]*\"\([^\"]*\)\".*/\1/p" /openbao/data/bao-init.json | tr -d "\n"' 2>/dev/null)"
[ -n "$ROOT" ] || { echo "error: couldn't read OpenBao root token — is the openbao container up?"; exit 1; }

# 2. provision AppRole (+ KV engine, done inside configure_approle) and capture creds
OUT="$(OPENBAO_ADDR="$ADDR" OPENBAO_TOKEN="$ROOT" python openbao_setup.py approle 2>&1)" || {
  echo "error: provisioning failed:"; echo "$OUT"; exit 1; }
RID="$(printf '%s\n' "$OUT" | sed -n 's/.*OPENBAO_ROLE_ID=\([^ ]*\).*/\1/p'   | head -1)"
SID="$(printf '%s\n' "$OUT" | sed -n 's/.*OPENBAO_SECRET_ID=\([^ ]*\).*/\1/p' | head -1)"
[ -n "$RID" ] && [ -n "$SID" ] || { echo "error: could not parse role_id/secret_id:"; echo "$OUT"; exit 1; }

# 3. write both into .env idempotently — replace existing lines, else append.
#    Each value goes on ONE quoted line (avoids the wrapped-secret corruption).
_setenv() {  # _setenv KEY VALUE  (writes: export KEY='VALUE')
  _k="$1"; _v="$2"; _t="$(mktemp)"
  grep -v "^export ${_k}=" "$ENVFILE" 2>/dev/null > "$_t" || true
  mv "$_t" "$ENVFILE"
  printf "export %s='%s'\n" "$_k" "$_v" >> "$ENVFILE"
}
touch "$ENVFILE"
_setenv OPENBAO_ROLE_ID   "$RID"
_setenv OPENBAO_SECRET_ID "$SID"

echo "OK: AppRole + KV provisioned; OPENBAO_ROLE_ID/SECRET_ID written to $ENVFILE (one line each)."
echo "    Set OPENBAO_SECRETS=<names> and restart the app to read those secrets via AppRole."
