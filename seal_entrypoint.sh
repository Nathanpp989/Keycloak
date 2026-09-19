#!/bin/sh
# seal-entrypoint.sh — a throwaway DEV OpenBao that acts as the "transit seal"
# (key-wrapper) for the MAIN OpenBao's auto-unseal. Dev mode auto-unseals itself,
# which is fine for a LOCAL proof of the mechanism; in production this role is a
# cloud KMS/HSM (Azure Key Vault), not a dev bao. It enables the transit engine
# and creates the wrapping key the main bao references.
#
# NOT FOR PRODUCTION — the dev seal holds its master key in memory with a fixed
# root token; it only exists to demonstrate that BAO_AUTO_UNSEAL works end to end.
set -u

TOKEN="${SEAL_ROOT_TOKEN:-sealroot}"
KEY="${SEAL_KEY_NAME:-autounseal}"

echo "[seal] starting dev OpenBao (transit seal provider)"
bao server -dev -dev-root-token-id="$TOKEN" -dev-listen-address=0.0.0.0:8200 &
SRV=$!

export BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN="$TOKEN"
i=0
while [ "$i" -lt 30 ]; do
  bao status >/dev/null 2>&1 && break
  i=$((i + 1)); sleep 1
done
if ! bao status >/dev/null 2>&1; then
  echo "[seal] dev server did not come up"; kill "$SRV" 2>/dev/null; exit 1
fi

bao secrets enable transit >/dev/null 2>&1 || true      # idempotent
bao write -f "transit/keys/${KEY}" >/dev/null 2>&1 || true
if bao read "transit/keys/${KEY}" >/dev/null 2>&1; then
  echo "[seal] transit engine + key '${KEY}' ready"
else
  echo "[seal] WARNING: could not confirm transit key '${KEY}'"
fi

wait "$SRV"
