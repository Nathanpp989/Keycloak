#!/usr/bin/env bash
# Deactivate the opt-in mTLS route: remove the active mtls.yml and reload Traefik.
# Leaves the .example, the CA, and any client certs in place (harmless).
#   ./disable-mtls.sh
set -euo pipefail
OUT="${OUT_DIR:-./traefik/dynamic}"
if [ -f "$OUT/mtls.yml" ]; then
  rm -f "$OUT/mtls.yml"
  echo "removed $OUT/mtls.yml"
  docker compose restart traefik >/dev/null 2>&1 || true
  echo "Traefik reloaded — mtls.test.local no longer requires (or serves) a client cert."
else
  echo "$OUT/mtls.yml not present — mTLS already inactive."
fi
