#!/usr/bin/env bash
# verify_sync.sh — flag broker source files that have DRIFTED from the committed
# manifest. Catches the "my local file is behind the tested tree" problem
# (a stale entrypoint, a compose.yaml missing a router, etc.) in one command,
# before it wastes a debugging round.
#
# USAGE:
#   ./verify-sync.sh            check the working tree against MANIFEST.txt
#   ./verify-sync.sh --update   regenerate MANIFEST.txt from the current tree
#                               (run after tests pass, then commit MANIFEST.txt)
#
# Only broker source is tracked — the Keycloak distribution (bin/lib/conf/…),
# venv, caches, generated certs/secrets, and archives are excluded.

set -uo pipefail
MANIFEST="${MANIFEST:-MANIFEST.txt}"

# Emit "sha16  path" for every broker source file, skipping non-source trees.
_scan() {
  _tmp="$(mktemp)"
  find . -type f \
    ! -path './.git/*' ! -path './venv/*' ! -path './__pycache__/*' \
    ! -path '*/__pycache__/*' ! -path './.pytest_cache/*' ! -path './.mypy_cache/*' \
    ! -path './bin/*' ! -path './lib/*' ! -path './conf/*' ! -path './themes/*' \
    ! -path './providers/*' ! -path './data/*' \
    ! -name '*.pyc' ! -name '.coverage' ! -name '*.tar.gz' ! -name "$MANIFEST" \
    ! -name '.env' ! -name '.env.*' ! -name 'bao-init.json' \
    ! -name 'openbao-cert.pem' ! -name 'openbao-key.pem' ! -name 'tls-openbao.yml' \
    ! -name 'server.crt' ! -name 'server.key' \
    \( -name '*.py' -o -name '*.sh' -o -name '*.yml' -o -name '*.yaml' \
       -o -name '*.hcl' -o -name '*.md' -o -name '*.ini' -o -name '*.txt' \
       -o -name '*.example' -o -name 'Dockerfile' -o -name '.gitignore' \) \
    2>/dev/null | sort > "$_tmp"
  # read the file list from a real file (not a pipe) to avoid fd quirks
  while read -r f; do
    printf '%s  %s\n' "$(sha256sum "$f" | cut -c1-16)" "${f#./}"
  done < "$_tmp"
  rm -f "$_tmp"
}

if [ "${1:-}" = "--update" ]; then
  _scan > "$MANIFEST"
  echo "OK: wrote $MANIFEST ($(wc -l < "$MANIFEST" | tr -d ' ') files) — commit it."
  exit 0
fi

[ -f "$MANIFEST" ] || { echo "error: $MANIFEST not found — run './verify-sync.sh --update' first."; exit 1; }

drift=0
while read -r want path; do
  [ -n "${want:-}" ] || continue
  if [ ! -f "$path" ]; then
    echo "  x MISSING: $path"; drift=$((drift + 1)); continue
  fi
  have="$(sha256sum "$path" | cut -c1-16)"
  if [ "$have" != "$want" ]; then
    echo "  x DIFFERS: $path  (have $have, want $want)"; drift=$((drift + 1))
  fi
done < "$MANIFEST"

if [ "$drift" -eq 0 ]; then
  echo "OK: working tree matches $MANIFEST ($(wc -l < "$MANIFEST" | tr -d ' ') files)."
  exit 0
fi
echo "FAIL: $drift file(s) drifted from $MANIFEST. Pull the current versions and re-check."
exit 1
