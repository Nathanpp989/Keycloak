#!/usr/bin/env bash
# One command to run EVERY live proof against the running stack and summarize:
#   health (doctor) -> smoke -> dynamic secrets -> mTLS
# Runs them all (does NOT stop at the first failure) so you see the full picture,
# then prints a pass/fail summary and exits non-zero if any failed.
#
#   ./live-test.sh
# Reads .env for TEST_PASS / DEFAULT_USER_PASSWORD / POSTGRES_ADMIN_PASSWORD.
set -uo pipefail   # deliberately NOT -e: we want to run every check and summarize

COMPOSE="docker compose -f compose.yaml -f compose.postgres.yaml"
if [ -f .env ]; then set -a; . ./.env; set +a; fi

names=(); results=()
record() { names+=("$1"); results+=("$2"); }
# Resolve a script to whatever it's actually named on this machine — hyphen or
# underscore (this repo is edited on a Mac that uses underscore names).
resolve() {
  local n="$1" cand
  for cand in "$n" "${n//-/_}" "${n//_/-}"; do
    [ -f "./$cand" ] && { printf '%s' "$cand"; return 0; }
  done
  return 1
}
run() {
  local name="$1" base="$2"; shift 2
  printf '\n======================================================================\n'
  printf '  %s\n' "$name"
  printf '======================================================================\n'
  local script
  if ! script="$(resolve "$base")"; then record "$name" "SKIP (missing $base)"; return; fi
  # Invoke via `bash` so an un-chmod'd script still runs (no +x required).
  if bash "./$script" "$@"; then record "$name" "PASS"; else record "$name" "FAIL"; fi
}

echo "Preparing: ensuring Postgres is up + mTLS is activated..."
$COMPOSE up -d postgres >/dev/null 2>&1 || true
if [ ! -f traefik/dynamic/mtls.yml ] || [ ! -f traefik/dynamic/openbao-ca.pem ]; then
  em="$(resolve enable-mtls.sh || true)"
  [ -n "$em" ] && bash "./$em" || true
  docker compose restart traefik >/dev/null 2>&1 || true
  sleep 3
fi

run "Health (doctor.sh)"          doctor.sh
run "Smoke tests"                 smoke-test.sh
run "Dynamic secrets"             test-dynamic-secrets.sh
run "mTLS"                        test-mtls.sh

printf '\n======================================================================\n'
printf '  LIVE TEST SUMMARY\n'
printf '======================================================================\n'
overall=0
for i in "${!names[@]}"; do
  case "${results[$i]}" in
    PASS) printf '  \033[32m✓ PASS\033[0m  %s\n' "${names[$i]}" ;;
    SKIP*) printf '  \033[33m• %s\033[0m  %s\n' "${results[$i]}" "${names[$i]}" ;;
    *)    printf '  \033[31m✗ FAIL\033[0m  %s\n' "${names[$i]}"; overall=1 ;;
  esac
done
printf '\n'
[ "$overall" -eq 0 ] && echo "All live checks passed." || echo "Some live checks FAILED (see sections above)."
exit "$overall"
