#!/usr/bin/env bash
# Preflight for Azure Key Vault auto-unseal: verify the Azure side is ready BEFORE
# starting OpenBao, so a misconfig shows up here with a clear message instead of a
# cryptic seal failure in the OpenBao log.
#   ./check-azure-kms.sh
set -uo pipefail   # not -e: run every check, then summarize
if [ -f .env ]; then set -a; . ./.env; set +a; fi

VAULT="${AZURE_KEY_VAULT_NAME:-}"
KEY="${AZURE_UNSEAL_KEY_NAME:-openbao-unseal}"
fails=0
pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; fails=$((fails + 1)); }
warn() { printf '  \033[33m•\033[0m %s\n' "$1"; }

echo "Azure KMS auto-unseal preflight"
echo "-------------------------------"

for v in AZURE_TENANT_ID AZURE_CLIENT_ID AZURE_KEY_VAULT_NAME; do
  if [ -n "${!v:-}" ]; then pass "$v is set"; else fail "$v is NOT set (add it to .env)"; fi
done
if [ -n "${AZURE_CLIENT_SECRET:-}" ]; then
  pass "AZURE_CLIENT_SECRET set (service-principal auth)"
else
  warn "AZURE_CLIENT_SECRET not set — assuming a managed identity"
fi

if [ -f openbao/config.azure.hcl ]; then
  pass "openbao/config.azure.hcl present"
else
  fail "openbao/config.azure.hcl missing — run: cp openbao/config.azure.hcl.example openbao/config.azure.hcl"
fi

if command -v az >/dev/null 2>&1 && [ -n "$VAULT" ]; then
  if az keyvault show --name "$VAULT" >/dev/null 2>&1; then
    pass "Key Vault '$VAULT' reachable"
    kt="$(az keyvault key show --vault-name "$VAULT" --name "$KEY" \
          --query 'key.kty' -o tsv 2>/dev/null || true)"
    if [ -n "$kt" ]; then
      pass "unseal key '$KEY' exists (type: $kt)"
      case "$kt" in
        RSA|RSA-HSM) : ;;
        *) warn "key type '$kt' — the azurekeyvault seal expects RSA/RSA-HSM" ;;
      esac
    else
      fail "unseal key '$KEY' not found in '$VAULT' — create an RSA key named '$KEY'"
    fi
  else
    fail "cannot reach Key Vault '$VAULT' (az login? name correct? RBAC on your identity?)"
  fi
else
  warn "az CLI not available (or no vault name) — can't auto-verify the Vault/key"
  warn "  manually confirm: Vault '$VAULT' holds an RSA key '$KEY', and the identity"
  warn "  (client ${AZURE_CLIENT_ID:-?}) has wrapKey + unwrapKey + get on it"
fi

echo "-------------------------------"
if [ "$fails" -eq 0 ]; then
  echo "Preflight OK. Then:"
  echo "  docker compose -f compose.yaml -f compose.azure-kms.yaml up -d openbao"
  echo "  docker compose -f compose.yaml -f compose.azure-kms.yaml logs openbao | grep '\[entrypoint\]'"
  exit 0
fi
echo "Preflight found $fails problem(s) — fix them before starting OpenBao."
exit 1
