#!/usr/bin/env bash
# Cross-platform: trust the internal CA in the OS trust store and add the
# .test.local hosts entries, so a browser/curl reaches the stack WITHOUT -k.
# Detects macOS, Linux (Debian/Ubuntu + RHEL/Fedora families), and Windows
# (Git Bash / MSYS / Cygwin). The container stack itself is already portable;
# this is the one host-side step that differs per OS.
#
#   ./trust-ca.sh           detect OS, add hosts, trust the CA (uses sudo/admin)
#   ./trust-ca.sh --print   just print the exact commands for your OS; run them yourself
set -euo pipefail

HOSTNAMES="app.test.local keycloak.test.local openbao.test.local traefik.test.local mtls.test.local"
PRINT_ONLY=0
[ "${1:-}" = "--print" ] && PRINT_ONLY=1
CA_PEM=""

say()  { printf '  %s\n' "$1"; }
cmd()  { if [ "$PRINT_ONLY" = 1 ]; then printf '    $ %s\n' "$*"; else eval "$*"; fi; }

detect_os() {
  case "$(uname -s 2>/dev/null || echo unknown)" in
    Darwin) echo macos ;;
    Linux)  echo linux ;;
    MINGW*|MSYS*|CYGWIN*) echo windows ;;
    *) [ "${OS:-}" = "Windows_NT" ] && echo windows || echo unknown ;;
  esac
}

linux_family() {
  if command -v update-ca-certificates >/dev/null 2>&1; then echo debian
  elif command -v update-ca-trust    >/dev/null 2>&1; then echo rhel
  else echo unknown; fi
}

resolve_ca() {
  for f in traefik/dynamic/openbao-ca.pem /tmp/openbao-ca.pem; do
    [ -f "$f" ] && [ -s "$f" ] && { CA_PEM="$f"; return 0; }
  done
  if curl -sf "${OPENBAO_ADDR:-http://127.0.0.1:8200}/v1/pki/ca/pem" \
       -o /tmp/openbao-ca.pem 2>/dev/null && [ -s /tmp/openbao-ca.pem ]; then
    CA_PEM=/tmp/openbao-ca.pem; return 0
  fi
  return 1
}

add_hosts() {
  local file="$1"
  if grep -q "app.test.local" "$file" 2>/dev/null; then
    say "hosts: .test.local already in $file"
  else
    say "hosts: adding entries to $file"
    cmd "$2"
  fi
}

main() {
  local os; os="$(detect_os)"
  say "detected OS: $os"
  if ! resolve_ca; then
    say "could not find or fetch the CA cert (is OpenBao up at ${OPENBAO_ADDR:-http://127.0.0.1:8200}?)"
    [ "$PRINT_ONLY" = 1 ] || exit 1
    CA_PEM="traefik/dynamic/openbao-ca.pem"   # placeholder for --print
  fi
  say "CA cert: $CA_PEM"
  echo ""

  case "$os" in
    macos)
      add_hosts /etc/hosts \
        "echo '127.0.0.1 $HOSTNAMES' | sudo tee -a /etc/hosts >/dev/null"
      say "trust: add the CA to the System keychain"
      cmd "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '$CA_PEM'"
      ;;
    linux)
      add_hosts /etc/hosts \
        "echo '127.0.0.1 $HOSTNAMES' | sudo tee -a /etc/hosts >/dev/null"
      case "$(linux_family)" in
        debian)
          say "trust (Debian/Ubuntu): copy to the anchors dir (.crt) + update"
          cmd "sudo cp '$CA_PEM' /usr/local/share/ca-certificates/openbao-ca.crt"
          cmd "sudo update-ca-certificates"
          ;;
        rhel)
          say "trust (RHEL/Fedora): copy to the anchors dir + update"
          cmd "sudo cp '$CA_PEM' /etc/pki/ca-trust/source/anchors/openbao-ca.pem"
          cmd "sudo update-ca-trust"
          ;;
        *)
          say "trust: unknown Linux trust tooling — install the CA manually ($CA_PEM)"
          ;;
      esac
      ;;
    windows)
      say "hosts: add to C:\\Windows\\System32\\drivers\\etc\\hosts (admin editor):"
      say "       127.0.0.1 $HOSTNAMES"
      say "trust: in an ADMIN PowerShell/cmd:"
      cmd "certutil -addstore -f Root \"$CA_PEM\""
      ;;
    *)
      say "unsupported OS — trust '$CA_PEM' in your OS trust store manually and add the hosts entries."
      exit 1
      ;;
  esac

  echo ""
  if [ "$PRINT_ONLY" = 1 ]; then
    say "printed the commands for $os — review and run them."
  else
    say "done. Verify (should NOT need -k):  curl https://app.test.local/health/live"
  fi
}
main "$@"
