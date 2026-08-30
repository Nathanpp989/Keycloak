#!/usr/bin/env bash
# stack_up.sh — bring the stack up with deterministic port-conflict resolution.
#
# THE PROBLEM THIS SOLVES (once and for all):
#   Multiple compose stacks with different project names share the host ports
#   (80/443, etc). A Traefik left running from ANOTHER project keeps port 80,
#   so THIS stack's Traefik can't start ("Bind for 0.0.0.0:80 failed: port is
#   already allocated"). `docker compose down` doesn't help — it only touches
#   the current project, not the stray from a different one.
#
# WHAT THIS DOES:
#   1. Cleans up THIS project's own containers + orphans (always safe).
#   2. Finds containers from OTHER projects that hold the ports this stack needs
#      and removes them (after confirmation, or immediately with -y).
#   3. Flags any NON-docker process still holding a port (can't safely kill it).
#   4. Optionally brings the stack up and shows status (--up).
#
# USAGE:
#   ./stack-up.sh            # clear conflicts (prompts before removing strays)
#   ./stack-up.sh -y         # clear conflicts without prompting
#   ./stack-up.sh --up       # clear, then `docker compose up -d`
#   ./stack-up.sh -y --up    # the "just make it work" invocation
#   ./stack-up.sh --check     # report conflicts only; change nothing
#
# Written for macOS Bash 3.2 (no associative arrays, no mapfile, no ${x,,}).

set -uo pipefail   # NOT -e: several checks legitimately return non-zero.

ASSUME_YES=0
DO_UP=0
CHECK_ONLY=0

usage() { sed -n '2,/^set /p' "$0" | sed 's/^# \{0,1\}//;s/^#//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes)   ASSUME_YES=1 ;;
    --up)       DO_UP=1 ;;
    -n|--check) CHECK_ONLY=1 ;;
    -h|--help)  usage ;;
    *) echo "unknown option: $1 (try --help)"; exit 2 ;;
  esac
  shift
done

# ── dependency + context guards ─────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || { echo "error: docker not found on PATH"; exit 1; }
docker compose version >/dev/null 2>&1 || {
  echo "error: 'docker compose' (v2) is required (you may have the old 'docker-compose')."; exit 1; }
if [ ! -f compose.yaml ] && [ ! -f compose.yml ] && \
   [ ! -f docker-compose.yml ] && [ ! -f docker-compose.yaml ]; then
  echo "error: no compose file in $(pwd) — run this from your stack directory."; exit 1
fi

# ── project name (to tell OUR containers from strays) ───────────────────────
PROJECT="$(docker compose config 2>/dev/null | awk -F': ' '/^name:/{print $2; exit}')"
if [ -z "$PROJECT" ]; then
  # compose's default: lowercased dir basename with non-alnum stripped.
  PROJECT="$(basename "$PWD" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
fi

# ── host ports this stack publishes (from the resolved config) ──────────────
PORTS="$(docker compose config 2>/dev/null | grep 'published:' | grep -oE '[0-9]+' | sort -un | tr '\n' ' ')"
[ -n "$PORTS" ] || PORTS="80 443"   # fallback to the ports that actually conflict

echo "Project      : $PROJECT"
echo "Host ports   : $PORTS"
echo "Mode         : $([ "$CHECK_ONLY" -eq 1 ] && echo check-only || echo resolve)$([ "$DO_UP" -eq 1 ] && echo ' + up')"
echo "----------------------------------------------------------------------"

# ── step 1: clean up OUR OWN containers + orphans (always safe) ──────────────
if [ "$CHECK_ONLY" -ne 1 ]; then
  echo "1. Removing this project's own containers + orphans..."
  docker compose down --remove-orphans >/dev/null 2>&1 || true
else
  echo "1. (check-only) skipping self-cleanup."
fi

# ── step 2: find + remove stray containers from OTHER projects on our ports ──
# A stray = a running container publishing one of our ports whose compose
# project label differs from ours (or is empty, i.e. a plain `docker run`).
find_strays() {
  docker ps --format '{{.ID}}|{{.Names}}|{{.Label "com.docker.compose.project"}}|{{.Ports}}' 2>/dev/null | \
  while IFS='|' read -r id name proj ports; do
    for p in $PORTS; do
      case "$ports" in
        *":$p->"*)
          if [ "$proj" != "$PROJECT" ]; then
            echo "$id|$name|${proj:-<none>}|$ports"
          fi
          break ;;
      esac
    done
  done | sort -u
}

STRAYS="$(find_strays)"
if [ -n "$STRAYS" ]; then
  echo "2. Containers from OTHER projects are holding your ports:"
  echo "$STRAYS" | awk -F'|' '{printf "     %-14s %-32s [project: %s]\n", $1, $2, $3}'
  if [ "$CHECK_ONLY" -eq 1 ]; then
    echo "   (check-only: not removing)"
  else
    if [ "$ASSUME_YES" -ne 1 ]; then
      printf "   Remove these stray container(s)? [y/N] "
      read -r ans
      case "$(echo "${ans:-}" | tr '[:upper:]' '[:lower:]')" in
        y|yes) ;;
        *) echo "   Left in place. Ports still conflict — aborting."; exit 1 ;;
      esac
    fi
    ids="$(echo "$STRAYS" | awk -F'|' '{print $1}' | tr '\n' ' ')"
    echo "   Removing: $ids"
    # shellcheck disable=SC2086
    docker rm -f $ids >/dev/null 2>&1 || true
  fi
else
  echo "2. No stray containers from other projects on your ports."
fi

# ── step 3: flag any NON-docker listener still on a port ────────────────────
# (Docker Desktop's own proxy may appear for docker-published ports; that's
#  expected. This flags e.g. a local Apache/nginx that would block the bind.)
if command -v lsof >/dev/null 2>&1; then
  for p in $PORTS; do
    holders="$(lsof -nP -iTCP:"$p" -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1}' | sort -u | tr '\n' ' ')"
    case "$holders" in
      ""|*com.docker*|*Docker*|*vpnkit*) : ;;   # empty or Docker's own proxy — fine
      *) echo "3. note: port $p still has a non-docker listener: $holders"
         echo "        stop it before 'up' (e.g. 'sudo apachectl stop'), or it will block the bind." ;;
    esac
  done
fi

# ── step 4: optionally bring the stack up ───────────────────────────────────
if [ "$DO_UP" -eq 1 ] && [ "$CHECK_ONLY" -ne 1 ]; then
  echo "----------------------------------------------------------------------"
  echo "4. Bringing the stack up..."
  if docker compose up -d; then
    echo ""
    docker compose ps
    echo ""
    echo "Done. If Traefik is 'Up' with 80/443 mapped, the .test.local hosts will"
    echo "serve once your /etc/hosts entries + cert are in place."
  else
    echo ""
    echo "compose up failed. If it says 'port is already allocated', a non-docker"
    echo "process holds the port — find it with:"
    echo "  sudo lsof -nP -iTCP:80 -sTCP:LISTEN"
    exit 1
  fi
else
  echo "----------------------------------------------------------------------"
  echo "Ports cleared. Start the stack with:  ./stack-up.sh --up   (or docker compose up -d)"
fi
