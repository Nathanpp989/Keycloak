#!/usr/bin/env bash
# free_port.sh — free one or more host ports, whatever is holding them.
#
# THE PROBLEM THIS SOLVES:
#   "address already in use" / "port is already allocated" for a specific port.
#   Unlike stack-up.sh (which clears the compose stack's ports), this targets an
#   arbitrary port and handles BOTH kinds of holder:
#     - a Docker container publishing the port   -> remove it
#     - a plain host process listening on it      -> kill it
#   Typical case: a local `bao server -dev` stuck on 127.0.0.1:8200 from an
#   earlier session, or another project's container squatting a port.
#
# USAGE:
#   ./free-port.sh 8200            # free port 8200 (prompts before acting)
#   ./free-port.sh -y 8200         # free it without prompting
#   ./free-port.sh --check 8200    # report what's on it; change nothing
#   ./free-port.sh -y 8200 8201    # several ports at once
#
# Written for macOS Bash 3.2 (no associative arrays, no mapfile, no ${x,,}).

set -uo pipefail   # NOT -e: several checks legitimately return non-zero.

ASSUME_YES=0
CHECK_ONLY=0
PORTS=""

usage() { sed -n '2,/^set /p' "$0" | sed 's/^# \{0,1\}//;s/^#//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes)   ASSUME_YES=1 ;;
    -n|--check) CHECK_ONLY=1 ;;
    -h|--help)  usage ;;
    ''|*[!0-9]*) echo "unknown option or non-numeric port: $1 (try --help)"; exit 2 ;;
    *) PORTS="$PORTS $1" ;;
  esac
  shift
done

PORTS="$(echo "$PORTS" | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -un | tr '\n' ' ')"
if [ -z "$PORTS" ]; then
  echo "error: give at least one port, e.g. ./free-port.sh 8200"; exit 2
fi

HAVE_DOCKER=0
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && HAVE_DOCKER=1
HAVE_LSOF=0
command -v lsof >/dev/null 2>&1 && HAVE_LSOF=1
if [ "$HAVE_DOCKER" -eq 0 ] && [ "$HAVE_LSOF" -eq 0 ]; then
  echo "error: neither a running docker nor lsof is available; cannot inspect ports."; exit 1
fi

confirm() {
  # confirm "<question>" -> returns 0 to proceed, 1 to skip
  [ "$ASSUME_YES" -eq 1 ] && return 0
  printf "   %s [y/N] " "$1"
  read -r ans
  case "$(echo "${ans:-}" | tr '[:upper:]' '[:lower:]')" in
    y|yes) return 0 ;;
    *) return 1 ;;
  esac
}

overall_rc=0

for port in $PORTS; do
  echo "=================================================================="
  echo "Port $port"
  acted=0

  # ── holder type 1: a Docker container publishing the port ────────────────
  if [ "$HAVE_DOCKER" -eq 1 ]; then
    containers="$(docker ps --format '{{.ID}}|{{.Names}}|{{.Label "com.docker.compose.project"}}|{{.Ports}}' 2>/dev/null | \
      while IFS='|' read -r id name proj ports; do
        case "$ports" in
          *":$port->"*) echo "$id|$name|${proj:-<none>}" ;;
        esac
      done)"
    if [ -n "$containers" ]; then
      echo " Docker container(s) publishing $port:"
      echo "$containers" | awk -F'|' '{printf "   %-14s %-34s [project: %s]\n", $1, $2, $3}'
      if [ "$CHECK_ONLY" -eq 1 ]; then
        echo "   (check-only: not removing)"
      elif confirm "Remove the container(s) above?"; then
        ids="$(echo "$containers" | awk -F'|' '{print $1}' | tr '\n' ' ')"
        # shellcheck disable=SC2086
        docker rm -f $ids >/dev/null 2>&1 || true
        echo "   removed."
        acted=1
      else
        echo "   left in place."
      fi
    fi
  fi

  # ── holder type 2: a plain host process listening on the port ────────────
  # (Skip Docker's own proxy — that's the container above, handled already.)
  if [ "$HAVE_LSOF" -eq 1 ]; then
    procs="$(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | \
      awk 'NR>1 {print $1"|"$2}' | \
      grep -viE 'com\.docke|docker|vpnkit|backend' | sort -u)"
    if [ -n "$procs" ]; then
      echo " Host process(es) listening on $port:"
      echo "$procs" | awk -F'|' '{printf "   %-24s pid %s\n", $1, $2}'
      if [ "$CHECK_ONLY" -eq 1 ]; then
        echo "   (check-only: not killing)"
      elif confirm "Kill the process(es) above?"; then
        pids="$(echo "$procs" | awk -F'|' '{print $2}' | sort -un | tr '\n' ' ')"
        # shellcheck disable=SC2086
        kill $pids 2>/dev/null || true
        sleep 1
        # escalate only for those still alive
        for pid in $pids; do
          if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || \
              echo "   pid $pid survived; you may need: sudo kill -9 $pid"
          fi
        done
        echo "   signalled."
        acted=1
      else
        echo "   left in place."
      fi
    fi
  fi

  # ── verify ───────────────────────────────────────────────────────────────
  if [ "$CHECK_ONLY" -eq 1 ]; then
    continue
  fi
  still=""
  if [ "$HAVE_LSOF" -eq 1 ]; then
    still="$(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | \
      awk 'NR>1 {print $1}' | grep -viE 'com\.docke|docker|vpnkit|backend' | sort -u | tr '\n' ' ')"
  fi
  if [ -n "$still" ]; then
    echo " port $port STILL held by: $still (may need sudo)"
    overall_rc=1
  elif [ "$acted" -eq 1 ]; then
    echo " port $port is now free."
  else
    echo " port $port was already free."
  fi
done

echo "=================================================================="
exit $overall_rc