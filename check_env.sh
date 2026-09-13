#!/usr/bin/env bash
# check_env.sh — validate a .env file BEFORE scripts consume it, catching the
# failure modes seen in practice:
#   - a secret wrapped across lines (a bare continuation line that isn't
#     KEY=value) — breaks `source .env` and silently truncates the value
#   - leftover placeholders (PASTE_..., REPLACE_..., <...>)
#   - empty values for keys that must be set
# Exit 0 if clean, non-zero (with a per-line report) if not.
#
# USAGE:  ./check-env.sh [path-to-env]     (default: .env)

set -uo pipefail
FILE="${1:-.env}"
[ -f "$FILE" ] || { echo "error: $FILE not found"; exit 1; }

problems=0
lineno=0
checked=0
while IFS= read -r line || [ -n "$line" ]; do
  lineno=$((lineno + 1))
  case "$line" in
    ''|\#*) continue ;;                 # blank or comment
  esac
  checked=$((checked + 1))
  kv="${line#export }"                  # strip optional leading 'export '

  # every non-blank/comment line MUST be KEY=value; a bare line (e.g. a wrapped
  # secret's continuation) is the #1 corruption we hit.
  if ! printf '%s' "$kv" | grep -qE '^[A-Za-z_][A-Za-z0-9_]*='; then
    echo "  x line $lineno: not KEY=value — likely a wrapped/continuation line:"
    echo "        ${line:0:56}$([ ${#line} -gt 56 ] && echo ...)"
    problems=$((problems + 1))
    continue
  fi

  key="${kv%%=*}"
  val="${kv#*=}"
  val="${val%\'}"; val="${val#\'}"      # strip surrounding single quotes
  val="${val%\"}"; val="${val#\"}"      # or double quotes

  case "$val" in
    PASTE_*|REPLACE_*|*'<'*'>'*)
      echo "  x line $lineno: $key still holds a placeholder ($val)"
      problems=$((problems + 1)) ;;
  esac

  case "$key" in                        # keys that must be non-empty
    AUTH0_DOMAIN|AUTH0_CLIENT_ID|AUTH0_CLIENT_SECRET)
      [ -n "$val" ] || { echo "  x line $lineno: $key is empty"; problems=$((problems + 1)); } ;;
  esac
done < "$FILE"

if [ "$problems" -eq 0 ]; then
  echo "OK: $FILE looks well-formed ($checked assignments checked)"
  exit 0
fi
echo "FAIL: $problems problem(s) in $FILE"
exit 1
