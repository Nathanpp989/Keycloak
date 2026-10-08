#!/usr/bin/env bash
# sync-to-canonical.sh — make this git repo's tracked tree EXACTLY match the
# canonical Premkey broker bundle, in one reviewable commit.
#
# Why this exists: CI kept breaking not on code bugs but on stale committed
# files that had drifted from canonical (requirements.txt, ci.yml, .dockerignore).
# This does one clean wholesale sync so the drift can't recur.
#
# HOW IT WORKS (and why it's safe):
#   1. Removes every git-TRACKED file from the working tree (your .git history
#      is untouched; nothing is pushed yet).
#   2. Extracts the canonical bundle over the tree.
#   3. `git add -A` stages the net result: files that canonical dropped show up
#      as deletions, changed files as modifications, new files as additions.
#   4. You review `git status` / `git diff --cached`, then commit and push
#      YOURSELF. This script never commits or pushes for you.
#
# Untracked files you have locally (your real .env, generated certs, mtls.yml)
# are NOT touched — only tracked files are swept.
#
# USAGE (from the repo root):
#   ./sync-to-canonical.sh                         # auto-finds premkey-canonical.tar.gz
#   ./sync-to-canonical.sh path/to/bundle.tar.gz   # or point at it explicitly

set -euo pipefail

# Resolve the bundle: explicit arg wins; otherwise look for the canonical name
# in the current dir, then next to this script.
BUNDLE="${1:-}"
if [ -z "$BUNDLE" ]; then
  here="$(cd "$(dirname "$0")" && pwd)"
  for cand in "./premkey-canonical.tar.gz" "$here/premkey-canonical.tar.gz"; do
    if [ -f "$cand" ]; then BUNDLE="$cand"; break; fi
  done
fi
if [ -z "$BUNDLE" ] || [ ! -f "$BUNDLE" ]; then
  echo "error: canonical bundle not found." >&2
  echo "usage: $0 [path/to/premkey-canonical.tar.gz]" >&2
  echo "  (with no argument, it looks for ./premkey-canonical.tar.gz)" >&2
  exit 2
fi
BUNDLE="$(cd "$(dirname "$BUNDLE")" && pwd)/$(basename "$BUNDLE")"
echo "Using bundle: $BUNDLE"

if [ ! -d .git ]; then
  echo "error: run this from the root of your Keycloak git repo (no .git here)." >&2
  exit 2
fi

echo "This will replace all TRACKED files in $(pwd) with the canonical bundle."
echo "Your git history and untracked local files (.env, certs) are left alone."
printf 'Proceed? [y/N] '
read -r ans
case "$ans" in y|Y) ;; *) echo "aborted."; exit 1 ;; esac

# 1. Sweep tracked files out of the working tree (history untouched).
git ls-files -z | xargs -0 rm -f 2>/dev/null || true

# 2. Extract canonical over the tree.
tar xzf "$BUNDLE"

# 3. Stage everything (adds, mods, and deletions of dropped files).
git add -A

echo
echo "===================================================================="
echo "Staged. Review before committing:"
echo "    git status"
echo "    git diff --cached --stat"
echo
echo "Then commit and push yourself, e.g.:"
echo "    git commit -m 'Sync repo to canonical tree (fixes CI drift)'"
echo "    git push"
echo "===================================================================="
git status --short | head -40
