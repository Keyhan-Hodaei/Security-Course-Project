#!/usr/bin/env bash
# Target Git repositories (targets/<target>/repo) are stored as Git bundles
# in the project because nested repositories are not tracked as ordinary files
# by the parent repository and would otherwise be missing in clones/CI.
#
#   bash scripts/setup_targets.sh          Restore missing repo/ from repo.bundle
#   bash scripts/setup_targets.sh --pack   Repack repo/ into repo.bundle
#                                          (after adding/changing target branches)
set -eu
cd "$(dirname "$0")/.."
MODE="${1:-restore}"

for dir in targets/*/; do
  t="$(basename "$dir")"
  repo="targets/$t/repo"; bundle="targets/$t/repo.bundle"
  if [ "$MODE" = "--pack" ]; then
    [ -d "$repo/.git" ] || { echo "[$t] Repository not found"; continue; }
    git -C "$repo" bundle create "../repo.bundle" --all >/dev/null 2>&1
    git bundle verify "$bundle" >/dev/null 2>&1
    echo "[$t] Packed: $bundle ($(git -C "$repo" branch --format='%(refname:short)' | tr '\n' ' '))"
  else
    if [ -d "$repo/.git" ]; then
      echo "[$t] Repository already exists"
      continue
    fi
    [ -f "$bundle" ] || { echo "[$t] Neither repository nor $bundle exists"; exit 1; }
    git clone -q "$bundle" "$repo"
    for ref in $(git -C "$repo" for-each-ref --format='%(refname:short)' refs/remotes/origin/); do
      name="${ref#origin/}"
      [ "$name" = "HEAD" ] || [ "$name" = "origin" ] && continue
      git -C "$repo" branch -q -f "$name" "$ref" 2>/dev/null || true
    done
    git -C "$repo" checkout -q main 2>/dev/null || true
    echo "[$t] Restored from $bundle: $(git -C "$repo" branch --format='%(refname:short)' | tr '\n' ' ')"
  fi
done
