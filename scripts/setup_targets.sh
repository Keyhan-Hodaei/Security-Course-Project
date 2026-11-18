#!/usr/bin/env bash
# مخزن‌های git اهداف (targets/<هدف>/repo) به‌صورت git bundle در مخزن پروژه
# نگه داشته می‌شوند؛ چون مخزن git تودرتو در مخزن والد قابل‌ردیابی نیست و در
# clone/CI از دست می‌رود.
#
#   bash scripts/setup_targets.sh          بازیابی repo/ از repo.bundle (اگر نیست)
#   bash scripts/setup_targets.sh --pack   بسته‌بندی مجدد repo/ در repo.bundle
#                                          (پس از افزودن/تغییر شاخه‌های هدف)
set -eu
cd "$(dirname "$0")/.."
MODE="${1:-restore}"

for dir in targets/*/; do
  t="$(basename "$dir")"
  repo="targets/$t/repo"; bundle="targets/$t/repo.bundle"
  if [ "$MODE" = "--pack" ]; then
    [ -d "$repo/.git" ] || { echo "[$t] مخزن یافت نشد"; continue; }
    git -C "$repo" bundle create "../repo.bundle" --all >/dev/null 2>&1
    git bundle verify "$bundle" >/dev/null 2>&1
    echo "[$t] بسته شد: $bundle ($(git -C "$repo" branch --format='%(refname:short)' | tr '\n' ' '))"
  else
    if [ -d "$repo/.git" ]; then
      echo "[$t] مخزن موجود است"
      continue
    fi
    [ -f "$bundle" ] || { echo "[$t] نه مخزن هست نه $bundle"; exit 1; }
    git clone -q "$bundle" "$repo"
    for ref in $(git -C "$repo" for-each-ref --format='%(refname:short)' refs/remotes/origin/); do
      name="${ref#origin/}"
      [ "$name" = "HEAD" ] || [ "$name" = "origin" ] && continue
      git -C "$repo" branch -q -f "$name" "$ref" 2>/dev/null || true
    done
    git -C "$repo" checkout -q main 2>/dev/null || true
    echo "[$t] از $bundle بازیابی شد: $(git -C "$repo" branch --format='%(refname:short)' | tr '\n' ' ')"
  fi
done
