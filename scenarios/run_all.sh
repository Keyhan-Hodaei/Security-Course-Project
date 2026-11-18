#!/usr/bin/env bash
# اجرای همه سناریوهای ارزیابی PatchProbe با تأیید کدهای خروج موردانتظار.
# استفاده:  bash scenarios/run_all.sh [jsoncheck|imginfo|all]
#
# هر سناریو باید «دقیقاً» کد موردانتظار را بدهد، نه فقط اجرا شود.
# خروجی هر سناریو: reports/<هدف>/<سناریو>/{report.json,report.md,console.log}
# و بسته‌های بازتولید در bundles/<هدف>/<سناریو>/. مجموعه رگرسیون regression/
# بین سناریوها مشترک است (همان رفتار پایپ‌لاین واقعی).
set -u
cd "$(dirname "$0")/.."
PASS=0; FAIL=0; FAILED=()
ONLY="${1:-all}"
PY="${PYTHON:-python3}"

bash scripts/setup_targets.sh >/dev/null || { echo "بازیابی مخزن‌های هدف شکست خورد"; exit 1; }

run () {  # run <هدف> <پایه> <وصله> <کد موردانتظار> <نام سناریو> [پیکربندی]
  local target="$1" base="$2" patched="$3" want="$4" name="$5"
  local cfg="${6:-targets/$target/config.json}"
  local out="reports/$target/$name"
  rm -rf "$out" "bundles/$target/$name"; mkdir -p "$out"
  echo "──────────────────────────────────────────────────────"
  echo "▶ [$target] $name  (پایه: $base → وصله: $patched؛ انتظار: $want)"
  "$PY" -m patchprobe --config "$cfg" \
      --base-ref "$base" --patched-ref "$patched" \
      --out-json "$out/report.json" --out-md "$out/report.md" \
      --bundles-dir "bundles/$target/$name" > "$out/console.log" 2>&1
  local got=$?
  if [ "$got" -eq "$want" ]; then
    echo "  ✓ کد خروج $got (مطابق انتظار)"
    PASS=$((PASS+1))
  else
    echo "  ✗ کد خروج $got ≠ انتظار $want — آخر گزارش:"
    tail -25 "$out/console.log" | sed 's/^/    /'
    FAIL=$((FAIL+1)); FAILED+=("$target/$name")
  fi
}

if [ "$ONLY" = all ] || [ "$ONLY" = jsoncheck ]; then
  run jsoncheck main             patch-correct     0  correct
  run jsoncheck main             patch-incomplete  10 incomplete
  run jsoncheck main             patch-regression  20 regression
  run jsoncheck main             patch-newissue    10 newissue
  # وصله ترکیبی: هم خطا باقی است هم پسرفت عملکردی → اولویت 10 بر 20
  run jsoncheck main             patch-mixed       10 mixed-priority
  # پایه بدون خطای قابل‌بازتولید ولی پسرفت عملکردی واقعی → اولویت 20 بر 40
  run jsoncheck patch-correct    patch-regression  20 fixedbase-regression
  # پایه بدون خطای قابل‌بازتولید و بدون پسرفت → 40
  run jsoncheck patch-regression patch-correct     40 nonrepro
  run jsoncheck main             build-broken      30 buildbroken
  run jsoncheck main             no-such-ref       30 bad-ref
  # سناریوی کور: فقط هش کامیت‌ها (بدون نام شاخه) — پاسخ ابزار نباید وابسته به
  # نام فایل/شاخه/شناسه از پیش شناخته‌شده وصله باشد.
  BH=$(git -C targets/jsoncheck/repo rev-parse --short main)
  PH=$(git -C targets/jsoncheck/repo rev-parse --short patch-incomplete)
  run jsoncheck "$BH"            "$PH"             10 blind-hashes
fi

if [ "$ONLY" = all ] || [ "$ONLY" = imginfo ]; then
  run imginfo   main             patch-correct     0  correct
  run imginfo   main             patch-incomplete  10 incomplete
  run imginfo   main             patch-regression  20 regression
  run imginfo   patch-correct    patch-regression  20 fixedbase-regression
  run imginfo   patch-regression patch-correct     40 nonrepro
  run imginfo   main             build-broken      30 buildbroken
fi

echo "──────────────────────────────────────────────────────"
echo "جمع‌بندی: $PASS موفق، $FAIL ناموفق"
[ "$FAIL" -eq 0 ] || { printf '  ناموفق: %s\n' "${FAILED[@]}"; exit 1; }
exit 0
