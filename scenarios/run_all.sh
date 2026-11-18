#!/usr/bin/env bash
# Run all PatchProbe evaluation scenarios and verify expected exit codes.
# Usage: bash scenarios/run_all.sh [jsoncheck|imginfo|all]
#
# Each scenario must return its exact expected code, not merely execute.
# Scenario outputs: reports/<target>/<scenario>/{report.json,report.md,console.log}
# Reproduction bundles: bundles/<target>/<scenario>/. The regression/ suite
# is shared between scenarios, matching actual pipeline behavior.
set -u
cd "$(dirname "$0")/.."
PASS=0; FAIL=0; FAILED=()
ONLY="${1:-all}"
PY="${PYTHON:-python3}"

bash scripts/setup_targets.sh >/dev/null || { echo "Failed to restore target repositories"; exit 1; }

run () {  # run <target> <base> <patched> <expected-code> <scenario-name> [config]
  local target="$1" base="$2" patched="$3" want="$4" name="$5"
  local cfg="${6:-targets/$target/config.json}"
  local out="reports/$target/$name"
  rm -rf "$out" "bundles/$target/$name"; mkdir -p "$out"
  echo "──────────────────────────────────────────────────────"
  echo "▶ [$target] $name  (base: $base → patched: $patched; expected: $want)"
  "$PY" -m patchprobe --config "$cfg" \
      --base-ref "$base" --patched-ref "$patched" \
      --out-json "$out/report.json" --out-md "$out/report.md" \
      --bundles-dir "bundles/$target/$name" > "$out/console.log" 2>&1
  local got=$?
  if [ "$got" -eq "$want" ]; then
    echo "  ✓ Exit code $got (as expected)"
    PASS=$((PASS+1))
  else
    echo "  ✗ Exit code $got ≠ expected $want — log tail:"
    tail -25 "$out/console.log" | sed 's/^/    /'
    FAIL=$((FAIL+1)); FAILED+=("$target/$name")
  fi
}

if [ "$ONLY" = all ] || [ "$ONLY" = jsoncheck ]; then
  run jsoncheck main             patch-correct     0  correct
  run jsoncheck main             patch-incomplete  10 incomplete
  run jsoncheck main             patch-regression  20 regression
  run jsoncheck main             patch-newissue    10 newissue
  # Mixed patch: remaining issue and functional regression → 10 takes priority over 20
  run jsoncheck main             patch-mixed       10 mixed-priority
  # No reproducible base issue, but a genuine regression → 20 takes priority over 40
  run jsoncheck patch-correct    patch-regression  20 fixedbase-regression
  # No reproducible base issue and no regression → 40
  run jsoncheck patch-regression patch-correct     40 nonrepro
  run jsoncheck main             build-broken      30 buildbroken
  run jsoncheck main             no-such-ref       30 bad-ref
  # Blind scenario: only revision hashes, without branch names. The verdict must
  # not depend on filenames, branch labels, or known patch identifiers.
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
echo "Summary: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || { printf '  Failed: %s\n' "${FAILED[@]}"; exit 1; }
exit 0
