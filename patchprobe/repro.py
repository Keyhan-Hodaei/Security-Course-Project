"""بستۀ بازتولید (Reproducer Bundle) و پایداری یافته.

برای هر خطای تأییدشده، در bundles/<هدف>/<run_id>/<شناسه>/ ذخیره می‌شود:
  manifest.json      شناسه دقیق کامیت، هش SHA-256 باینری، دستور و پرچم‌های ساخت،
                     متغیرهای محیطی مؤثر، محدودیت‌ها، فرمان کامل اجرا، نتیجه
                     بازپخش‌ها و نتیجه همان ورودی روی نسخه مقابل
  input.original     ورودی ایجادکننده خطا
  input.minimized    ورودی کوچک‌شده (همان امضا)
  reproduce.sh       اسکریپت مستقل: ساخت مجدد از کامیت، تطبیق هش، ۳ بازپخش
"""
import json
import os
import shlex
import shutil
import time

from .runner import build_argv, effective_env


def replay(binary, input_path, method, limits, sanitized, times=3, run_fn=None):
    """اجرای مجدد برای سنجش پایداری؛ خروجی: {runs: [...], stable, signature_seen}"""
    from . import evidence
    runs, sigs = [], []
    for i in range(times):
        r = run_fn(binary, input_path, method, limits, sanitized)
        ev = evidence.analyze(r)
        sig = evidence.signature(ev) if ev.get("confirmed") else None
        runs.append({"attempt": i + 1,
                     "exit_code": r.get("exit_code"),
                     "signal": r.get("signal") or None,
                     "timed_out": bool(r.get("timed_out")),
                     "signature": sig,
                     "summary": ev.get("summary_line")})
        sigs.append(sig)
    stable = times > 0 and all(s is not None for s in sigs) and len(set(sigs)) == 1
    return {"runs": runs, "stable": stable, "times": times,
            "signature_seen": sigs[0] if stable else None}


REPRO_SH = r"""#!/usr/bin/env bash
# بازتولید مستقل یافته {bid} ({signature}) — تولیدشده خودکار توسط PatchProbe
# استفاده: bash reproduce.sh [مسیر-مخزن-هدف]
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="${{1:-$HERE/{repo}}}"
COMMIT={commit}
WANT_SHA={sha}
WANT_SIG={signature_q}
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
SRC="$WORK/src"; mkdir -p "$SRC"
git -C "$REPO" archive "$COMMIT" | tar -x -C "$SRC" || {{ echo "برون‌بری کامیت شکست خورد"; exit 30; }}
CMD_T={build_template}
CFL={sanitized_flags}" -ffile-prefix-map=$SRC=."
CMD=${{CMD_T//'{{src}}'/$SRC}}; CMD=${{CMD//'{{cflags}}'/$CFL}}
CMD=${{CMD//'{{mode}}'/sanitized}}; CMD=${{CMD//'{{out}}'/$WORK}}
echo "دستور ساخت: $CMD"
( cd "$SRC" && LC_ALL=C SOURCE_DATE_EPOCH=0 bash -c "$CMD" ) > "$WORK/build.log" 2>&1 || {{ echo "ساخت شکست خورد"; tail -20 "$WORK/build.log"; exit 30; }}
GOT_SHA=$(sha256sum "$SRC/{binary}" | cut -d' ' -f1)
if [ "$GOT_SHA" = "$WANT_SHA" ]; then echo "✓ هش باینری با بسته یکسان است: $GOT_SHA"
else echo "⚠ هش باینری متفاوت است (کامپایلر/محیط دیگر): $GOT_SHA ≠ $WANT_SHA"; fi
export {env_exports}
INPUT="$HERE/${{INPUT_KIND:-input.minimized}}"
[ -s "$INPUT" ] || INPUT="$HERE/input.original"
ok=0
for i in 1 2 3; do
  for try in $(seq 12); do  # بازتلاش خرابی راه‌اندازی زمان‌اجرای ASan (مشکل محیط)
    {run_cmd} > "$WORK/out.$i" 2> "$WORK/err.$i"; rc=$?
    grep -q "AddressSanitizer:DEADLYSIGNAL" "$WORK/err.$i" && ! grep -q -E "ERROR: AddressSanitizer|runtime error" "$WORK/err.$i" || break
  done
  line=$(grep -m1 -E "ERROR: AddressSanitizer|runtime error|stack smashing|buffer overflow detected" "$WORK/err.$i")
  echo "بازپخش $i: exit=$rc  $line"
  grep -q -E "{grep_type}" "$WORK/err.$i" && grep -q -E "in {grep_func}[ (]" "$WORK/err.$i" && ok=$((ok+1))
done
echo "تکرار امضای $WANT_SIG در $ok از ۳ بازپخش"
[ "$ok" -eq 3 ]
"""

# نگاشت نوع خطای استاندارد به عبارت خام گزارش Sanitizer (برای grep در اسکریپت)
RAW_TYPE = {
    "HEAP_BUFFER_OVERFLOW": "heap-buffer-overflow",
    "STACK_BUFFER_OVERFLOW": "stack-buffer-overflow|stack smashing",
    "GLOBAL_BUFFER_OVERFLOW": "global-buffer-overflow",
    "USE_AFTER_FREE": "heap-use-after-free",
    "DOUBLE_FREE": "double-free",
    "INDEX_OUT_OF_BOUNDS": "out of bounds",
    "NULL_DEREF": "null pointer|SEGV",
    "DIV_BY_ZERO": "division by zero|FPE",
    "INTEGER_OVERFLOW": "integer overflow",
}


def write_bundle(out_dir, target, finding, replay_result, minimize_result,
                 own_build, other_build, cfg, refs, run_id, cross_version):
    """نوشتن بستۀ بازتولید؛ خروجی: مسیر manifest.json."""
    bid = finding["id"]
    bdir = os.path.join(out_dir, bid)
    os.makedirs(bdir, exist_ok=True)
    orig = os.path.join(bdir, "input.original")
    mini = os.path.join(bdir, "input.minimized")
    shutil.copyfile(finding["input_path"], orig)
    m = minimize_result or {}
    if m.get("minimized_path") and os.path.isfile(m["minimized_path"]):
        shutil.copyfile(m["minimized_path"], mini)

    ev = finding["evidence"]
    version = finding["version"]
    other = "patched" if version == "base" else "base"
    env = effective_env(True)
    binary_name = os.path.basename(own_build["binary"])
    argv = build_argv("./" + binary_name, "INPUT", cfg.input_method)
    run_cmd_display = " ".join(argv) + (" < INPUT" if cfg.input_method == "stdin" else "")
    env_display = " ".join(f"{k}={shlex.quote(v)}" for k, v in env.items())

    manifest = {
        "bundle_id": bid,
        "target": target,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "run_id": run_id,
        "status": finding.get("status"),
        "signature": finding["signature"],
        "error": {
            "type": ev.get("error_type"), "rw": ev.get("rw"), "size": ev.get("size"),
            "mechanism": ev.get("mechanism"), "summary": ev.get("summary_line"),
            "top_frame": ev.get("top"), "stack": ev.get("frames", [])[:12],
        },
        "found_on": {
            "version": version, "ref": refs[version], "commit": own_build.get("commit"),
            "build_mode": "sanitized",
            "binary_sha256": own_build.get("sha256"),
            "build_command": own_build.get("command"),
            "cflags": own_build.get("cflags"),
        },
        "counterpart": {
            "version": other, "ref": refs[other], "commit": other_build.get("commit"),
            "build_mode": "sanitized",
            "binary_sha256": other_build.get("sha256"),
            "build_command": other_build.get("command"),
        },
        "cross_version_same_input": cross_version,
        "environment": {"env_relevant": env, "limits": cfg.limits,
                        "input_method": cfg.input_method},
        "commands": {
            "build": own_build.get("command"),
            "reproduce": f"{env_display} {run_cmd_display}",
            "script": "bash reproduce.sh   # ساخت مجدد از کامیت + تطبیق هش + ۳ بازپخش",
        },
        "inputs": {"original": "input.original",
                   "original_test": finding.get("input"),
                   "minimized": "input.minimized" if os.path.isfile(mini) else None,
                   "original_size": m.get("original_size"),
                   "minimized_size": m.get("minimized_size"),
                   "minimization_calls": m.get("calls"),
                   "minimized_verified_signature": m.get("verified_signature")},
        "replays": replay_result["runs"],
        "stability": {"stable": replay_result["stable"],
                      "times": replay_result.get("times"),
                      "signature": replay_result.get("signature_seen")},
    }
    with open(os.path.join(bdir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    # اسکریپت بازتولید مستقل
    run_argv = build_argv('"$SRC/' + binary_name + '"', '"$INPUT"', cfg.input_method)
    run_cmd = " ".join(run_argv) + (' < "$INPUT"' if cfg.input_method == "stdin" else "")
    etype = ev.get("error_type") or ""
    top = (ev.get("top") or {}).get("func") or ""
    script = REPRO_SH.format(
        bid=bid, signature=finding["signature"],
        signature_q=shlex.quote(finding["signature"]),
        repo=os.path.relpath(cfg.repo, bdir), commit=own_build.get("commit"), sha=own_build.get("sha256"),
        build_template=shlex.quote(cfg.build_command),
        sanitized_flags=shlex.quote(cfg.flags["sanitized"]),
        binary=cfg.binary_relpath,
        env_exports=" ".join(f"{k}={shlex.quote(v)}" for k, v in env.items()),
        run_cmd=run_cmd,
        grep_type=RAW_TYPE.get(etype, etype.lower().replace("_", "[-_ ]")),
        grep_func=top.replace(".", r"\.") or ".")
    sp = os.path.join(bdir, "reproduce.sh")
    with open(sp, "w", encoding="utf-8") as f:
        f.write(script)
    os.chmod(sp, 0o755)
    return os.path.join(bdir, "manifest.json")
