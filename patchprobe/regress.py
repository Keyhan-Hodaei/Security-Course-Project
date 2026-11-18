"""مجموعه آزمون‌های رگرسیون تولیدشده خودکار.

ورودی کوچک‌شده هر خطای تأییدشده روی نسخه پایه به‌صورت خودکار به مجموعه
رگرسیون هدف (regression/<هدف>/suite.json) اضافه می‌شود تا در اجراهای بعدی
پایپ‌لاین بررسی شود. انتظار دولایه هر مدخل:
  - روی نسخه پایه: خطای موردانتظار (همان امضا = نوع خطا/دسترسی + تابع) آشکار شود؛
  - روی نسخه وصله‌شده: همان خطا آشکار نشود.

شناسه مدخل از امضا مشتق می‌شود (R-<sha1 کوتاه امضا>) تا اجراهای مختلف و
سناریوهای مختلف هرگز ورودی یکدیگر را بازنویسی نکنند.

تفسیر شکست‌ها در verify_suite:
  - شکست سمت وصله (امضا روی نسخه وصله‌شده دیده شد) → VULN_REMAINS (کد 10).
  - شکست سمت پایه روی همان کامیتی که مدخل از آن ثبت شده → مدخل کهنه/ناپایدار
    → INCONCLUSIVE (کد 40).
  - شکست سمت پایه روی کامیت پایه دیگری (مثلاً پایه‌ای که این خطا را از قبل
    رفع کرده) → «نامرتبط با این پایه» و فقط اطلاع‌رسانی؛ هنوز سمت وصله بررسی
    می‌شود تا بازگشت (reintroduction) خطا کشف شود.
"""
import hashlib
import json
import os
import shutil
import time


def suite_path(reg_dir, target):
    return os.path.join(reg_dir, target, "suite.json")


def entry_id(signature: str, variant: str = "") -> str:
    key = signature + (f"#{variant}" if variant else "")
    return "R-" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:8]


def load_suite(reg_dir, target):
    p = suite_path(reg_dir, target)
    if not os.path.isfile(p):
        return {"target": target, "entries": []}
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _save(reg_dir, target, suite):
    p = suite_path(reg_dir, target)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(suite, f, indent=2, ensure_ascii=False)
    os.replace(tmp, p)


def add_entry(reg_dir, target, finding, minimize_result, run_id, base_commit,
              variant=""):
    """افزودن/به‌روزرسانی مدخل امضای یافته؛ خروجی: (مدخل, تازه‌افزوده؟).

    variant="bypass" برای شاهد دورزدن یک وصله ناقص است: ورودی متفاوتی با همان
    امضا که از وصله ناقص عبور کرد؛ مدخل جداگانه می‌گیرد تا وصله‌های بعدی هم
    در برابر همین مسیر دورزدن آزموده شوند.
    """
    suite = load_suite(reg_dir, target)
    inputs_dir = os.path.join(reg_dir, target, "inputs")
    os.makedirs(inputs_dir, exist_ok=True)
    sig = finding["signature"]
    eid = entry_id(sig, variant)
    m = minimize_result or {}
    src = m.get("minimized_path") if m.get("verified_signature") == sig else None
    src = src or finding["input_path"]
    dst = os.path.join(inputs_dir, f"{eid}.input")
    new_size = os.path.getsize(src)

    for e in suite["entries"]:
        if e["id"] == eid:
            # فقط اگر ورودی تازه کوچک‌تر است جایگزین شود (همان امضا)
            if not os.path.isfile(dst) or new_size < os.path.getsize(dst):
                shutil.copyfile(src, dst)
                e["input_size"] = new_size
            e["last_seen_run"] = run_id
            prov = {"run_id": run_id, "base_commit": base_commit}
            if base_commit not in {p["base_commit"] for p in e["provenance"]}:
                e["provenance"].append(prov)
            _save(reg_dir, target, suite)
            return e, False

    shutil.copyfile(src, dst)
    entry = {
        "id": eid,
        "added_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "added_run": run_id,
        "input": os.path.relpath(dst, os.path.join(reg_dir, target)),
        "input_size": new_size,
        "original_input": finding.get("input"),
        "variant": variant or "primary",
        "minimized": bool(m.get("success")) and src != finding["input_path"],
        "expect": {
            "signature": sig,
            "error_type": finding["evidence"].get("error_type"),
            "top_function": (finding["evidence"].get("top") or {}).get("func"),
            "on_base": "CRASH_WITH_SIGNATURE",
            "on_patched": "NO_SUCH_SIGNATURE",
        },
        "provenance": [{"run_id": run_id, "base_commit": base_commit}],
        "last_seen_run": run_id,
    }
    suite["entries"].append(entry)
    _save(reg_dir, target, suite)
    return entry, True


def verify_suite(suite, reg_dir, base_binary, patched_binary, cfg, run_fn,
                 base_commit=None):
    """اجرای هر مدخل روی هر دو نسخه (بیلد sanitized) و ارزیابی انتظارها."""
    from . import evidence
    results = []
    for e in suite.get("entries", []):
        input_path = e["input"]
        if not os.path.isabs(input_path):
            input_path = os.path.join(reg_dir, suite["target"], input_path)
        want = e["expect"]["signature"]
        row = {"id": e["id"], "expect": want, "checks": {}}
        if not os.path.isfile(input_path):
            row.update(ok=False, base_applicable=True, missing_input=True)
            results.append(row)
            continue
        for role, binary in (("base", base_binary), ("patched", patched_binary)):
            r = run_fn(binary, input_path, cfg.input_method, cfg.limits, True)
            ev = evidence.analyze(r)
            sig = evidence.signature(ev) if ev.get("confirmed") else None
            ok = (sig == want) if role == "base" else (sig != want)
            row["checks"][role] = {
                "confirmed": bool(ev.get("confirmed")), "signature": sig,
                "exit_code": r.get("exit_code"),
                "timed_out": bool(r.get("timed_out")), "ok": ok,
            }
        recorded = {p.get("base_commit") for p in e.get("provenance", [])}
        row["base_applicable"] = base_commit in recorded if base_commit else True
        row["ok"] = row["checks"]["patched"]["ok"] and (
            row["checks"]["base"]["ok"] or not row["base_applicable"])
        results.append(row)
    return results
