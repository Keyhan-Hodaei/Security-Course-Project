"""پیوند یافته‌ها به تغییرات وصله (Patch-to-Finding Correlation).

منطق پیوند (شواهد، از قوی به ضعیف):
1. STRONG  — قاب نخست خطا در تابعی است که در وصله تغییر کرده است.
2. MODERATE — تابع تغییرکرده در عمق پشته اجرای خطا حضور دارد.
3. SAME_FILE — فقط فایلِ خطا در وصله تغییر کرده (تابع تغییر نکرده).
4. NONE — هیچ هم‌پوشانی؛ «ارتباط نامشخص (Inconclusive)» گزارش می‌شود.

تذکرات صورت پروژه که اینجا رعایت شده:
- محل خطا لزوماً روی خط تغییرکرده نیست؛ تغییر در فراخواننده می‌تواند بر
  تابع دیگر اثر بگذارد ⇒ به همین دلیل قاب‌های میانی پشته هم شواهدند.
- هم‌جواری ظاهری یک هشدار ایستا با محل تغییر، به‌تنهایی کافی نیست ⇒
  بدون شاهد اجرایی، پیوند «نامشخص» است.
"""
import os

from .cparse import scan_functions, functions_overlapping


def enrich_diff_with_functions(diff: dict, base_dir: str, patched_dir: str) -> dict:
    """افزودن نام توابع تغییرکرده به diff_hunks (از روی هر دو نسخه فایل)."""
    for path, info in diff["files"].items():
        for side, src_root, ranges, key in (
            ("old", base_dir, info["old_ranges"], "old_functions"),
            ("new", patched_dir, info["new_ranges"], "new_functions"),
        ):
            full = os.path.join(src_root, path)
            if os.path.isfile(full):
                with open(full, encoding="utf-8", errors="replace") as f:
                    funcs = scan_functions(f.read())
                info[key] = [f["name"] for f in functions_overlapping(funcs, ranges)]
            else:
                info[key] = []
    return diff


def differential(finding: dict, row_runs: dict) -> dict:
    """شاهد تفاضلی: همان ورودی با تنظیمات متناظر روی هر دو نسخه.

    row_runs: {variant: evidence-dict} برای ورودی نماینده یافته. خروجی خلاصه‌ای
    از اینکه همان امضا روی هر نسخه/بیلد دیده شد یا نه، و تفسیر آن.
    """
    from .evidence import signature
    sig = finding["signature"]
    seen = {}
    for variant, ev in row_runs.items():
        s = signature(ev) if ev.get("confirmed") else None
        seen[variant] = {"signature": s, "same": s == sig,
                         "mechanism": ev.get("mechanism")}
    b, p = seen.get("base_sanitized", {}), seen.get("patched_sanitized", {})
    if b.get("same") and not p.get("same"):
        note = "همان ورودی: خطا روی پایه هست و روی وصله نیست — تغییر رفتار ناشی از وصله"
    elif p.get("same") and not b.get("same"):
        note = "همان ورودی: خطا فقط پس از وصله ظاهر شد — رفتار جدید ناشی از تغییرات وصله"
    elif b.get("same") and p.get("same"):
        note = "همان ورودی روی هر دو نسخه همان امضا را می‌دهد — وصله این مسیر را نبسته است"
    else:
        note = "ورودی نماینده روی هیچ‌یک از دو نسخه همان امضا را نداد"
    return {"by_variant": seen, "note": note}


def correlate(finding: dict, diff: dict) -> dict:
    """پیوند یک یافته (با قاب‌هایش) به توابع/فایل‌های تغییرکرده."""
    frames = [f for f in finding["evidence"].get("frames", []) if f.get("func")]
    changed_funcs = set()
    changed_files = set()
    for path, info in diff["files"].items():
        changed_files.add(os.path.basename(path))
        for k in ("old_functions", "new_functions"):
            changed_funcs.update(info.get(k) or [])

    top = finding["evidence"].get("top") or {}
    top_func = top.get("func")
    matched_frames = []
    for f in frames:
        if f["func"] in changed_funcs:
            matched_frames.append(f)

    if top_func and top_func in changed_funcs:
        status, why = "STRONG", (f"قاب نخست خطا در تابع تغییرکرده «{top_func}» است")
    elif matched_frames:
        status = "MODERATE"
        why = "توابع تغییرکرده در پشته اجرای خطا حضور دارند: " + \
              ", ".join(sorted({f['func'] for f in matched_frames}))
    elif top.get("file") and top["file"] in changed_files:
        status, why = "SAME_FILE", (
            f"فایل «{top['file']}» در وصله تغییر کرده اما تابع محل خطا "
            f"«{top_func or '؟'}» مستقیماً تغییر نکرده است")
    else:
        status, why = "NONE", (
            "هیچ تابع یا فایل تغییرکرده وصله با محل خطا هم‌پوشانی ندارد؛ "
            "ارتباط وصله با این یافته نامشخص (Inconclusive) است")

    return {
        "status": status,
        "evidence": why,
        "changed_functions": sorted(changed_funcs),
        "changed_files": sorted(changed_files),
        "matched_frames": matched_frames[:6],
    }


def classify_findings(base_findings, patched_findings) -> list:
    """دسته‌بندی یافته‌ها: FIXED / INCOMPLETE_FIX / NEW_ISSUE / UNCHANGED.

    base_findings, patched_findings: فهرست یافته‌ها با امضا (signature)
    و آزمون مولد (input). تطبیق در سطح امضا انجام می‌شود و جزئیات هر
    ورودی هم ثبت می‌گردد.
    """
    base_sigs = {f["signature"]: f for f in base_findings}
    patched_sigs = {f["signature"]: f for f in patched_findings}
    out = []
    for sig, f in base_sigs.items():
        if sig in patched_sigs:
            pf = patched_sigs[sig]
            out.append({**f, "status": "INCOMPLETE_FIX",
                        "patched_inputs": pf.get("inputs", []),
                        # شاهد دورزدن وصله: ورودی‌ای که روی نسخه وصله‌شده هنوز خطا می‌دهد
                        "witness": {"id": pf.get("id"), "input": pf.get("input"),
                                    "input_path": pf.get("input_path"),
                                    "evidence": pf.get("evidence")},
                        "why": "همان امضای خطا در نسخه وصله‌شده نیز مشاهده شد"})
        else:
            out.append({**f, "status": "FIXED",
                        "patched_inputs": [],
                        "why": "در محدوده آزمون‌های تعریف‌شده دیگر مشاهده نشد"})
    for sig, pf in patched_sigs.items():
        if sig not in base_sigs:
            out.append({**pf, "status": "NEW_ISSUE",
                        "base_inputs": [],
                        "why": "امضای خطایی که در نسخه پایه وجود نداشت"})
    return out
