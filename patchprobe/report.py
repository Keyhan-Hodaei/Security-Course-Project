"""گزارش‌دهی: خروجی ساخت‌یافته JSON + خلاصه انسانی (کنسول و Markdown).

گزارش انسانی برای توسعه‌دهنده است؛ همه یافته‌ها، وضعیت‌ها، شواهد، نسخه‌ها و
تنظیمات اجرا در JSON باقی می‌ماند (الزام صورت پروژه). هر دو رندرکننده با
گزارش ناقص (خروج زودهنگام کد 30) هم کار می‌کنند.
"""
import io

STATUS_FA = {
    "FIXED": "برطرف‌شده (در محدوده آزمون‌ها)",
    "INCOMPLETE_FIX": "وصله ناقص / باقی‌مانده",
    "NEW_ISSUE": "خطای تازه مشاهده‌شده",
    "FUNC_REGRESSION": "پسرفت عملکردی",
    "INCONCLUSIVE": "نامشخص (شواهد ناکافی)",
}

CORR_FA = {
    "STRONG": "پیوند قوی (قاب نخست در تابع تغییرکرده)",
    "MODERATE": "پیوند متوسط (تابع تغییرکرده در پشته)",
    "SAME_FILE": "هم‌پوشانی فقط در سطح فایل",
    "NONE": "بدون پیوند قابل‌اتکا (Inconclusive)",
}

VARIANT_FA = {
    "base_release": "پایه/عادی", "base_sanitized": "پایه/ابزارگذاری‌شده",
    "patched_release": "وصله/عادی", "patched_sanitized": "وصله/ابزارگذاری‌شده",
}


def _short(c):
    return (c or "?")[:10]


def _term(v):
    if not v:
        return "—"
    if v.get("timed_out"):
        return "TIMEOUT"
    s = f"exit={v.get('exit_code')}"
    if v.get("signal"):
        s = f"signal={v['signal']}"
    if v.get("mechanism"):
        s += f" [{v['mechanism']}]"
    return s


def render_console(jr: dict) -> str:
    """خلاصه انسانی برای کنسول/پایپ‌لاین."""
    buf = io.StringIO()
    w = buf.write
    v = jr.get("verdict", {})
    commits = jr.get("commits") or {}
    refs = jr.get("refs") or {}
    w("=" * 74 + "\n")
    w(f"PatchProbe — اعتبارسنجی وصله «{jr.get('target', '?')}»\n")
    w(f"  پایه: {refs.get('base')} ({_short(commits.get('base'))})   "
      f"وصله: {refs.get('patched')} ({_short(commits.get('patched'))})\n")
    w(f"  نتیجه: {v.get('name')} (کد خروج {v.get('exit_code')})\n")
    for r in v.get("reasons", []):
        w(f"    - {r}\n")
    flags = v.get("flags") or {}
    if flags:
        on = [k for k, val in flags.items() if val]
        w(f"  وضعیت‌های مستقل: {', '.join(on) if on else 'هیچ'}\n")
    w("-" * 74 + "\n")
    summ = jr.get("summary") or {}
    if summ.get("runs_total"):
        w(f"اجراها: {summ['runs_total']} اجرا روی ۲ نسخه × ۲ بیلد (release/sanitized)\n")
    if jr.get("findings"):
        w("یافته‌ها:\n")
        for f in jr["findings"]:
            ev = f.get("evidence") or {}
            w(f"  [{f['status']}] {f['id']}: {ev.get('error_type')}"
              f" ({ev.get('rw') or '-'}) توسط {ev.get('mechanism')}\n")
            top = ev.get("top") or {}
            w(f"      محل: {top.get('func')} @ {top.get('file')}:{top.get('line')}"
              f" | ورودی: {f.get('input')}\n")
            corr = f.get("correlation") or {}
            w(f"      پیوند با وصله: {CORR_FA.get(corr.get('status'), '?')}\n")
            if f.get("witness"):
                w(f"      شاهد دورزدن روی وصله: {f['witness'].get('input')}\n")
            rv = f.get("release_view") or {}
            if rv:
                w(f"      بیلد عادی: پایه {_term(rv.get('base_release'))} | "
                  f"وصله {_term(rv.get('patched_release'))}\n")
    elif summ.get("runs_total"):
        w("یافته‌ای ثبت نشد.\n")
    if jr.get("func_results"):
        bad = [t for t in jr["func_results"] if not t["ok"]]
        w(f"آزمون‌های عملکردی (مرجع مستقل): {len(jr['func_results'])} مورد، "
          f"ناموفق: {len(bad)}\n")
        for t in bad:
            mark = "✗ پسرفت" if t.get("regression") else "✗"
            w(f"  {mark} {t['name']}: پایه=[{t['base']}] وصله=[{t['patched']}]\n")
    an = jr.get("anomalies") or {}
    for key, label in (("unclassified_terminations", "توقف طبقه‌بندی‌نشده"),
                       ("protection_only_detections", "تشخیص فقط با محافظ باینری"),
                       ("resource_limit_events", "عبور از محدودیت منابع/زمان")):
        for item in an.get(key, []):
            w(f"  ! {label}: {item}\n")
    h = jr.get("hardening") or {}
    if h.get("base") and h.get("patched"):
        hb, hp = h["base"], h["patched"]
        w("سخت‌سازی (release): ")
        for k, label in (("pie", "PIE"), ("nx", "NX"), ("stack_canary", "Canary")):
            key = "present" if k == "stack_canary" else "enabled"
            w(f"{label}={'✓' if hb[k][key] else '✗'}")
            if hb[k][key] != hp[k][key]:
                w(f"→{'✓' if hp[k][key] else '✗'}")
            w("  ")
        w(f"RELRO={hb['relro']['level']}"
          + (f"→{hp['relro']['level']}" if hb["relro"]["level"] != hp["relro"]["level"] else "")
          + "\n")
        for warn in (h.get("comparison") or {}).get("warnings", []):
            w(f"  ⚠ {warn}\n")
    rs = jr.get("regression_suite")
    if rs:
        w(f"مجموعه رگرسیون: {rs['total']} مدخل، تأیید این اجرا: "
          f"{rs['verified_ok']}/{rs['total']}"
          + (f"، تازه: {', '.join(rs['added'])}" if rs.get("added") else "") + "\n")
    if jr.get("bundles"):
        w(f"بسته‌های بازتولید: {len(jr['bundles'])} عدد در {jr.get('bundles_dir')}\n")
    if jr.get("duration_sec") is not None:
        w(f"مدت اجرا: {jr['duration_sec']} ثانیه\n")
    w("=" * 74 + "\n")
    return buf.getvalue()


def render_markdown(jr: dict) -> str:
    """گزارش تفصیلی Markdown برای بایگانی اجرای پایپ‌لاین."""
    buf = io.StringIO()
    w = buf.write
    v = jr.get("verdict", {})
    commits = jr.get("commits") or {}
    subjects = jr.get("subjects") or {}
    refs = jr.get("refs") or {}
    w(f"# گزارش PatchProbe — {jr.get('target', '?')}\n\n")
    w(f"- اجرا: `{jr.get('run_id')}` (PatchProbe {jr.get('tool_version')})\n"
      f"- نسخه پایه: `{refs.get('base')}` ({(commits.get('base') or '?')[:12]}"
      f" — «{subjects.get('base', '')}»)\n"
      f"- نسخه وصله‌شده: `{refs.get('patched')}` ({(commits.get('patched') or '?')[:12]}"
      f" — «{subjects.get('patched', '')}»)\n"
      f"- **نتیجه: {v.get('name')} (کد خروج {v.get('exit_code')})**\n\n")
    w("## دلایل نتیجه\n\n")
    for r in v.get("reasons", []):
        w(f"- {r}\n")
    if v.get("flags"):
        w("\n| وضعیت مستقل | مقدار |\n|---|---|\n")
        for k, val in v["flags"].items():
            w(f"| {k} | {'✓' if val else '—'} |\n")
    if jr.get("interpretation"):
        w("\n## تفسیر وضعیت‌ها\n\n")
        for line in jr["interpretation"]:
            w(f"- {line}\n")

    if jr.get("summary", {}).get("runs_total"):
        w("\n## یافته‌ها\n\n")
        if jr.get("findings"):
            w("| شناسه | وضعیت | نوع خطا | سازوکار | محل (بیلد ابزارگذاری‌شده) | "
              "ورودی | پیوند با diff |\n|---|---|---|---|---|---|---|\n")
            for f in jr["findings"]:
                ev = f.get("evidence") or {}
                top = ev.get("top") or {}
                corr = f.get("correlation") or {}
                w(f"| {f['id']} | {STATUS_FA.get(f['status'], f['status'])} | "
                  f"{ev.get('error_type')} {ev.get('rw') or ''} | "
                  f"{ev.get('mechanism')} | "
                  f"{top.get('func')} @ {top.get('file')}:{top.get('line')} | "
                  f"`{f.get('input')}` | {CORR_FA.get(corr.get('status'), corr.get('status'))} |\n")
            for f in jr["findings"]:
                ev = f.get("evidence") or {}
                w(f"\n### {f['id']} — {STATUS_FA.get(f['status'], f['status'])} — "
                  f"`{f['signature']}`\n\n")
                w(f"- معیار: {f.get('why')}\n")
                w(f"- خلاصه گواهی: `{ev.get('summary_line')}`\n")
                if ev.get("frames"):
                    stack = " ← ".join(f"{fr.get('func')}" for fr in ev["frames"][:6])
                    w(f"- پشته فراخوانی: {stack}\n")
                w(f"- ورودی‌های بروز: {', '.join(f.get('inputs', []))}\n")
                corr = f.get("correlation") or {}
                w(f"- شاهد پیوند: {corr.get('evidence')}\n")
                w(f"- توابع تغییرکرده وصله: "
                  f"{', '.join(corr.get('changed_functions') or []) or '—'}\n")
                d = corr.get("differential") or {}
                if d:
                    w(f"- شاهد تفاضلی (همان ورودی روی دو نسخه): {d.get('note')}\n")
                rv = f.get("release_view") or {}
                if rv:
                    w("- نحوه خاتمه در ۴ بیلد:\n")
                    for var in ("base_release", "base_sanitized",
                                "patched_release", "patched_sanitized"):
                        w(f"  - {VARIANT_FA[var]}: {_term(rv.get(var))}\n")
                if f.get("replay"):
                    rp = f["replay"]
                    w(f"- پایداری: {'پایدار' if rp['stable'] else 'ناپایدار'} "
                      f"({len(rp['runs'])} بازپخش: "
                      f"{', '.join(str(r.get('signature')) for r in rp['runs'])})\n")
                if f.get("minimize"):
                    m = f["minimize"]
                    w(f"- کوچک‌سازی: {m['original_size']} → {m['minimized_size']} بایت "
                      f"({m['calls']} اجرا؛ امضای تأییدشده: {m.get('verified_signature')})\n")
                if f.get("bundle"):
                    w(f"- بسته بازتولید: `{f['bundle']}`\n")
                if f.get("regression_entry"):
                    w(f"- مدخل رگرسیون: `{f['regression_entry']}`\n")
                wt = f.get("witness")
                if wt:
                    w(f"- **شاهد دورزدن وصله** (روی نسخه وصله‌شده هنوز خطا می‌دهد): "
                      f"`{wt.get('input')}`")
                    wm = wt.get("minimize") or {}
                    if wm:
                        w(f" — کوچک‌سازی روی وصله: {wm.get('original_size')} → "
                          f"{wm.get('minimized_size')} بایت")
                    w("\n")
                    if wt.get("bundle"):
                        w(f"  - بسته بازتولید روی وصله: `{wt['bundle']}`\n")
                    if wt.get("regression_entry"):
                        w(f"  - مدخل رگرسیون دورزدن: `{wt['regression_entry']}`\n")
        else:
            w("یافته‌ای ثبت نشد.\n")

        an = jr.get("anomalies") or {}
        if any(an.get(k) for k in an):
            w("\n## رخدادهای بدون گواهی کافی\n\n")
            for key, label in (("unclassified_terminations", "توقف طبقه‌بندی‌نشده"),
                               ("protection_only_detections", "تشخیص فقط با محافظ باینری"),
                               ("resource_limit_events", "عبور از محدودیت زمان/منابع"),
                               ("unstable_findings", "یافته ناپایدار")):
                for item in an.get(key, []):
                    w(f"- {label}: {item}\n")

        w("\n## آزمون‌های عملکردی (مرجع مستقل)\n\n")
        if jr.get("func_results"):
            w("| آزمون | دسته | انتظار | پایه | وصله | وضعیت |\n|---|---|---|---|---|---|\n")
            for t in jr["func_results"]:
                status = "✓" if t["ok"] else ("✗ پسرفت" if t.get("regression")
                                              else "✗ (پایه هم مطابق مرجع نبود)")
                w(f"| `{t['name']}` | {t.get('kind')} | exit={t['expect_exit']}"
                  f"{' «' + str(t['expect_stdout']) + '»' if t.get('expect_stdout') else ''} | "
                  f"{t['base']} | {t['patched']} | {status} |\n")

        tests = jr.get("tests") or {}
        if tests:
            w("\n## ماتریس اجرای کامل (۴ بیلد، تنظیمات یکسان)\n\n")
            w("| آزمون | دسته | پایه/عادی | پایه/sanitized | وصله/عادی | وصله/sanitized |\n"
              "|---|---|---|---|---|---|\n")
            for name, t in tests.items():
                r = t["results"]

                def cell(x):
                    s = "TIMEOUT" if x["timed_out"] else (
                        f"sig={x['signal']}" if x.get("signal") else f"exit={x['exit_code']}")
                    return s + (f" **{x['signature']}**" if x.get("signature") else "")
                w(f"| `{name}` | {t['kind']} | {cell(r['base_release'])} | "
                  f"{cell(r['base_sanitized'])} | {cell(r['patched_release'])} | "
                  f"{cell(r['patched_sanitized'])} |\n")

    h = jr.get("hardening")
    if h and h.get("base"):
        w("\n## سخت‌سازی باینری (بیلد عادی)\n\n")
        w("| محافظت | پایه | وصله | شاهد پایه | شاهد وصله |\n|---|---|---|---|---|\n")
        hb, hp = h["base"], h["patched"]
        rows = (("PIE", "pie", "enabled"), ("NX", "nx", "enabled"),
                ("Stack Canary", "stack_canary", "present"))
        for label, k, key in rows:
            w(f"| {label} | {'✓' if hb[k][key] else '✗'} | {'✓' if hp[k][key] else '✗'} | "
              f"{hb[k]['evidence']} | {hp[k]['evidence']} |\n")
        w(f"| RELRO | {hb['relro']['level']} | {hp['relro']['level']} | "
          f"{hb['relro']['evidence']} | {hp['relro']['evidence']} |\n")
        if hb.get("fortify_source"):
            w(f"| FORTIFY (تکمیلی) | {'✓' if hb['fortify_source']['present'] else '✗'} | "
              f"{'✓' if hp['fortify_source']['present'] else '✗'} | "
              f"{hb['fortify_source']['evidence']} | {hp['fortify_source']['evidence']} |\n")
        for warn in (h.get("comparison") or {}).get("warnings", []):
            w(f"\n- ⚠ {warn}\n")
        for c in hb.get("caveats", []):
            w(f"- نکته: {c}\n")

    summ = jr.get("summary") or {}
    if summ.get("runs_total"):
        w("\n## اجراهای ثبت‌شده\n\n")
        w(f"مجموع {summ['runs_total']} اجرای برنامه هدف "
          f"({summ.get('runs_release')} بیلد عادی، {summ.get('runs_sanitized')} بیلد "
          f"ابزارگذاری‌شده)؛ آزمون‌ها: {summ.get('tests')}.\n")
    rs = jr.get("regression_suite")
    if rs:
        w("\n## مجموعه آزمون رگرسیون\n\n")
        w(f"- مدخل‌های موجود: {rs['total']} (در `{rs.get('dir')}`)\n"
          f"- تأییدشده در این اجرا: {rs['verified_ok']}\n"
          f"- مدخل‌های جدید این اجرا: {', '.join(rs.get('added', [])) or '—'}\n")
        for row in rs.get("verification", []):
            chk = row.get("checks") or {}
            na = "" if row.get("base_applicable", True) else " (پایه دیگری؛ سمت پایه فقط اطلاعاتی)"
            w(f"  - `{row['id']}` {row['expect']}: {'✓' if row['ok'] else '✗'} "
              f"(پایه: {(chk.get('base') or {}).get('signature')}, "
              f"وصله: {(chk.get('patched') or {}).get('signature')}){na}\n")

    w("\n## شواهد و تنظیمات\n\n")
    builds = jr.get("builds") or {}
    for k, b in builds.items():
        w(f"- `{k}`: sha256=`{b.get('sha256')}` — `{b.get('command')}`\n")
    if jr.get("environment"):
        w(f"- محیط اجرا: `{jr['environment']}`\n")
    w(f"- فایل پیکربندی: `{jr.get('config_path')}`\n")
    if jr.get("diff_stat"):
        w(f"\n### آمار diff\n\n```\n{jr['diff_stat']}\n```\n")
    return buf.getvalue()
