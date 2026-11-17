"""تصمیم نهایی و کد خروج استاندارد.

اولویت کدهای خروج دقیقاً مطابق صورت پروژه (بند ۳.۵):
    «در صورت هم‌زمانی چند وضعیت، اولویت کد خروج به ترتیب 30، 10، 20، 40 و 0 است.»

1. 30 BUILD_OR_CONFIG_ERROR — ساخت/پیکربندی/ابزار خراب است. چون هیچ داوری
   دیگری ممکن نیست، در cli به‌صورت زودهنگام گزارش می‌شود و هرگز با یافتن خطای
   امنیتی یا تأیید وصله جمع نمی‌شود.
2. 10 VULN_REMAINS — خطای قبلی روی نسخه وصله‌شده باقی است (INCOMPLETE_FIX)،
   یا خطای حافظه/امنیتی جدیدی با گواهی معتبر (Sanitizer) تأیید شده است
   (NEW_ISSUE)، یا یک مدخل مجموعه رگرسیون روی نسخه وصله‌شده دوباره آشکار شد.
   یک توقف طبقه‌بندی‌نشده به‌تنهایی هرگز به 10 نمی‌انجامد.
3. 20 FUNC_REGRESSION — دست‌کم یک آزمون عملکردی دارای انتظار (مرجع مستقل)
   که در نسخه پایه موفق بود، در نسخه وصله‌شده شکست خورد؛ مستقل از وضعیت
   خطای امنیتی ثبت می‌شود.
4. 40 INCONCLUSIVE — بررسی الزامی کامل نشد یا شواهد کافی نیست: بازتولیدنشدن
   خطای پایه، یافته ناپایدار، توقف طبقه‌بندی‌نشده، عبور از محدودیت زمان/منابع
   در آزمون، یا مدخل رگرسیونی که روی همان کامیت پایه دیگر بازتولید نمی‌شود.
5. 0 PASS — هیچ‌کدام از موارد بالا؛ یعنی خطای پایه بازتولید شد، در وصله
   دیده نشد، خطای امنیتی دیگری تأیید نشد و همه آزمون‌های عملکردی و
   بررسی‌های الزامی موفق و کامل بودند.

همه وضعیت‌های مستقل (امنیت، عملکرد، کامل‌بودن تحلیل) جدا از کد نهایی در
خروجی «flags» برگردانده می‌شوند تا در JSON باقی بمانند.
"""

PRIORITY = (30, 10, 20, 40, 0)

NAMES = {
    0: "PASS",
    10: "VULN_REMAINS",
    20: "FUNC_REGRESSION",
    30: "BUILD_OR_CONFIG_ERROR",
    40: "INCONCLUSIVE",
}


def _inconclusive_reasons(state: dict) -> list:
    reasons = []
    if not state.get("base_confirmed_findings"):
        reasons.append("هیچ خطای حافظه تأییدشده‌ای روی نسخه پایه در محدوده "
                       "آزمون‌ها بازتولید نشد؛ داوری امنیتی درباره وصله ممکن "
                       "نیست (خطای پایه بازتولید نشد).")
    for f in state.get("unstable_findings") or []:
        reasons.append(f"یافته ناپایدار (در همه بازپخش‌ها همان امضا تکرار نشد): {f}")
    for t in state.get("unclassified_terminations") or []:
        reasons.append(f"توقف طبقه‌بندی‌نشده (بدون گواهی Sanitizer): {t}")
    for t in state.get("resource_limit_events") or []:
        reasons.append(f"عبور از محدودیت زمان/منابع؛ بررسی این آزمون کامل نشد: {t}")
    for t in state.get("stale_suite_entries") or []:
        reasons.append(t)
    if not state.get("mandatory_complete", True):
        reasons.append("بررسی الزامی کامل نشد (اجرای برخی آزمون‌ها ممکن نشد).")
    return reasons


def decide(state: dict) -> dict:
    """ورودی state از cli؛ خروجی {exit_code, name, reasons[], flags{}}.

    flags همه وضعیت‌های مستقل را نگه می‌دارد (مثلاً وصله‌ای که هم خطا را باقی
    گذاشته و هم پسرفت عملکردی دارد: کد 10 و flags.func_regression=True).
    """
    if state.get("build_error"):
        return {"exit_code": 30, "name": NAMES[30],
                "reasons": [state["build_error"]],
                "flags": {"build_or_config_error": True},
                "priority": list(PRIORITY)}

    vuln = list(state.get("vuln_remains") or [])
    func = list(state.get("func_regressions") or [])
    inconc = _inconclusive_reasons(state)

    flags = {
        "build_or_config_error": False,
        "vuln_remains": bool(vuln),
        "func_regression": bool(func),
        "inconclusive": bool(inconc),
    }

    if vuln:
        code, reasons = 10, vuln
    elif func:
        code, reasons = 20, func
    elif inconc:
        code, reasons = 40, inconc
    else:
        code = 0
        reasons = ["خطای هدف روی نسخه پایه بازتولید شد، در نسخه وصله‌شده در "
                   "محدوده آزمون‌ها مشاهده نشد، خطای امنیتی تأییدشده دیگری "
                   "ثبت نشد و همه آزمون‌های عملکردی و بررسی‌های الزامی موفق "
                   "و کامل بودند."]

    # وضعیت‌های هم‌زمانِ کم‌اولویت‌تر هم در دلایل ثبت می‌شوند (بدون تغییر کد)
    secondary = []
    if code == 10 and func:
        secondary += [f"[هم‌زمان، اولویت پایین‌تر — 20] {t}" for t in func]
    if code in (10, 20) and inconc:
        secondary += [f"[هم‌زمان، اولویت پایین‌تر — 40] {t}" for t in inconc]

    return {"exit_code": code, "name": NAMES[code],
            "reasons": reasons + secondary, "flags": flags,
            "priority": list(PRIORITY)}
