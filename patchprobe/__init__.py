"""PatchProbe — اعتبارسنجی خودکار وصله‌های امنیتی و آزمون رگرسیون در CI/CD.

پروژه درس امنیت داده و شبکه — دانشگاه صنعتی شریف.
"""
import os

__version__ = "1.1.0"

# ------------------------------------------------------------------ کدهای خروج
# 0   PASS               وصله معتبر: خطای پایه بازتولید شد و در نسخه وصله‌شده
#                       در محدوده آزمون‌ها دیده نشد؛ آزمون عملکردی موفق.
# 10  VULN_REMAINS      خطای قبلی همچنان رخ می‌دهد یا خطای امنیتی جدید (NEW_ISSUE)
#                       با شواهد معتبر تأیید شد.
# 20  FUNC_REGRESSION   حداقل یک آزمون عملکردی معتبر که در نسخه پایه موفق بود
#                       در نسخه وصله‌شده شکست خورد (مستقل از وضعیت خطای امنیتی).
# 30  BUILD_OR_CONFIG_ERROR  برنامه هدف ساخته نمی‌شود، پیکربندی ناقص یا خطای ابزار/محیط.
# 40  INCONCLUSIVE      بررسی الزامی کامل نشد یا شواهد برای داوری کافی نیست
#                       (بازتولید نشدن خطای پایه، یافته ناپایدار، توقف طبقه‌بندی‌نشده).
#
# اولویت در هم‌زمانی (صورت پروژه، بند ۳.۵): 30، 10، 20، 40، 0 — verdict.py
EXIT_PASS = 0
EXIT_VULN_REMAINS = 10
EXIT_FUNC_REGRESSION = 20
EXIT_BUILD_OR_CONFIG_ERROR = 30
EXIT_INCONCLUSIVE = 40

EXIT_CODE_NAMES = {
    EXIT_PASS: "PASS",
    EXIT_VULN_REMAINS: "VULN_REMAINS",
    EXIT_FUNC_REGRESSION: "FUNC_REGRESSION",
    EXIT_BUILD_OR_CONFIG_ERROR: "BUILD_OR_CONFIG_ERROR",
    EXIT_INCONCLUSIVE: "INCONCLUSIVE",
}


def project_root_from(path: str) -> str:
    """ریشه پروژه از مسیر فایل پیکربندی: اولین والد دارای targets/ یا patchprobe/."""
    d = os.path.dirname(os.path.abspath(path))
    for _ in range(4):
        if os.path.isdir(os.path.join(d, "targets")) or os.path.isdir(os.path.join(d, "patchprobe")):
            return d
        d = os.path.dirname(d)
    return os.path.dirname(os.path.abspath(path))
