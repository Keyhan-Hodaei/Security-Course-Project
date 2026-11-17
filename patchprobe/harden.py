"""بررسی سخت‌سازی باینری ELF: NX، PIE، سطح RELRO و Stack Canary.

شواهد از readelf گرفته می‌شود (نه از نام فایل یا حدس):
- PIE   از نوع فایل (ET_DYN در مقایسه با ET_EXEC)
- NX    از نشانگر PT_GNU_STACK (RWE یعنی غیرفعال)
- RELRO از وجود PT_GNU_RELRO + پرچم BIND_NOW (کامل/جزئی/بدون)
- Canary از حضور نماد __stack_chk_fail در نمادهای پویا

هشدارهای مهم (مطابق صورت پروژه):
- وجود PIE به‌معنای فعال‌بودن ASLR در محیط اجرا نیست؛
- وجود نماد قناری به‌معنای محافظت همه توابع نیست.
"""
import re
import subprocess


def _readelf(binary, *args):
    r = subprocess.run(["readelf", "-W", *args, binary],
                       capture_output=True, text=True)
    return r.stdout


def check_hardening(binary: str) -> dict:
    hdr = _readelf(binary, "-h")
    phdrs = _readelf(binary, "-l")
    dyn = _readelf(binary, "-d")
    syms = _readelf(binary, "--dyn-syms")
    if "__stack_chk_fail" not in syms:
        # باینری ایستا یا بدون نماد پویا: جدول نماد کامل هم بررسی شود
        syms += _readelf(binary, "-s")

    pie = re.search(r"Type:\s+(\w+)", hdr)
    pie_val = pie.group(1) if pie else "?"
    is_pie = pie_val == "DYN"

    # NX: وجود GNU_STACK با مجوز اجرا (E) یعنی NX غیرفعال
    stack_flags = None
    for line in phdrs.splitlines():
        if "GNU_STACK" not in line:
            continue
        # ستون پرچم‌ها: توکنی که فقط از حروف R/W/E تشکیل شده است
        for tok in line.split():
            if tok and all(c in "RWE" for c in tok):
                stack_flags = tok
                break
        break
    if stack_flags is None:
        # نبود PT_GNU_STACK یعنی هسته پشته را اجرایی فرض می‌کند → NX غیرفعال
        nx, stack_flags = False, "بدون نشانگر GNU_STACK (پشته اجرایی پیش‌فرض)"
    else:
        nx = "E" not in stack_flags

    # RELRO
    has_relro_seg = "GNU_RELRO" in phdrs
    bind_now = bool(re.search(r"(BIND_NOW|FLAGS_1.*NOW|FLAGS.*NOW)", dyn))
    if has_relro_seg and bind_now:
        relro = "full"
    elif has_relro_seg:
        relro = "partial"
    else:
        relro = "none"

    # Stack Canary
    canary = "__stack_chk_fail" in syms
    # FORTIFY_SOURCE (اطلاعات تکمیلی؛ جزء چهار محافظت الزامی نیست)
    fortified = sorted(set(re.findall(r"\b(__\w+_chk)\b", syms)) - {"__stack_chk_fail"})

    return {
        "binary": binary,
        "pie": {"enabled": is_pie, "evidence": f"ELF type: {pie_val}"},
        "nx": {"enabled": nx, "evidence": f"GNU_STACK flags: {stack_flags or 'بدون نشانگر'}"},
        "relro": {"level": relro,
                  "evidence": (f"PT_GNU_RELRO={'موجود' if has_relro_seg else 'ناموجود'}؛ "
                               f"BIND_NOW={'بله' if bind_now else 'خیر'}")},
        "stack_canary": {"present": canary,
                         "evidence": ("نماد __stack_chk_fail در نمادهای پویا"
                                      if canary else
                                      "نماد __stack_chk_fail یافت نشد")},
        "fortify_source": {"present": bool(fortified),
                           "evidence": (", ".join(fortified[:6]) if fortified
                                        else "هیچ تابع ‎__*_chk یافت نشد")},
        "caveats": [
            "وجود PIE به‌معنای فعال‌بودن ASLR در محیط اجرا نیست.",
            "حضور نماد قناری به‌معنای محافظت همه توابع نیست.",
        ],
    }


def compare(base: dict, patched: dict) -> dict:
    """مقایسه وضعیت محافظت‌ها بین دو نسخه و هشدار تضعیف."""
    changes, warnings = [], []
    for key in ("pie", "nx", "stack_canary"):
        b, p = base[key]["enabled" if key != "stack_canary" else "present"], \
               patched[key]["enabled" if key != "stack_canary" else "present"]
        if b != p:
            changes.append({"protection": key, "base": b, "patched": p})
            if p is False or p == "none":
                warnings.append(
                    f"تضعیف محافظت {key.upper()} در نسخه وصله‌شده "
                    f"({base[key].get('evidence')} → {patched[key].get('evidence')})")
    if base["relro"]["level"] != patched["relro"]["level"]:
        changes.append({"protection": "relro", "base": base["relro"]["level"],
                        "patched": patched["relro"]["level"]})
        order = {"none": 0, "partial": 1, "full": 2}
        if order[patched["relro"]["level"]] < order[base["relro"]["level"]]:
            warnings.append(f"افت سطح RELRO: {base['relro']['level']} → "
                            f"{patched['relro']['level']}")
    return {"changed": changes, "warnings": warnings}
