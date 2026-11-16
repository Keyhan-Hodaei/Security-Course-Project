"""پویش‌گر سبک توابع C/C++ — نگاشت نام تابع به بازه خطوط.

این پویشگر یک تحلیل‌گر کامپایل نیست؛ یک اکتشاف‌گر ساده سبک کد C است که
برای «پیوند یافته‌ها به تابع تغییرکرده در وصله» کفایت می‌کند. قواعد:

- تابع از خطی شروع می‌شود که در ستون صفر شروع شود، در امضایش «(» باشد،
  به «;» ختم نشود و آکولاد بازِ آن (در همین خط یا خطوط بعدی) در ستون صفر
  با «{» بیاید.
- نام تابع: آخرین شناسه‌ای که در متن امضا بلافاصله پیش از «(» آمده است
  (برای سازوکارهایی مانند CJSON_PUBLIC(...) cJSON_Parse(...) نام درست
  یعنی cJSON_Parse برداشت می‌شود).
- پایان تابع: اولین «}» در ستون صفر پس از آغاز.
"""
import re

SIG_START = re.compile(r"^[A-Za-z_#][\w\s\*&:,()\[\]]*\(")
NAME_BEFORE_PAREN = re.compile(r"([A-Za-z_]\w*)\s*\(")


def scan_functions(source: str):
    """خروجی: فهرست {name, start, end} (شماره خطوط از ۱)."""
    lines = source.splitlines()
    funcs = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if (line.startswith("#") or line.startswith("}")):
            i += 1
            continue
        if SIG_START.match(line) and not line.rstrip().endswith(";") \
                and "=" not in line.split("(")[0]:
            sig = line
            j = i
            # انباشت امضا تا رسیدن به «{» یا «;»
            while j < n and "{" not in lines[j] and ";" not in lines[j] \
                    and not lines[j].startswith("#"):
                sig += "\n" + lines[j]
                j += 1
            if j < n and "{" in lines[j]:
                # نام تابع: آخرین «شناسه(» در متن امضا
                names = NAME_BEFORE_PAREN.findall(sig)
                name = names[-1] if names else None
                if name and name not in ("if", "for", "while", "switch", "return"):
                    # یافتن پایان: «}» در ستون صفر
                    k = j
                    while k < n and not lines[k].startswith("}"):
                        k += 1
                    if k < n:
                        funcs.append({"name": name, "start": i + 1, "end": k + 1})
                        i = k
                        i += 1
                        continue
        i += 1
    return funcs


def function_at(funcs, line: int):
    """تابع دربرگیرنده خط داده‌شده (شماره از ۱) یا None."""
    for f in funcs:
        if f["start"] <= line <= f["end"]:
            return f
    return None


def functions_overlapping(funcs, ranges):
    """توابعی که با یکی از بازه‌های [(s,e)] هم‌پوشانی دارند."""
    out = []
    for f in funcs:
        for s, e in ranges:
            if f["start"] <= e and s <= f["end"]:
                out.append(f)
                break
    return out
