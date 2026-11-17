"""تحلیل شواهد اجرا: دسته‌بندی نوع خطا، سازوکار تشخیص و قاب‌های پشته.

خروجی تحلیل مشخص می‌کند آیا اجرا «خطای حافظه تأییدشده» است یا فقط یک خاتمه
طبقه‌بندی‌نشده، و قاب‌های پشته آن را برای پیوند با diff استخراج می‌کند.

سازوکارهای تشخیص (Detection Mechanism) که از هم جدا گزارش می‌شوند:
  sanitizer:ASan / sanitizer:UBSan       — گواهی ابزار تشخیص خطا (بیلد sanitized)
  protection:stack-canary                — «*** stack smashing detected ***» یعنی
                                           فراخوانی __stack_chk_fail (بیلد عادی)
  protection:fortify-source              — «*** buffer overflow detected ***» یعنی
                                           __chk_fail از FORTIFY_SOURCE (بیلد عادی)
  signal:SIGSEGV / SIGABRT / ...         — فقط سیگنال سیستم‌عامل، بدون گواهی
  resource-limit:timeout / SIGXCPU / ... — عبور از محدودیت زمان یا منابع

نوع خطا (Error Type) با علت ریشه‌ای یکی نیست؛ اینجا فقط نوع مشاهده‌شده ثبت
می‌شود.
"""
import os
import re
import signal as _signal

# ---------------------------------------------------------------------------
ASAN_ERR = re.compile(r"ERROR: AddressSanitizer: ([\w-]+(?: [\w-]+)?)")
ASAN_ADDR = re.compile(r"on (?:unknown )?address (0x[0-9a-f]+)")
ASAN_RW = re.compile(r"^(READ|WRITE) of size (\d+)", re.M)
ASAN_SEGV_RW = re.compile(r"The signal is caused by a (READ|WRITE) memory access")
# قاب پشته در قالب sanitizer:  #3 0x55d0 in func /path/file.c:123[:col]
FRAME_RE = re.compile(
    r"^\s*#(\d+)\s+0x[0-9a-f]+\s+in\s+(.+?)\s+((?:/|\.{1,2}/|[\w.-]+/)?[^\s:()]+):(\d+)(?::\d+)?\s*$",
    re.M)
SRC_EXT = r"(?:c|h|cc|cpp|cxx|hpp|hh|hxx|C|inc)"
UBSAN_ERR = re.compile(
    r"^((?:[\w./+-]+/)?[\w.+-]+\." + SRC_EXT + r"):(\d+):(\d+):\s*runtime error:\s*(.+)$", re.M)
UBSAN_OOB = re.compile(r"index (-?\d+) out of bounds for type '([^']+)'")
CANARY_MSG = "*** stack smashing detected ***"
FORTIFY_MSG = "*** buffer overflow detected ***"

# نگاشت گزارش ASan به نوع خطای استاندارد
TYPE_MAP = {
    "heap-buffer-overflow": "HEAP_BUFFER_OVERFLOW",
    "stack-buffer-overflow": "STACK_BUFFER_OVERFLOW",
    "stack-buffer-underflow": "STACK_BUFFER_UNDERFLOW",
    "global-buffer-overflow": "GLOBAL_BUFFER_OVERFLOW",
    "dynamic-stack-buffer-overflow": "DYNAMIC_STACK_BUFFER_OVERFLOW",
    "container-overflow": "CONTAINER_OVERFLOW",
    "heap-use-after-free": "USE_AFTER_FREE",
    "stack-use-after-return": "USE_AFTER_RETURN",
    "stack-use-after-scope": "USE_AFTER_SCOPE",
    "attempting double-free": "DOUBLE_FREE",
    "attempting free": "INVALID_FREE",
    "alloc-dealloc-mismatch": "ALLOC_DEALLOC_MISMATCH",
    "new-delete-type-mismatch": "NEW_DELETE_TYPE_MISMATCH",
    "stack-overflow": "STACK_EXHAUSTION",
    "allocation-size-too-big": "ALLOCATION_TOO_BIG",
    "requested allocation": "ALLOCATION_TOO_BIG",
    "out of memory": "OUT_OF_MEMORY",
    "out-of-memory": "OUT_OF_MEMORY",
    "negative-size-param": "NEGATIVE_SIZE_PARAM",
    "memcpy-param-overlap": "MEMCPY_PARAM_OVERLAP",
    "strcpy-param-overlap": "STRCPY_PARAM_OVERLAP",
    "calloc-overflow": "CALLOC_OVERFLOW",
    "FPE": "DIV_BY_ZERO",
    "unknown-crash": "UNKNOWN_MEMORY_ERROR",
}

# قاب‌های میانجی زمان‌اجرای Sanitizer/کتابخانه استاندارد که «محل خطا» نیستند
SANITIZER_INTERNAL = ("__asan", "__ubsan", "__interceptor_", "__sanitizer",
                      "__msan", "__tsan", "___interceptor_", "__lsan")
RUNTIME_FILE_HINTS = ("sanitizer_common", "/libsanitizer/", "interceptor",
                      "libasan", "libubsan", "compiler-rt", "compiler_rt",
                      "/usr/include/", "string_fortified.h", "/sysdeps/",
                      "/csu/", "libc-start", "libc_start")
RUNTIME_FUNCS = frozenset((
    "__libc_start_main", "__libc_start_call_main", "_start",
    "__libc_start_main_impl", "__chk_fail", "__fortify_fail",
    "__stack_chk_fail", "abort", "raise",
    # توابع تخصیص و رشته‌ای که Sanitizer رهگیری می‌کند (قاب میانجی، نه محل خطا)
    "malloc", "calloc", "realloc", "free", "reallocarray", "posix_memalign",
    "operator new", "operator new[]", "operator delete", "operator delete[]",
    "memcpy", "memmove", "memset", "memcmp", "strlen", "strnlen", "strcpy",
    "strncpy", "strcat", "strncat", "strcmp", "strncmp", "strdup", "sprintf",
    "snprintf", "vsprintf", "vsnprintf", "fread", "fwrite", "read", "printf",
    "puts", "fputs"))

RESOURCE_SIGNALS = {getattr(_signal, n): n for n in ("SIGXCPU", "SIGXFSZ")
                    if hasattr(_signal, n)}


def signal_name(signum: int) -> str:
    try:
        return _signal.Signals(signum).name
    except (ValueError, TypeError):
        return f"SIG{signum}"


def _first_stack(text: str):
    """فقط نخستین پشته فراخوانی گزارش (پشته محل خطا).

    گزارش ASan برای UAF/double-free پشته‌های «allocated by» و «freed by» هم
    دارد؛ مخلوط‌کردن آن‌ها پیوند با diff را آلوده می‌کند. پشته نخست با
    بازگشت شماره قاب به #0 پایان می‌یابد.
    """
    frames = []
    for m in FRAME_RE.finditer(text):
        idx = int(m.group(1))
        if frames and idx == 0:
            break
        func = m.group(2).strip()
        # نام‌های C++ ممکن است امضای پارامتر داشته باشند: ns::f(int) → ns::f
        func = re.sub(r"\(.*\)$", "", func).strip()
        frames.append({"idx": idx, "func": func, "file": m.group(3),
                       "line": int(m.group(4))})
    return frames


def _is_runtime(frame) -> bool:
    fn = frame.get("func") or ""
    fp = (frame.get("file") or "").lower()
    if fn.startswith(SANITIZER_INTERNAL) or fn in RUNTIME_FUNCS:
        return True
    return any(h in fp for h in RUNTIME_FILE_HINTS)


def _top_frame(frames):
    """قاب نخست معنادار (فیلتر قاب‌های میانجی مانند memcpy در interceptor)."""
    for f in frames:
        if f.get("func") and not _is_runtime(f):
            return {"func": f["func"], "file": os.path.basename(f["file"]),
                    "line": f["line"]}
    if frames:
        f = frames[0]
        return {"func": f.get("func"), "file": os.path.basename(f.get("file") or "?"),
                "line": f.get("line", 0)}
    return None


def _empty():
    return {
        "confirmed": False,          # خطای حافظه/امنیتی با گواهی معتبر؟
        "unclassified_crash": False,  # توقف غیرعادی بدون طبقه‌بندی؟
        "resource_limit": False,     # عبور از محدودیت زمان/منابع؟
        "env_error": False,          # خرابی محیط (زمان‌اجرای Sanitizer)، نه برنامه
        "error_type": None,
        "rw": None,
        "size": None,
        "address": None,
        "mechanism": None,
        "summary_line": None,
        "frames": [],
        "top": None,                 # {"func", "file", "line"}
        "detail": None,
    }


def analyze(run_result: dict) -> dict:
    """تحلیل نتیجه یک اجرا (خروجی runner) و تولید گزارش شواهد."""
    err = run_result.get("stderr", "") or ""
    out = _empty()
    if run_result.get("sanitizer_runtime_failure"):
        out["env_error"] = True
        out["mechanism"] = "environment:sanitizer-runtime"
        out["summary_line"] = run_result.get("note")
        return out
    if run_result.get("timed_out"):
        out["resource_limit"] = True
        out["mechanism"] = "resource-limit:timeout"
        out["summary_line"] = run_result.get("note") or "عبور از محدودیت زمان"
        return out

    # --- AddressSanitizer
    m = ASAN_ERR.search(err)
    if m:
        kind = m.group(1)
        etype = None
        for pat, tname in TYPE_MAP.items():
            if kind == pat or kind.startswith(pat):
                etype = tname
                break
        if etype is None:
            first = kind.split()[0]
            etype = TYPE_MAP.get(first, first.upper().replace("-", "_"))
        addr = ASAN_ADDR.search(err)
        if addr:
            out["address"] = addr.group(1)
        if etype == "SEGV":
            # دسترسی به نشانی بسیار کوچک ≈ ارجاع اشاره‌گر تهی
            if addr and int(addr.group(1), 16) < 0x1000:
                etype = "NULL_DEREF"
            else:
                etype = "SEGV_INVALID_ACCESS"
        out.update(confirmed=True, mechanism="sanitizer:ASan",
                   summary_line=m.group(0), error_type=etype)
        rw = ASAN_RW.search(err)
        if rw:
            out["rw"], out["size"] = rw.group(1), int(rw.group(2))
        else:
            srw = ASAN_SEGV_RW.search(err)
            if srw:
                out["rw"] = srw.group(1)
        out["frames"] = _first_stack(err)
        out["top"] = _top_frame(out["frames"])
        return out

    # --- UndefinedBehaviorSanitizer
    m = UBSAN_ERR.search(err)
    if m:
        file, line, _col, msg = m.groups()
        out.update(confirmed=True, mechanism="sanitizer:UBSan",
                   summary_line=f"{os.path.basename(file)}:{line}: {msg}".strip())
        oob = UBSAN_OOB.search(msg)
        if oob:
            out["error_type"] = "INDEX_OUT_OF_BOUNDS"
            out["detail"] = f"index {oob.group(1)} out of bounds for type {oob.group(2)}"
        elif "null pointer" in msg:
            out["error_type"] = "NULL_DEREF"
        elif "division by zero" in msg:
            out["error_type"] = "DIV_BY_ZERO"
        elif "signed integer overflow" in msg:
            out["error_type"] = "INTEGER_OVERFLOW"
        elif "shift exponent" in msg or "left shift" in msg:
            out["error_type"] = "INVALID_SHIFT"
        elif "misaligned address" in msg:
            out["error_type"] = "MISALIGNED_ACCESS"
        elif "pointer overflow" in msg:
            out["error_type"] = "POINTER_OVERFLOW"
        elif "is outside the range of representable values" in msg:
            out["error_type"] = "FLOAT_CAST_OVERFLOW"
        elif "not a valid value for type" in msg:
            out["error_type"] = "INVALID_VALUE_LOAD"
        else:
            out["error_type"] = "UNDEFINED_BEHAVIOR"
        frames = _first_stack(err[m.start():])
        if frames:
            out["frames"] = frames
            out["top"] = _top_frame(frames)
        else:
            out["frames"] = [{"idx": 0, "func": None, "file": file, "line": int(line)}]
            out["top"] = {"func": None, "file": os.path.basename(file), "line": int(line)}
        return out

    rc = run_result.get("exit_code")
    sig = run_result.get("signal") or 0
    if not sig and isinstance(rc, int) and rc < 0:
        sig = -rc

    # --- محافظ‌های باینری (بیلد عادی): قناری پشته و FORTIFY_SOURCE
    if CANARY_MSG in err:
        out.update(confirmed=True, mechanism="protection:stack-canary",
                   error_type="STACK_BUFFER_OVERFLOW", rw="WRITE",
                   summary_line=f"{CANARY_MSG} — __stack_chk_fail "
                                f"(خاتمه با {signal_name(sig) if sig else 'abort'})")
        return out
    if FORTIFY_MSG in err:
        out.update(confirmed=True, mechanism="protection:fortify-source",
                   error_type="BUFFER_OVERFLOW", rw="WRITE",
                   summary_line=f"{FORTIFY_MSG} — __chk_fail از FORTIFY_SOURCE "
                                f"(خاتمه با {signal_name(sig) if sig else 'abort'})")
        return out

    # --- عبور از محدودیت منابع (CPU/حجم فایل)
    if run_result.get("ran") and sig in RESOURCE_SIGNALS:
        out.update(resource_limit=True,
                   mechanism=f"resource-limit:{RESOURCE_SIGNALS[sig]}",
                   summary_line=f"عبور از محدودیت منابع ({RESOURCE_SIGNALS[sig]})")
        return out

    # --- فقط سیگنال (بدون هیچ گواهی) → طبقه‌بندی‌نشده
    if run_result.get("ran") and sig:
        out.update(unclassified_crash=True, error_type="UNCLASSIFIED_SIGNAL",
                   mechanism=f"signal:{signal_name(sig)}",
                   summary_line=f"خاتمه با سیگنال {signal_name(sig)} بدون گواهی "
                                f"Sanitizer یا محافظ باینری")
    return out


def signature(ev: dict) -> str:
    """امضای یافته: نوع خطا [/نوع دسترسی] + تابع قاب نخست.

    مثال: HEAP_BUFFER_OVERFLOW/READ@parse_string. نوع دسترسی (READ/WRITE) جزء
    امضاست تا مثلاً سرریز «نوشتن» تازه‌ای که وصله در همان تابع ایجاد کرده، با
    سرریز «خواندن» قبلی یکی شمرده نشود (NEW_ISSUE، نه INCOMPLETE_FIX). در نبود
    تابع، فایل یا سازوکار تشخیص جای آن را می‌گیرد. معیار «همان خطا» برای
    بازتولید، کوچک‌سازی و رگرسیون همین امضا است، نه صرفاً کد خروج غیرصفر.
    """
    top = ev.get("top") or {}
    loc = top.get("func") or top.get("file")
    if not loc:
        loc = "[" + (ev.get("mechanism") or "?") + "]"
    rw = f"/{ev['rw']}" if ev.get("rw") else ""
    return f"{ev.get('error_type')}{rw}@{loc}"


def termination(run_result: dict) -> dict:
    """نحوه خاتمه برنامه به‌صورت مجزا برای گزارش."""
    rc = run_result.get("exit_code")
    sig = run_result.get("signal") or 0
    return {"exit_code": rc,
            "signal": signal_name(sig) if sig else None,
            "timed_out": bool(run_result.get("timed_out")),
            "stdout": (run_result.get("stdout") or "")[:2000],
            "stderr": (run_result.get("stderr") or "")[:4000]}
