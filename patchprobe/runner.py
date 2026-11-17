"""اجرای ایزوله برنامه هدف روی یک ورودی مشخص.

ایزولاسیون در سطح فرایند:
- RLIMIT_CPU / RLIMIT_FSIZE / RLIMIT_NOFILE و RLIMIT_CORE=0 (بدون core dump
  در دایرکتوری کار) از طریق preexec_fn؛
- گروه فرایند مستقل (setsid) تا در عبور از سقف زمان، کل درخت فرزندان کشته شود؛
- سقف زمان دیواری با timeout والد.

تذکر مهم: RLIMIT_AS فقط روی بیلد release اعمال می‌شود؛ AddressSanitizer برای
نگاشت حافظه سایه به فضای آدرس عظیمی (چند ترابایت مجازی) نیاز دارد و محدودیت
معمولی، خودِ ASan را از کار می‌اندازد («failed to allocate»). سقف حافظه واقعی
و قطع شبکه در سطح کانتینر (docker-compose.yml) اعمال می‌شود.
"""
import os
import resource
import signal
import subprocess

# متغیرهای محیطی مؤثر بر رفتار Sanitizer — در گزارش و بسته بازتولید ثبت می‌شوند
SANITIZER_ENV = {
    "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0:exitcode=1:"
                    "allocator_may_return_null=1:symbolize=1",
    "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1:symbolize=1",
}


class RunResult(dict):
    """نتیجه یک اجرا: exit_code، signal، stdout، stderr، timed_out و غیره."""


def _make_preexec(cpu_sec, as_mb, fsize_mb, nofile):
    def apply():
        def setlim(res, soft, hard):
            try:
                resource.setrlimit(res, (soft, hard))
            except (ValueError, OSError):
                pass
        os.setsid()  # گروه فرایند/نشست مستقل برای کشتن امن کل درخت
        setlim(resource.RLIMIT_CORE, 0, 0)
        setlim(resource.RLIMIT_CPU, cpu_sec, cpu_sec + 1)
        setlim(resource.RLIMIT_FSIZE, fsize_mb << 20, fsize_mb << 20)
        setlim(resource.RLIMIT_NOFILE, nofile, nofile)
        if as_mb:
            setlim(resource.RLIMIT_AS, as_mb << 20, as_mb << 20)
    return apply


def effective_env(sanitized: bool) -> dict:
    """متغیرهای محیطی مؤثر یک اجرا (برای گزارش/بسته بازتولید)."""
    return dict(SANITIZER_ENV) if sanitized else {}


def build_argv(binary: str, input_path: str, method: str):
    if method == "stdin":
        return [binary]
    return [binary, input_path]


def is_sanitizer_runtime_failure(res: dict) -> bool:
    """خرابی زمان‌اجرای خود ASan پیش از اجرای برنامه (مشکل محیط، نه یافته).

    زمان‌اجرای ASan قدیمی (مثلاً gcc 12) روی هسته‌های جدید با تصادفی‌سازی بالای
    mmap (vm.mmap_rnd_bits=32) گاهی هنگام راه‌اندازی با «AddressSanitizer:DEADLYSIGNAL»
    و بدون هیچ گزارش ERROR از کار می‌افتد. این رخداد شاهد خطای حافظه برنامه نیست.
    """
    err = res.get("stderr") or ""
    return (bool(res.get("sanitized")) and res.get("ran")
            and "AddressSanitizer:DEADLYSIGNAL" in err
            and "ERROR: AddressSanitizer" not in err
            and "runtime error:" not in err)


_SETARCH = {"checked": False, "ok": False}


def _setarch_available() -> bool:
    """آیا «setarch -R» (غیرفعال‌سازی ASLR فقط برای همین فرایند) مجاز است؟"""
    if not _SETARCH["checked"]:
        _SETARCH["checked"] = True
        try:
            r = subprocess.run(["setarch", os.uname().machine, "-R", "true"],
                               capture_output=True, timeout=10)
            _SETARCH["ok"] = r.returncode == 0
        except (OSError, subprocess.SubprocessError):
            _SETARCH["ok"] = False
    return _SETARCH["ok"]


def run_input(binary: str, input_path: str, method: str, limits: dict,
              sanitized: bool, cwd: str = None, env_extra: dict = None) -> RunResult:
    """اجرای binary روی input_path با بازتلاش خرابی زمان‌اجرای Sanitizer.

    اگر زمان‌اجرای ASan هنگام راه‌اندازی از کار بیفتد (مشکل محیط)، اجرا تا
    «sanitizer_retries» بار تکرار می‌شود و از تلاش دوم، در صورت امکان، با
    setarch -R (بدون ASLR) اجرا می‌شود. اگر همه تلاش‌ها شکست بخورند، نتیجه با
    sanitizer_runtime_failure علامت می‌خورد و ابزار آن را خطای محیط (30) گزارش
    می‌کند، نه یافته امنیتی.
    """
    retries = int(limits.get("sanitizer_retries", 12)) if sanitized else 1
    res = None
    for attempt in range(max(1, retries)):
        prefix = None
        if attempt > 0 and _setarch_available():
            prefix = ["setarch", os.uname().machine, "-R"]
        res = _run_once(binary, input_path, method, limits, sanitized, cwd,
                        env_extra, prefix)
        if not is_sanitizer_runtime_failure(res):
            if attempt:
                res["sanitizer_runtime_retries"] = attempt
                res["aslr_disabled"] = bool(prefix)
            return res
    res["sanitizer_runtime_failure"] = True
    res["sanitizer_runtime_retries"] = retries
    res["note"] = ("زمان‌اجرای Sanitizer در همه تلاش‌ها هنگام راه‌اندازی از کار افتاد "
                   "(مشکل محیط: احتمالاً vm.mmap_rnd_bits بالا با ASan قدیمی)")
    return res


def _run_once(binary, input_path, method, limits, sanitized, cwd, env_extra, prefix):
    timeout = float(limits.get("timeout_sec", 5))
    cpu = int(limits.get("cpu_sec", 10))
    as_mb = int(limits.get("rlimit_as_mb_sanitized" if sanitized else "rlimit_as_mb", 0) or 0)
    fsize = int(limits.get("rlimit_fsize_mb", 64))
    nofile = int(limits.get("rlimit_nofile", 64))

    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("ASAN_", "UBSAN_", "LSAN_", "MSAN_"))}
    env.update(SANITIZER_ENV)  # در بیلد عادی بی‌اثرند؛ برای یکسانی تنظیمات
    env["LC_ALL"] = "C"
    if env_extra:
        env.update(env_extra)

    argv = (prefix or []) + build_argv(binary, input_path, method)
    res = RunResult(binary=binary, input=os.path.basename(input_path),
                    method=method, timeout_limit=timeout,
                    sanitized=bool(sanitized))
    stdin_file = open(input_path, "rb") if method == "stdin" else None
    try:
        p = subprocess.Popen(
            argv, stdin=stdin_file if stdin_file is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, env=env,
            preexec_fn=_make_preexec(cpu, as_mb, fsize, nofile))
        try:
            out, err = p.communicate(timeout=timeout)
            rc = p.returncode
            res.update(exit_code=rc, signal=(-rc if rc < 0 else 0),
                       stdout=out.decode("utf-8", "replace"),
                       stderr=err.decode("utf-8", "replace"),
                       timed_out=False, ran=True)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                p.kill()
            out, err = p.communicate()
            res.update(exit_code=None, signal=signal.SIGKILL, timed_out=True, ran=True,
                       stdout=(out or b"").decode("utf-8", "replace"),
                       stderr=(err or b"").decode("utf-8", "replace"),
                       note=f"عبور از محدودیت زمان اجرا ({timeout:g} ثانیه) — TIMEOUT")
    except Exception as e:  # خطای خود ابزار/محیط در اجرا
        res.update(exit_code=None, signal=0, timed_out=False, ran=False,
                   stdout="", stderr=str(e), note="خطای اجرای ابزار")
    finally:
        if stdin_file is not None:
            stdin_file.close()
    return res
