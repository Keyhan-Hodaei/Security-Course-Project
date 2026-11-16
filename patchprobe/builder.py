"""ساخت بیلدهای release و ابزارگذاری‌شده از درخت منبع + هش باینری.

- هر ترکیب نسخه×بیلد درخت منبع جداگانه دارد و باینری احتمالی قبلی پیش از
  ساخت حذف می‌شود (وگرنه make باینری به‌روزِ بیلد دیگر را دست‌نخورده
  می‌گذارد و بیلد «ابزارگذاری‌شده» عملاً همان بیلد عادی می‌شود).
- -ffile-prefix-map مسیر موقت درخت منبع را از اطلاعات اشکال‌زدایی حذف می‌کند
  تا ساخت قطعی (reproducible) باشد: ساخت مجدد همان کامیت با همان دستور، همان
  هش SHA-256 را می‌دهد و بسته بازتولید می‌تواند هش باینری را تطبیق دهد.
- پس از ساخت، تفکیک دو بیلد با شواهد تأیید می‌شود: بیلد sanitized باید
  نمادهای زمان‌اجرای ASan/UBSan داشته باشد و بیلد release نباید داشته باشد.
"""
import hashlib
import os
import subprocess


class BuildError(Exception):
    pass


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def effective_cflags(cfg, mode: str, src_dir: str) -> str:
    return f"{cfg.flags[mode]} -ffile-prefix-map={src_dir}=."


def render_command(cfg, mode: str, src_dir: str, workdir: str) -> str:
    return (cfg.build_command.replace("{src}", src_dir)
            .replace("{cflags}", effective_cflags(cfg, mode, src_dir))
            .replace("{mode}", mode).replace("{out}", workdir))


def instrumentation(binary: str) -> dict:
    """شواهد ابزارگذاری از جدول نمادها (readelf)."""
    r = subprocess.run(["readelf", "-W", "-s", "--dyn-syms", binary],
                       capture_output=True, text=True)
    syms = r.stdout
    return {"asan": "__asan_init" in syms or "__asan_report" in syms,
            "ubsan": "__ubsan_handle" in syms}


def build(src_dir: str, cfg, mode: str, workdir: str) -> dict:
    """ساخت نسخه «mode» (release|sanitized) از src_dir.

    خروجی: {mode, binary, sha256, command, log_tail, instrumentation, ok}
    """
    cmd = render_command(cfg, mode, src_dir, workdir)
    binary = os.path.join(src_dir, cfg.binary_relpath)
    if os.path.exists(binary):
        os.remove(binary)
    env = dict(os.environ, LC_ALL="C", SOURCE_DATE_EPOCH="0")
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                       cwd=src_dir, timeout=600, env=env)
    log = (r.stdout + "\n" + r.stderr).strip()
    if r.returncode != 0 or not os.path.isfile(binary):
        why = (f"کد {r.returncode}" if r.returncode != 0
               else f"باینری «{cfg.binary_relpath}» پس از ساخت یافت نشد")
        raise BuildError(f"ساخت {mode} شکست خورد ({why})\n{log[-2000:]}")
    inst = instrumentation(binary)
    if mode == "sanitized" and not (inst["asan"] or inst["ubsan"]):
        raise BuildError("بیلد sanitized ابزارگذاری نشده است (نماد __asan_init/"
                         "__ubsan_handle یافت نشد) — احتمالاً سیستم ساخت CFLAGS "
                         "بیرونی را نادیده می‌گیرد؛ پیکربندی ساخت را اصلاح کنید")
    if mode == "release" and (inst["asan"] or inst["ubsan"]):
        raise BuildError("بیلد release شامل زمان‌اجرای Sanitizer است؛ دو بیلد "
                         "تفکیک نشده‌اند")
    return {
        "mode": mode,
        "binary": binary,
        "sha256": sha256_file(binary),
        "command": cmd,
        "cflags": effective_cflags(cfg, mode, src_dir),
        "instrumentation": inst,
        "log_tail": log[-1500:],
        "ok": True,
    }
