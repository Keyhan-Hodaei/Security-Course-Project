"""بارگذاری و اعتبارسنجی پیکربندی هدف.

پیکربندیِ هر هدفِ ارزیابی، یک فایل JSON است که همه اطلاعات لازم برای
«افزودن برنامه جدید صرفاً با تغییر پیکربندی» را در خود دارد:
دستور ساخت، مسیر باینری، نحوه ارسال ورودی و مجموعه آزمون‌ها.

جای‌نگهدارهای دستور ساخت (با جایگزینی متنی ساده، نه str.format؛ تا عبارات
پوسته مانند ${VAR} دست‌نخورده بمانند):
  {src}     درخت منبع برون‌بری‌شده همان نسخه×بیلد   (الزامی نیست)
  {cflags}  پرچم‌های بیلد release یا sanitized       (الزامی — وگرنه دو بیلد یکی می‌شوند)
  {mode}    release | sanitized
  {out}     دایرکتوری کار اجرا
"""
import json
import os
import subprocess

DEFAULT_LIMITS = {
    "timeout_sec": 5.0,
    "cpu_sec": 10,
    # RLIMIT_AS فقط روی بیلد release اعمال می‌شود؛ ASan برای نگاشت سایه‌اش
    # به فضای آدرس بسیار بزرگی نیاز دارد و محدودیت کم آن را می‌شکند.
    "rlimit_as_mb": 512,
    "rlimit_as_mb_sanitized": 0,   # 0 = بدون محدودیت
    "rlimit_fsize_mb": 64,
    "rlimit_nofile": 64,
}

# -U_FORTIFY_SOURCE در بیلد ابزارگذاری‌شده: در توزیع‌هایی که FORTIFY_SOURCE را
# پیش‌فرض روشن می‌کنند (مثل Ubuntu)، بررسی‌های __*_chk پیش از ASan برنامه را
# abort می‌کنند و گواهی دقیق Sanitizer (نوع خطا/پشته) از دست می‌رود. بیلد عادی
# همان پیش‌فرض‌های کامپایلر را نگه می‌دارد تا رفتار واقعی باینری نهایی دیده شود.
DEFAULT_BUILD_FLAGS = {
    "release": "-O2 -pipe -g",
    "sanitized": ("-O1 -g -fsanitize=address,undefined "
                  "-fno-sanitize-recover=undefined -fno-omit-frame-pointer "
                  "-U_FORTIFY_SOURCE"),
}

REQUIRED_KEYS = ("target", "repo", "build", "input", "tests")
TEST_KINDS = ("valid", "boundary", "invalid")


class ConfigError(Exception):
    pass


def restore_repo_from_bundle(repo: str) -> bool:
    """اگر مخزن هدف موجود نیست ولی «repo.bundle» کنار آن هست، بازیابی کن.

    مخزن‌های هدف به‌صورت git bundle در مخزن پروژه نگه داشته می‌شوند (مخزن
    تودرتو در git قابل‌ردیابی نیست). خروجی: True اگر بازیابی انجام شد.
    """
    bundle = repo.rstrip("/") + ".bundle"
    if os.path.isdir(os.path.join(repo, ".git")) or not os.path.isfile(bundle):
        return False
    r = subprocess.run(["git", "clone", "-q", bundle, repo], capture_output=True, text=True)
    if r.returncode != 0:
        raise ConfigError(f"بازیابی مخزن هدف از {bundle} شکست خورد: {r.stderr.strip()[:300]}")
    # ساخت شاخه محلی برای همه شاخه‌های bundle (main، patch-*، ...)
    refs = subprocess.run(["git", "-C", repo, "for-each-ref", "--format=%(refname:short)",
                           "refs/remotes/origin/"], capture_output=True, text=True).stdout
    for ref in refs.split():
        name = ref.split("/", 1)[1] if "/" in ref else ref
        if name in ("HEAD", "origin"):
            continue
        subprocess.run(["git", "-C", repo, "branch", "-q", "-f", name, ref],
                       capture_output=True)
    return True


class TargetConfig:
    def __init__(self, path: str, root: str, data: dict):
        self.path = os.path.abspath(path)
        self.root = root
        self.data = data
        if not isinstance(data, dict):
            raise ConfigError("ریشه پیکربندی باید یک شیء JSON باشد")
        for k in REQUIRED_KEYS:
            if k not in data:
                raise ConfigError(f"پیکربندی ناقص است: کلید «{k}» یافت نشد")
        self.name = str(data["target"])
        self.repo = os.path.join(root, data["repo"])
        restore_repo_from_bundle(self.repo)
        if not os.path.isdir(os.path.join(self.repo, ".git")):
            raise ConfigError(f"مخزن git یافت نشد: {self.repo} "
                              f"(برای بازیابی: bash scripts/setup_targets.sh)")

        b = data["build"]
        if not isinstance(b, dict):
            raise ConfigError("بخش build باید شیء باشد")
        for k in ("command", "binary"):
            if not b.get(k):
                raise ConfigError("بخش build باید «command» و «binary» داشته باشد")
        self.build_command = b["command"]
        if "{cflags}" not in self.build_command:
            raise ConfigError("build.command باید جای‌نگهدار {cflags} داشته باشد؛ وگرنه "
                              "بیلد ابزارگذاری‌شده با بیلد عادی یکی می‌شود")
        self.binary_relpath = b["binary"]
        self.flags = dict(DEFAULT_BUILD_FLAGS)
        self.flags.update(b.get("flags", {}))
        for mode in ("release", "sanitized"):
            if not isinstance(self.flags.get(mode), str):
                raise ConfigError(f"build.flags.{mode} باید رشته باشد")
        if "-fsanitize=" not in self.flags["sanitized"]:
            raise ConfigError("build.flags.sanitized باید -fsanitize=... داشته باشد")
        if "-fsanitize=" in self.flags["release"]:
            raise ConfigError("build.flags.release نباید Sanitizer داشته باشد "
                              "(نتایج بیلد عادی و ابزارگذاری‌شده نباید مخلوط شوند)")

        inp = data["input"]
        m = inp.get("method") if isinstance(inp, dict) else None
        if m not in ("stdin", "file"):
            raise ConfigError("input.method باید «stdin» یا «file» باشد")
        self.input_method = m

        t = data["tests"]
        if not isinstance(t, dict):
            raise ConfigError("بخش tests باید شیء باشد")
        for k in TEST_KINDS:
            if not isinstance(t.get(k), list):
                raise ConfigError(f"tests.{k} باید فهرستی از آزمون‌ها باشد")
        self.tests = t
        self.tests_dir = os.path.join(root, data.get("tests_dir", ""))
        self.limits = dict(DEFAULT_LIMITS)
        self.limits.update(data.get("limits", {}))

        seen = set()
        for kind in TEST_KINDS:
            for i, case in enumerate(self.tests[kind]):
                if not isinstance(case, dict) or not case.get("name"):
                    raise ConfigError(f"tests.{kind}[{i}] باید شیء دارای «name» باشد")
                if case["name"] in seen:
                    raise ConfigError(f"نام آزمون تکراری: {case['name']}")
                seen.add(case["name"])
                p = os.path.join(self.tests_dir, case["name"])
                if not os.path.isfile(p):
                    raise ConfigError(f"فایل آزمون یافت نشد: {p} ({kind}[{i}])")
                if "expect_exit" in case and not isinstance(case["expect_exit"], int):
                    raise ConfigError(f"expect_exit آزمون {case['name']} باید عدد صحیح باشد")
                case["_path"] = p
        if not seen:
            raise ConfigError("مجموعه آزمون خالی است")

    def all_cases(self):
        """همه آزمون‌ها به‌همراه دسته‌شان."""
        for kind in TEST_KINDS:
            for case in self.tests[kind]:
                yield kind, case

    def expect(self, case):
        """انتظار عملکردی آزمون: (exit, stdout دقیق, stdout الگو)."""
        return (case.get("expect_exit"),
                case.get("expect_stdout"),
                case.get("expect_stdout_pattern"))


def load_config(path: str, root: str = None) -> TargetConfig:
    if not os.path.isfile(path):
        raise ConfigError(f"فایل پیکربندی یافت نشد: {path}")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ConfigError(f"خطای JSON در پیکربندی: {e}") from e
    if root is None:
        from . import project_root_from
        root = project_root_from(path)
    return TargetConfig(path, root, data)
