#!/usr/bin/env python3
"""اجرای «وصله‌های ندیده» روی PatchProbe — تمرین روز دفاع و ارزیابی زنده.

دو حالت:

1) کل مجموعه تمرینی (defense/unseen/manifest.json) با مقایسه کد خروج موردانتظار:
       python3 defense/run_unseen.py
       python3 defense/run_unseen.py --only u03-alloc-off-by-one

2) یک وصله دلخواه (مثلاً فایلی که روز دفاع داده می‌شود):
       python3 defense/run_unseen.py --target jsoncheck --base main --patch /path/x.patch
   (وصله با «git am» یا در صورت شکست با «git apply» روی شاخه موقت اعمال می‌شود.)

مخزن هدف رسمی و مجموعه رگرسیون رسمی دست نمی‌خورند: هر وصله روی یک clone موقت
از targets/<هدف>/repo.bundle اعمال می‌شود و مجموعه رگرسیون از یک کپی موقت خوانده
و نوشته می‌شود. خروجی‌ها: defense/results/<نام>/{report.json,report.md,console.log}.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UNSEEN = os.path.join(ROOT, "defense", "unseen")
RESULTS = os.path.join(ROOT, "defense", "results")
GIT_ID = ["-c", "user.name=PatchProbe Defense", "-c", "user.email=defense@example.invalid"]


def git(repo, *args, check=True):
    return subprocess.run(["git", *GIT_ID, "-C", repo, *args], capture_output=True,
                          text=True, check=check)


def prepare_repo(target, workdir):
    """clone موقت مخزن هدف با همه شاخه‌ها."""
    src = os.path.join(ROOT, "targets", target, "repo")
    bundle = src + ".bundle"
    dst = os.path.join(workdir, f"{target}-repo")
    origin = src if os.path.isdir(os.path.join(src, ".git")) else bundle
    subprocess.run(["git", "clone", "-q", origin, dst], check=True)
    refs = git(dst, "for-each-ref", "--format=%(refname:short)", "refs/remotes/origin/").stdout
    for ref in refs.split():
        if "/" not in ref:  # refs/remotes/origin/HEAD → «origin»
            continue
        name = ref.split("/", 1)[1]
        if name != "HEAD":
            git(dst, "branch", "-q", "-f", name, ref, check=False)
    return dst


def apply_patch(repo, base, patch, branch):
    git(repo, "checkout", "-q", "-B", branch, base)
    r = git(repo, "am", "-q", "--3way", os.path.abspath(patch), check=False)
    if r.returncode != 0:  # وصله خام (diff) بدون سربرگ ایمیل
        git(repo, "am", "--abort", check=False)
        git(repo, "checkout", "-q", "-B", branch, base)
        r2 = git(repo, "apply", "--index", os.path.abspath(patch), check=False)
        if r2.returncode != 0:
            raise RuntimeError(f"اعمال وصله شکست خورد:\n{r.stderr}\n{r2.stderr}")
        git(repo, "commit", "-q", "-m", f"unseen patch {os.path.basename(patch)}")
    return git(repo, "rev-parse", "HEAD").stdout.strip()


def temp_config(target, repo, workdir):
    with open(os.path.join(ROOT, "targets", target, "config.json"), encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["repo"] = repo  # مسیر مطلق
    cfg["tests_dir"] = os.path.join(ROOT, cfg["tests_dir"])
    path = os.path.join(workdir, f"{target}-config.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    return path


def run_one(target, base, patch, name, workdir, reg_dir, extra):
    repo = prepare_repo(target, os.path.join(workdir, name))
    commit = apply_patch(repo, base, patch, name)
    cfg = temp_config(target, repo, os.path.join(workdir, name))
    out = os.path.join(RESULTS, name)
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    cmd = [sys.executable, "-m", "patchprobe", "--config", cfg, "--base-ref", base,
           "--patched-ref", commit, "--out-json", os.path.join(out, "report.json"),
           "--out-md", os.path.join(out, "report.md"),
           "--bundles-dir", os.path.join(out, "bundles"),
           "--regression-dir", reg_dir, *extra]
    with open(os.path.join(out, "console.log"), "w", encoding="utf-8") as log:
        rc = subprocess.run(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT).returncode
    summary = ""
    try:
        with open(os.path.join(out, "report.json"), encoding="utf-8") as f:
            jr = json.load(f)
        st = [f"{x['status']}:{x['signature']}" for x in jr.get("findings", [])]
        fl = [k for k, v in (jr.get("verdict", {}).get("flags") or {}).items() if v]
        warn = (jr.get("hardening") or {}).get("comparison", {}).get("warnings", [])
        summary = f"{jr['verdict']['name']} | {', '.join(st) or '—'} | flags={fl}" + \
                  (f" | ⚠ {len(warn)} هشدار سخت‌سازی" if warn else "")
    except (OSError, ValueError, KeyError):
        pass
    return rc, summary


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", help="فقط وصله‌های تمرینی که نامشان شامل این رشته است")
    ap.add_argument("--target", help="هدف وصله دلخواه (jsoncheck/imginfo/…)")
    ap.add_argument("--base", default="main", help="ref پایه وصله دلخواه")
    ap.add_argument("--patch", help="فایل وصله دلخواه (.patch/.diff)")
    ap.add_argument("--expect", type=int, help="کد موردانتظار وصله دلخواه (اختیاری)")
    ap.add_argument("--fresh-regression", action="store_true",
                    help="بدون مدخل‌های رگرسیون قبلی شروع شود")
    args, extra = ap.parse_known_args()

    if args.patch:
        if not args.target:
            ap.error("--target لازم است")
        items = [{"t": args.target, "base": args.base, "patch": os.path.abspath(args.patch),
                  "name": "custom-" + os.path.splitext(os.path.basename(args.patch))[0],
                  "expect": args.expect, "desc": "وصله دلخواه"}]
    else:
        with open(os.path.join(UNSEEN, "manifest.json"), encoding="utf-8") as f:
            items = json.load(f)
        for it in items:
            it["patch"] = os.path.join(UNSEEN, it["patch"])
        if args.only:
            items = [it for it in items if args.only in it["name"]]

    subprocess.run(["bash", os.path.join(ROOT, "scripts", "setup_targets.sh")],
                   check=True, capture_output=True)
    workdir = tempfile.mkdtemp(prefix="pp-unseen-")
    reg_dir = os.path.join(workdir, "regression")
    if not args.fresh_regression and os.path.isdir(os.path.join(ROOT, "regression")):
        shutil.copytree(os.path.join(ROOT, "regression"), reg_dir)
    ok = bad = 0
    rows = []
    try:
        for it in items:
            print(f"▶ {it['name']} [{it['t']}] پایه={it['base']} — {it['desc']}", flush=True)
            try:
                rc, summary = run_one(it["t"], it["base"], it["patch"], it["name"],
                                      workdir, reg_dir, extra)
            except (RuntimeError, subprocess.CalledProcessError) as e:
                rc, summary = 30, f"خطا در آماده‌سازی: {e}"
            want = it.get("expect")
            mark = "•" if want is None else ("✓" if rc == want else "✗")
            if want is not None:
                ok, bad = (ok + 1, bad) if rc == want else (ok, bad + 1)
            print(f"  {mark} کد خروج {rc}" + (f" (انتظار {want})" if want is not None else "")
                  + f"  {summary}", flush=True)
            rows.append({"name": it["name"], "target": it["t"], "base": it["base"],
                         "expect": want, "got": rc, "summary": summary, "desc": it["desc"]})
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)
    if any(r["expect"] is not None for r in rows):
        print(f"جمع‌بندی: {ok} مطابق انتظار، {bad} مغایر")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
