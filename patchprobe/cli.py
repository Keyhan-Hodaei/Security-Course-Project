"""PatchProbe orchestrator — execute a complete patch-validation scenario.

Workflow:
 Configuration → resolve refs → export and build 2 versions × 2 modes (verify
 build separation) → inspect hardening → run the full suite on all 4 builds →
 analyze evidence and findings → replay for stability → classify as FIXED /
 INCOMPLETE_FIX / NEW_ISSUE / FUNC_REGRESSION → correlate findings with the diff →
 ddmin reduction → reproduction bundles → add/verify regression cases →
 verdict and exit code plus JSON/Markdown/console reports.
"""
import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from . import (EXIT_BUILD_OR_CONFIG_ERROR, __version__,
               config as config_mod, gitops, builder, harden, verdict,
               evidence as evidence_mod, correlate as correlate_mod,
               repro as repro_mod, regress as regress_mod, report as report_mod)
from .builder import BuildError
from .config import ConfigError
from .gitops import GitError
from .minimize import Minimizer
from .runner import run_input, effective_env

log = logging.getLogger("patchprobe")

VARIANTS = ("base_release", "base_sanitized", "patched_release", "patched_sanitized")


# ---------------------------------------------------------------------------
def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="patchprobe",
        description="Automated security patch validation and regression testing (CI/CD)")
    p.add_argument("--config", required=True, help="Target JSON configuration file")
    p.add_argument("--base-ref", required=True, help="Base revision ref (before the patch)")
    p.add_argument("--patched-ref", required=True, help="Patched revision ref")
    p.add_argument("--work-dir", default=None,
                   help="Work directory (default: temporary directory, removed on completion)")
    p.add_argument("--keep-work", action="store_true",
                   help="Preserve the work directory, source trees, and binaries")
    p.add_argument("--out-json", default=None, help="JSON output path")
    p.add_argument("--out-md", default=None, help="Markdown output path")
    p.add_argument("--reports-dir", default=None, help="Report directory")
    p.add_argument("--bundles-dir", default=None,
                   help="Reproduction bundle directory (default: bundles/<target>/<run_id>)")
    p.add_argument("--replays", type=int, default=3,
                   help="Replays per finding (default and required minimum: 3)")
    p.add_argument("--jobs", type=int, default=0,
                   help="Parallel test workers (default: CPU count, capped at 8)")
    p.add_argument("--no-minimize", action="store_true", help="Disable ddmin minimization")
    p.add_argument("--minimize-budget", type=int, default=120,
                   help="Maximum candidate executions for each finding's ddmin reduction")
    p.add_argument("--regression-dir", default=None, help="Regression suite directory")
    p.add_argument("--no-regression-add", action="store_true",
                   help="Disable automatic regression entry updates")
    p.add_argument("--no-regression-verify", action="store_true",
                   help="Disable verification of existing regression entries")
    p.add_argument("--quiet", action="store_true", help="Suppress the console summary")
    p.add_argument("--version", action="version", version=f"patchprobe {__version__}")
    return p.parse_args(argv)


# ---------------------------------------------------------------------------
def _run_all(cfg, cases, binaries, jobs):
    """Run all tests on four builds with matching settings and limits."""
    matrix = {}
    tasks = []
    for kind, case in cases:
        matrix[case["name"]] = {"kind": kind, "case": case, "runs": {}, "ev": {}}
        for variant in VARIANTS:
            tasks.append((case, variant))

    def one(task):
        case, variant = task
        rr = run_input(binaries[variant], case["_path"], cfg.input_method,
                       cfg.limits, sanitized=variant.endswith("sanitized"))
        return case["name"], variant, rr

    with ThreadPoolExecutor(max_workers=jobs) as ex:
        for name, variant, rr in ex.map(one, tasks):
            matrix[name]["runs"][variant] = rr
            matrix[name]["ev"][variant] = evidence_mod.analyze(rr)
    return matrix


def _collect_findings(matrix, version):
    """Collect confirmed findings for one version.

    Findings use instrumented-build sanitizer evidence (error type and stack);
    normal-build behavior for the same input is stored separately in release_view.
    """
    per_sig = {}
    for name, row in matrix.items():
        ev = row["ev"][f"{version}_sanitized"]
        if ev.get("confirmed"):
            sig = evidence_mod.signature(ev)
            per_sig.setdefault(sig, []).append((name, ev))
    out = []
    prefix = "B" if version == "base" else "P"
    for i, sig in enumerate(sorted(per_sig), 1):
        items = per_sig[sig]
        # Representative: smallest input for faster minimization and clearer evidence
        rep_name, rep_ev = min(items, key=lambda it: (
            os.path.getsize(matrix[it[0]]["case"]["_path"]), it[0]))
        out.append({
            "id": f"{prefix}{i:02d}", "signature": sig, "version": version,
            "evidence": rep_ev, "inputs": [n for n, _ in items],
            "input": rep_name, "input_path": matrix[rep_name]["case"]["_path"],
        })
    return out


def _anomalies(matrix):
    """Collect unclassified terminations, protection-only detections, and resource events."""
    unclassified, protection_only, resource = [], [], []
    for name, row in matrix.items():
        for version in ("base", "patched"):
            sev = row["ev"][f"{version}_sanitized"]
            rev = row["ev"][f"{version}_release"]
            for variant, ev in ((f"{version}_sanitized", sev), (f"{version}_release", rev)):
                if ev.get("resource_limit"):
                    resource.append(f"{name} on {variant} ({ev.get('summary_line')})")
            if sev.get("unclassified_crash"):
                unclassified.append(f"{name} on {version}_sanitized "
                                    f"({sev.get('summary_line')})")
            if not sev.get("confirmed"):
                if rev.get("unclassified_crash"):
                    unclassified.append(f"{name} on {version}_release "
                                        f"({rev.get('summary_line')}) and the corresponding sanitized build "
                                        f"provided no evidence")
                elif rev.get("confirmed"):
                    protection_only.append(
                        f"{name} on {version}_release: {rev.get('mechanism')} "
                        f"but the corresponding sanitized build did not confirm the error; "
                        f"the error location cannot be determined")
    return sorted(set(unclassified)), sorted(set(protection_only)), sorted(set(resource))


def _functional_rows(cfg, matrix):
    """Compare matching release builds against independent functional expectations."""
    rows = []
    for kind, case in cfg.all_cases():
        exp_exit, exp_out, exp_pat = cfg.expect(case)
        if exp_exit is None:
            continue

        def ok(rr):
            if rr.get("timed_out") or rr.get("exit_code") != exp_exit:
                return False
            got = (rr.get("stdout") or "").strip()
            if exp_out is not None:
                return got == exp_out
            if exp_pat is not None:
                return re.fullmatch(exp_pat, got) is not None
            return True

        def show(rr):
            if rr.get("timed_out"):
                return "TIMEOUT"
            rc = rr.get("exit_code")
            if isinstance(rc, int) and rc < 0:
                return f"signal={evidence_mod.signal_name(-rc)}"
            return f"exit={rc} «{(rr.get('stdout') or '').strip()[:60]}»"

        row = matrix[case["name"]]["runs"]
        base, patched = row["base_release"], row["patched_release"]
        b_ok, p_ok = ok(base), ok(patched)
        rows.append({
            "name": case["name"], "kind": kind,
            "expect_exit": exp_exit,
            "expect_stdout": exp_out if exp_out is not None
            else (f"/{exp_pat}/" if exp_pat else None),
            "base": show(base), "patched": show(patched),
            "base_ok": b_ok, "patched_ok": p_ok, "ok": b_ok and p_ok,
            "regression": b_ok and not p_ok,
            "base_failed_reference": not b_ok,
        })
    return rows


def _release_view(row):
    """Input behavior in all four builds, separating release and instrumented results."""
    view = {}
    for variant in VARIANTS:
        rr, ev = row["runs"][variant], row["ev"][variant]
        sig = rr.get("signal") or 0
        view[variant] = {
            "exit_code": rr.get("exit_code"),
            "signal": evidence_mod.signal_name(sig) if sig else None,
            "timed_out": bool(rr.get("timed_out")),
            "mechanism": ev.get("mechanism"),
            "error_type": ev.get("error_type"),
            "signature": evidence_mod.signature(ev) if ev.get("confirmed") else None,
            "stdout": (rr.get("stdout") or "").strip()[:200],
            "stderr_head": (rr.get("stderr") or "").strip()[:600],
        }
    return view


def _rel(path, root):
    """Return a project-relative path if inside the project, otherwise an absolute path."""
    path = os.path.abspath(path)
    return os.path.relpath(path, root) if path.startswith(os.path.abspath(root) + os.sep) \
        else path


def _write_outputs(jr, state):
    os.makedirs(os.path.dirname(state["out_json"]) or ".", exist_ok=True)
    with open(state["out_json"], "w", encoding="utf-8") as f:
        json.dump(jr, f, indent=2, ensure_ascii=False, default=str)
    os.makedirs(os.path.dirname(state["out_md"]) or ".", exist_ok=True)
    with open(state["out_md"], "w", encoding="utf-8") as f:
        f.write(report_mod.render_markdown(jr))


# ---------------------------------------------------------------------------
def run_scenario(argv) -> int:
    args = parse_args(argv)
    run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    started = time.time()
    ctx = {"cfg": None, "commits": {}, "subjects": {}, "builds": {}}
    state = {"out_json": args.out_json, "out_md": args.out_md}

    def finish(reasons, extra=None):
        """Report an early definitive build/configuration error (code 30)."""
        cfg = ctx["cfg"]
        decision = verdict.decide({"build_error": "; ".join(reasons)})
        decision["reasons"] = reasons
        jr = {
            "run_id": run_id, "tool_version": __version__,
            "target": cfg.name if cfg else "?",
            "config_path": cfg.path if cfg else os.path.abspath(args.config),
            "refs": {"base": args.base_ref, "patched": args.patched_ref},
            "commits": ctx["commits"], "subjects": ctx["subjects"],
            "builds": {k: {kk: vv for kk, vv in v.items() if kk != "log_tail"}
                       for k, v in ctx["builds"].items()},
            "verdict": decision,
            "summary": {"runs_total": 0},
            "duration_sec": round(time.time() - started, 2),
            "interpretation": ["A build/configuration/environment error was reported early. "
                               "No security or functional judgment was made; "
                               "this result must not be confused with finding a security issue "
                               "or validating the patch."],
        }
        if extra:
            jr.update(extra)
        if state["out_json"] is None:
            rd = os.path.abspath(args.reports_dir or os.path.join(os.getcwd(), "reports"))
            state["out_json"] = os.path.join(rd, f"{run_id}.json")
            state["out_md"] = state["out_md"] or os.path.join(rd, f"{run_id}.md")
        _write_outputs(jr, state)
        if not args.quiet:
            print(report_mod.render_console(jr))
        return EXIT_BUILD_OR_CONFIG_ERROR

    if args.replays < 3:
        return finish([f"--replays={args.replays} is below the required minimum of 3 replays"])

    # ---------------------------------------------------------------- 1) Configuration
    try:
        cfg = config_mod.load_config(args.config)
    except ConfigError as e:
        return finish([f"Configuration error: {e}"])
    ctx["cfg"] = cfg
    root = cfg.root
    reports_dir = os.path.abspath(args.reports_dir or os.path.join(root, "reports", cfg.name))
    state["out_json"] = state["out_json"] or os.path.join(reports_dir, f"{run_id}.json")
    state["out_md"] = state["out_md"] or os.path.join(reports_dir, f"{run_id}.md")
    reg_dir = os.path.abspath(args.regression_dir or os.path.join(root, "regression"))
    bundles_dir = os.path.abspath(args.bundles_dir or
                                  os.path.join(root, "bundles", cfg.name, run_id))

    # ---------------------------------------------------------------- 2) Refs
    try:
        base_commit = gitops.resolve_commit(cfg.repo, args.base_ref)
        patched_commit = gitops.resolve_commit(cfg.repo, args.patched_ref)
        ctx["commits"] = {"base": base_commit, "patched": patched_commit}
        ctx["subjects"] = {"base": gitops.commit_subject(cfg.repo, base_commit),
                           "patched": gitops.commit_subject(cfg.repo, patched_commit)}
    except GitError as e:
        return finish([f"Ref/repository error: {e}"])

    workdir = os.path.abspath(args.work_dir) if args.work_dir else \
        tempfile.mkdtemp(prefix=f"patchprobe-{run_id}-")
    os.makedirs(workdir, exist_ok=True)
    try:
        return _evaluate(args, cfg, ctx, state, finish, run_id, started, root,
                         reg_dir, bundles_dir, workdir, base_commit, patched_commit)
    finally:
        if not args.keep_work:
            shutil.rmtree(workdir, ignore_errors=True)


def _evaluate(args, cfg, ctx, state, finish, run_id, started, root, reg_dir,
              bundles_dir, workdir, base_commit, patched_commit):
    # ---------------------------------------------------------- 3) Export and build
    # Each version/build combination gets a separate source tree so that
    # builds cannot contaminate each other.
    srcs = {}
    try:
        for version, commit in (("base", base_commit), ("patched", patched_commit)):
            for mode in ("release", "sanitized"):
                d = os.path.join(workdir, f"{version}-{mode}")
                os.makedirs(d, exist_ok=True)
                gitops.export_tree(cfg.repo, commit, d)
                srcs[f"{version}_{mode}"] = d
    except GitError as e:
        return finish([f"Failed to export source tree: {e}"])

    builds = ctx["builds"]
    for key in VARIANTS:
        try:
            b = builder.build(srcs[key], cfg, key.split("_")[1], workdir)
        except (BuildError, subprocess.TimeoutExpired) as e:
            return finish([f"Build {key} ({'base' if key.startswith('base') else 'patched'}) "
                           f"failed: {e}"])
        b["commit"] = base_commit if key.startswith("base") else patched_commit
        builds[key] = b
    binaries = {k: b["binary"] for k, b in builds.items()}

    # ---------------------------------------------------------------- 4) Hardening
    hard_base = harden.check_hardening(binaries["base_release"])
    hard_patched = harden.check_hardening(binaries["patched_release"])
    hard_cmp = harden.compare(hard_base, hard_patched)

    # ---------------------------------------------------------------- 5) Executions
    jobs = args.jobs or min(8, os.cpu_count() or 2)
    cases = list(cfg.all_cases())
    matrix = _run_all(cfg, cases, binaries, jobs)
    runs_total = sum(len(r["runs"]) for r in matrix.values())
    mandatory_complete = all(r.get("ran") for row in matrix.values()
                             for r in row["runs"].values())

    env_failures = sorted(f"{name} on {v}" for name, row in matrix.items()
                          for v, ev in row["ev"].items() if ev.get("env_error"))
    if env_failures:
        return finish([f"Runtime environment error: the sanitizer runtime failed at startup "
                       f"after repeated retries ({len(env_failures)} executions, for example "
                       f"{env_failures[0]}). This is not a security finding; workaround: "
                       f"sudo sysctl vm.mmap_rnd_bits=28 or a newer compiler (gcc ≥ 15)"])
    retried = sum(1 for row in matrix.values() for r in row["runs"].values()
                  if r.get("sanitizer_runtime_retries"))

    base_findings = _collect_findings(matrix, "base")
    patched_findings = _collect_findings(matrix, "patched")
    unclassified, protection_only, resource_events = _anomalies(matrix)

    # ---------------------------------------------------------------- 6) Replays
    replays, unstable = {}, []
    for f in base_findings + patched_findings:
        rep = repro_mod.replay(binaries[f"{f['version']}_sanitized"], f["input_path"],
                               cfg.input_method, cfg.limits, True,
                               times=args.replays, run_fn=run_input)
        replays[f["id"]] = rep
        if not rep["stable"]:
            unstable.append(f"{f['id']} ({f['signature']})")

    # ---------------------------------------------------------------- 7) Classification
    classified = correlate_mod.classify_findings(base_findings, patched_findings)
    for f in classified:
        f["replay"] = replays.get(f["id"])
        # Incomplete fix: choose a base input actually blocked by the patch if available,
        # giving two distinct witnesses: a blocked input and a bypass input.
        if f["status"] == "INCOMPLETE_FIX":
            blocked = [n for n in f["inputs"] if n not in f["patched_inputs"]]
            if blocked:
                rep = min(blocked, key=lambda n: (
                    os.path.getsize(matrix[n]["case"]["_path"]), n))
                f["input"] = rep
                f["input_path"] = matrix[rep]["case"]["_path"]
                f["evidence"] = matrix[rep]["ev"]["base_sanitized"]
                f["replay"] = replays[f["id"]] = repro_mod.replay(
                    binaries["base_sanitized"], f["input_path"], cfg.input_method,
                    cfg.limits, True, times=args.replays, run_fn=run_input)
                if not f["replay"]["stable"]:
                    unstable.append(f"{f['id']} ({f['signature']})")

    # ---------------------------------------------------------------- 8) Diff and correlation
    try:
        diff = gitops.diff_hunks(cfg.repo, base_commit, patched_commit)
        diff = correlate_mod.enrich_diff_with_functions(
            diff, srcs["base_release"], srcs["patched_release"])
        diff_stat = gitops.diff_stat(cfg.repo, base_commit, patched_commit)
    except GitError as e:
        return finish([f"Failed to compute diff: {e}"])
    for f in classified:
        row = matrix[f["input"]]
        f["correlation"] = correlate_mod.correlate(f, diff)
        # Differential evidence uses the input establishing the status: for an incomplete
        # fix, use the bypass input that still triggers the candidate.
        wrow = matrix[f["witness"]["input"]] if f.get("witness") else row
        f["correlation"]["differential"] = correlate_mod.differential(f, wrow["ev"])
        f["correlation"]["differential"]["input"] = (f["witness"]["input"]
                                                     if f.get("witness") else f["input"])
        f["release_view"] = _release_view(row)
        if f.get("witness"):
            f["witness"]["release_view"] = _release_view(wrow)
        f["runs"] = {v: {"exit_code": f["release_view"][v]["exit_code"],
                         "signal": f["release_view"][v]["signal"],
                         "timed_out": f["release_view"][v]["timed_out"]}
                     for v in VARIANTS}

    # ---------------------------------------------------------------- 9) Minimization
    if not args.no_minimize:
        for f in classified:
            vb = binaries[f"{f['version']}_sanitized"]
            mini = Minimizer(lambda p, _b=vb: run_input(_b, p, cfg.input_method,
                                                         cfg.limits, True),
                             budget=args.minimize_budget, workdir=workdir)
            f["minimize"] = mini.minimize(f["input_path"], f["signature"])
            if f.get("witness"):
                pb = binaries["patched_sanitized"]
                wmini = Minimizer(lambda p, _b=pb: run_input(_b, p, cfg.input_method,
                                                             cfg.limits, True),
                                  budget=args.minimize_budget, workdir=workdir)
                f["witness"]["minimize"] = wmini.minimize(f["witness"]["input_path"],
                                                          f["signature"])

    # --------------------------------------------------------------- 10) Bundles
    bundles = []
    for f in classified:
        other = "patched" if f["version"] == "base" else "base"
        cross = {
            "input": f["input"],
            f"{f['version']}_sanitized": f["release_view"][f"{f['version']}_sanitized"]["signature"],
            f"{other}_sanitized": f["release_view"][f"{other}_sanitized"]["signature"],
            "note": f["correlation"]["differential"]["note"],
        }
        bpath = repro_mod.write_bundle(
            bundles_dir, cfg.name, f, replays[f["id"]], f.get("minimize"),
            builds[f"{f['version']}_sanitized"], builds[f"{other}_sanitized"], cfg,
            {"base": args.base_ref, "patched": args.patched_ref}, run_id, cross)
        f["bundle"] = _rel(bpath, root)
        bundles.append(f["bundle"])
        w = f.get("witness")
        if w:  # Separate bundle for the bypass input on the patched version
            wf = {**f, "id": f"{f['id']}-bypass", "version": "patched",
                  "input": w["input"], "input_path": w["input_path"],
                  "evidence": w["evidence"]}
            wcross = {"input": w["input"],
                      "patched_sanitized": w["release_view"]["patched_sanitized"]["signature"],
                      "base_sanitized": w["release_view"]["base_sanitized"]["signature"],
                      "note": f["correlation"]["differential"]["note"]}
            wpath = repro_mod.write_bundle(
                bundles_dir, cfg.name, wf, replays.get(w["id"]) or replays[f["id"]],
                w.get("minimize"), builds["patched_sanitized"], builds["base_sanitized"],
                cfg, {"base": args.base_ref, "patched": args.patched_ref}, run_id, wcross)
            w["bundle"] = _rel(wpath, root)
            bundles.append(w["bundle"])

    # ------------------------------------------------- 11) Regression suite
    added_entries, suite_verification = [], []
    stale_entries, suite_reintroduced, suite_na = [], [], []
    if not args.no_regression_add:
        for f in classified:
            if f["version"] != "base":
                continue  # Regression entries require an issue reproduced on the base
            if f["id"] not in replays or not replays[f["id"]]["stable"]:
                continue  # Do not add unstable findings to the regression suite
            e, new = regress_mod.add_entry(reg_dir, cfg.name, f, f.get("minimize"),
                                           run_id, base_commit)
            f["regression_entry"] = e["id"]
            if new:
                added_entries.append(e["id"])
            w = f.get("witness")
            if w and w.get("id") in replays and replays[w["id"]]["stable"]:
                # Add a bypass only if the same signature also appears on the base (two-sided expectation)
                wm = w.get("minimize") or {}
                wp = wm.get("minimized_path") if wm.get("verified_signature") else None
                wp = wp or w["input_path"]
                chk = evidence_mod.analyze(run_input(binaries["base_sanitized"], wp,
                                                     cfg.input_method, cfg.limits, True))
                if chk.get("confirmed") and evidence_mod.signature(chk) == f["signature"]:
                    wf = {**f, "input": w["input"], "input_path": w["input_path"]}
                    e2, new2 = regress_mod.add_entry(reg_dir, cfg.name, wf, wm, run_id,
                                                     base_commit, variant="bypass")
                    w["regression_entry"] = e2["id"]
                    if new2:
                        added_entries.append(e2["id"])
    suite_total = suite_ok = 0
    if not args.no_regression_verify:
        suite = regress_mod.load_suite(reg_dir, cfg.name)
        suite_total = len(suite.get("entries", []))
        if suite_total:
            suite_verification = regress_mod.verify_suite(
                suite, reg_dir, binaries["base_sanitized"], binaries["patched_sanitized"],
                cfg, run_input, base_commit=base_commit)
            suite_ok = sum(1 for r in suite_verification if r["ok"])
            for r in suite_verification:
                if r.get("missing_input"):
                    stale_entries.append(f"Input for regression entry {r['id']} not found")
                    continue
                if not r["checks"]["patched"]["ok"]:
                    suite_reintroduced.append(
                        f"Regression entry {r['id']}: known security issue "
                        f"({r['expect']}) observed on the patched version")
                if not r["checks"]["base"]["ok"]:
                    if r["base_applicable"]:
                        stale_entries.append(
                            f"Regression entry {r['id']} ({r['expect']}) no longer reproduces on the same "
                            f"base revision from which it was recorded "
                            f"(stale or unstable entry)")
                    else:
                        suite_na.append(r["id"])

    # --------------------------------------------------------------- 12) Functional checks
    func_rows = _functional_rows(cfg, matrix)
    func_regressions = [
        f"Test '{t['name']}' ({t['kind']}) met the independent reference on the base "
        f"(exit={t['expect_exit']}" + (f", '{t['expect_stdout']}'" if t['expect_stdout'] else "")
        + f") but the patched version violated it ({t['patched']})"
        for t in func_rows if t["regression"]]

    # --------------------------------------------------------------- 13) Decision
    vuln_remains = []
    for f in classified:
        if f["status"] == "INCOMPLETE_FIX":
            vuln_remains.append(
                f"Finding {f['id']} ({f['signature']}) still reproduces on the patched version with "
                f"input {', '.join(f['patched_inputs'])} (INCOMPLETE_FIX)")
        elif f["status"] == "NEW_ISSUE":
            vuln_remains.append(
                f"New confirmed security issue (NEW_ISSUE): {f['id']} ({f['signature']}) with "
                f"input {', '.join(f['inputs'])} only on the patched version; patch correlation: "
                f"{f['correlation']['status']}")
    vstate = {
        "base_confirmed_findings": base_findings,
        "unstable_findings": unstable,
        "unclassified_terminations": unclassified + protection_only,
        "resource_limit_events": resource_events,
        "stale_suite_entries": stale_entries,
        "func_regressions": func_regressions,
        "vuln_remains": vuln_remains + suite_reintroduced,
        "mandatory_complete": mandatory_complete,
    }
    decision = verdict.decide(vstate)

    # --------------------------------------------------------------- 14) Reporting
    tests_meta = {}
    for name, row in matrix.items():
        tests_meta[name] = {"kind": row["kind"],
                            "expect_exit": row["case"].get("expect_exit"),
                            "results": {v: {
                                "exit_code": row["runs"][v].get("exit_code"),
                                "signal": (evidence_mod.signal_name(row["runs"][v]["signal"])
                                           if row["runs"][v].get("signal") else None),
                                "timed_out": bool(row["runs"][v].get("timed_out")),
                                "mechanism": row["ev"][v].get("mechanism"),
                                "signature": (evidence_mod.signature(row["ev"][v])
                                              if row["ev"][v].get("confirmed") else None),
                            } for v in VARIANTS}}
    for f in classified:
        f.pop("input_path", None)
        if f.get("minimize"):
            f["minimize"].pop("minimized_path", None)
        w = f.get("witness")
        if w:
            w.pop("input_path", None)
            w.pop("evidence", None)  # Same finding signature; full evidence is in release_view
            if w.get("minimize"):
                w["minimize"].pop("minimized_path", None)

    jr = {
        "run_id": run_id,
        "tool_version": __version__,
        "target": cfg.name,
        "config_path": cfg.path,
        "refs": {"base": args.base_ref, "patched": args.patched_ref},
        "commits": {"base": base_commit, "patched": patched_commit},
        "subjects": ctx["subjects"],
        "builds": {k: {kk: vv for kk, vv in v.items() if kk not in ("log_tail", "binary")}
                   for k, v in builds.items()},
        "binaries": {f"{k}_sha": b["sha256"] for k, b in builds.items()},
        "build_flags": {"release": cfg.flags["release"], "sanitized": cfg.flags["sanitized"]},
        "build_commands": {k: v["command"] for k, v in builds.items()},
        "environment": {"sanitized_env": effective_env(True), "limits": cfg.limits,
                        "input_method": cfg.input_method, "jobs": jobs,
                        "sanitizer_runtime_retried_runs": retried,
                        "replays": args.replays},
        "limits": cfg.limits,
        "hardening": {"base": hard_base, "patched": hard_patched, "comparison": hard_cmp},
        "diff_stat": diff_stat,
        "diff_files": {p: {k: v for k, v in info.items()}
                       for p, info in diff["files"].items()},
        "summary": {
            "runs_total": runs_total,
            "runs_release": sum(1 for row in matrix.values()
                                for k in row["runs"] if k.endswith("release")),
            "runs_sanitized": sum(1 for row in matrix.values()
                                  for k in row["runs"] if k.endswith("sanitized")),
            "tests": {k: len(cfg.tests[k]) for k in ("valid", "boundary", "invalid")},
            "base_findings": len(base_findings),
            "patched_findings": len(patched_findings),
            "status_counts": {s: sum(1 for f in classified if f["status"] == s)
                              for s in ("FIXED", "INCOMPLETE_FIX", "NEW_ISSUE")},
            "func_regressions": len(func_regressions),
        },
        "findings": classified,
        "func_results": func_rows,
        "anomalies": {"unclassified_terminations": unclassified,
                      "protection_only_detections": protection_only,
                      "resource_limit_events": resource_events,
                      "unstable_findings": unstable},
        "tests": tests_meta,
        "regression_suite": {
            "total": suite_total, "verified_ok": suite_ok,
            "added": added_entries, "verification": suite_verification,
            "not_applicable_to_base": suite_na,
            "dir": _rel(os.path.join(reg_dir, cfg.name), root),
        },
        "bundles": bundles,
        "bundles_dir": _rel(bundles_dir, root),
        "verdict": decision,
        "duration_sec": round(time.time() - started, 2),
        "interpretation": [
            "The identity used for replay/minimization/regression is error type + access direction + "
            "top application function in the instrumented build, not just a nonzero exit code.",
            "Before/after comparisons use matching build modes; normal (release) behavior "
            "is recorded separately from instrumented (sanitized) behavior in each finding's release_view.",
            "FIXED means not observed within the defined tests, not proof that "
            "all vulnerabilities are absent.",
            "Exit-code priority for concurrent conditions: 30, 10, 20, 40, 0 (assignment); all "
            "independent conditions remain in verdict.flags.",
        ],
    }
    _write_outputs(jr, state)
    if not args.quiet:
        print(report_mod.render_console(jr))
    return decision["exit_code"]


def main(argv=None):
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    try:
        return run_scenario(sys.argv[1:] if argv is None else argv)
    except SystemExit as e:  # argparse: invalid arguments → configuration error
        return EXIT_BUILD_OR_CONFIG_ERROR if e.code not in (0, None) else 0
    except Exception as e:  # Tool/environment error → 30
        log.exception("Internal tool error")
        print(f"BUILD_OR_CONFIG_ERROR: internal tool/environment error: {e}", file=sys.stderr)
        return EXIT_BUILD_OR_CONFIG_ERROR


if __name__ == "__main__":
    sys.exit(main())
