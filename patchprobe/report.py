"""Reporting: structured JSON and human-readable console/Markdown summaries.

Human-readable reports serve developers; all findings, statuses, evidence,
versions, and settings remain in JSON as required. Both renderers also support
partial reports from an early exit with code 30.
"""
import io

STATUS_FA = {
    "FIXED": "Fixed (within the test scope)",
    "INCOMPLETE_FIX": "Incomplete fix / issue remains",
    "NEW_ISSUE": "Newly observed issue",
    "FUNC_REGRESSION": "Functional regression",
    "INCONCLUSIVE": "Inconclusive (insufficient evidence)",
}

CORR_FA = {
    "STRONG": "Strong correlation (top frame in a changed function)",
    "MODERATE": "Moderate correlation (changed function in the stack)",
    "SAME_FILE": "File-level overlap only",
    "NONE": "No reliable correlation (Inconclusive)",
}

VARIANT_FA = {
    "base_release": "base/release", "base_sanitized": "base/sanitized",
    "patched_release": "patched/release", "patched_sanitized": "patched/sanitized",
}


def _short(c):
    return (c or "?")[:10]


def _term(v):
    if not v:
        return "—"
    if v.get("timed_out"):
        return "TIMEOUT"
    s = f"exit={v.get('exit_code')}"
    if v.get("signal"):
        s = f"signal={v['signal']}"
    if v.get("mechanism"):
        s += f" [{v['mechanism']}]"
    return s


def render_console(jr: dict) -> str:
    """Render a human-readable console/pipeline summary."""
    buf = io.StringIO()
    w = buf.write
    v = jr.get("verdict", {})
    commits = jr.get("commits") or {}
    refs = jr.get("refs") or {}
    w("=" * 74 + "\n")
    w(f"PatchProbe — patch validation for '{jr.get('target', '?')}'\n")
    w(f"  Base: {refs.get('base')} ({_short(commits.get('base'))})   "
      f"Patched: {refs.get('patched')} ({_short(commits.get('patched'))})\n")
    w(f"  Verdict: {v.get('name')} (exit code {v.get('exit_code')})\n")
    for r in v.get("reasons", []):
        w(f"    - {r}\n")
    flags = v.get("flags") or {}
    if flags:
        on = [k for k, val in flags.items() if val]
        w(f"  Independent conditions: {', '.join(on) if on else 'none'}\n")
    w("-" * 74 + "\n")
    summ = jr.get("summary") or {}
    if summ.get("runs_total"):
        w(f"Executions: {summ['runs_total']} runs on 2 versions × 2 builds (release/sanitized)\n")
    if jr.get("findings"):
        w("Findings:\n")
        for f in jr["findings"]:
            ev = f.get("evidence") or {}
            w(f"  [{f['status']}] {f['id']}: {ev.get('error_type')}"
              f" ({ev.get('rw') or '-'}) detected by {ev.get('mechanism')}\n")
            top = ev.get("top") or {}
            w(f"      Location: {top.get('func')} @ {top.get('file')}:{top.get('line')}"
              f" | Input: {f.get('input')}\n")
            corr = f.get("correlation") or {}
            w(f"      Patch correlation: {CORR_FA.get(corr.get('status'), '?')}\n")
            if f.get("witness"):
                w(f"      Candidate bypass witness: {f['witness'].get('input')}\n")
            rv = f.get("release_view") or {}
            if rv:
                w(f"      Release build: base {_term(rv.get('base_release'))} | "
                  f"patched {_term(rv.get('patched_release'))}\n")
    elif summ.get("runs_total"):
        w("No findings recorded.\n")
    if jr.get("func_results"):
        bad = [t for t in jr["func_results"] if not t["ok"]]
        w(f"Functional tests (independent reference): {len(jr['func_results'])} cases, "
          f"failed: {len(bad)}\n")
        for t in bad:
            mark = "✗ regression" if t.get("regression") else "✗"
            w(f"  {mark} {t['name']}: base=[{t['base']}] patched=[{t['patched']}]\n")
    an = jr.get("anomalies") or {}
    for key, label in (("unclassified_terminations", "Unclassified termination"),
                       ("protection_only_detections", "Binary-protection-only detection"),
                       ("resource_limit_events", "Time/resource limit exceeded")):
        for item in an.get(key, []):
            w(f"  ! {label}: {item}\n")
    h = jr.get("hardening") or {}
    if h.get("base") and h.get("patched"):
        hb, hp = h["base"], h["patched"]
        w("Hardening (release): ")
        for k, label in (("pie", "PIE"), ("nx", "NX"), ("stack_canary", "Canary")):
            key = "present" if k == "stack_canary" else "enabled"
            w(f"{label}={'✓' if hb[k][key] else '✗'}")
            if hb[k][key] != hp[k][key]:
                w(f"→{'✓' if hp[k][key] else '✗'}")
            w("  ")
        w(f"RELRO={hb['relro']['level']}"
          + (f"→{hp['relro']['level']}" if hb["relro"]["level"] != hp["relro"]["level"] else "")
          + "\n")
        for warn in (h.get("comparison") or {}).get("warnings", []):
            w(f"  ⚠ {warn}\n")
    rs = jr.get("regression_suite")
    if rs:
        w(f"Regression suite: {rs['total']} entries, verified this run: "
          f"{rs['verified_ok']}/{rs['total']}"
          + (f", new: {', '.join(rs['added'])}" if rs.get("added") else "") + "\n")
    if jr.get("bundles"):
        w(f"Reproduction bundles: {len(jr['bundles'])} in {jr.get('bundles_dir')}\n")
    if jr.get("duration_sec") is not None:
        w(f"Duration: {jr['duration_sec']} seconds\n")
    w("=" * 74 + "\n")
    return buf.getvalue()


def render_markdown(jr: dict) -> str:
    """Render a detailed Markdown report for pipeline archives."""
    buf = io.StringIO()
    w = buf.write
    v = jr.get("verdict", {})
    commits = jr.get("commits") or {}
    subjects = jr.get("subjects") or {}
    refs = jr.get("refs") or {}
    w(f"# PatchProbe report — {jr.get('target', '?')}\n\n")
    w(f"- Run: `{jr.get('run_id')}` (PatchProbe {jr.get('tool_version')})\n"
      f"- Base version: `{refs.get('base')}` ({(commits.get('base') or '?')[:12]}"
      f" — «{subjects.get('base', '')}»)\n"
      f"- Patched version: `{refs.get('patched')}` ({(commits.get('patched') or '?')[:12]}"
      f" — «{subjects.get('patched', '')}»)\n"
      f"- **Verdict: {v.get('name')} (exit code {v.get('exit_code')})**\n\n")
    w("## Verdict reasons\n\n")
    for r in v.get("reasons", []):
        w(f"- {r}\n")
    if v.get("flags"):
        w("\n| Independent condition | Value |\n|---|---|\n")
        for k, val in v["flags"].items():
            w(f"| {k} | {'✓' if val else '—'} |\n")
    if jr.get("interpretation"):
        w("\n## Interpreting the results\n\n")
        for line in jr["interpretation"]:
            w(f"- {line}\n")

    if jr.get("summary", {}).get("runs_total"):
        w("\n## Findings\n\n")
        if jr.get("findings"):
            w("| ID | Status | Error type | Mechanism | Location (instrumented build) | "
              "Input | Diff correlation |\n|---|---|---|---|---|---|---|\n")
            for f in jr["findings"]:
                ev = f.get("evidence") or {}
                top = ev.get("top") or {}
                corr = f.get("correlation") or {}
                w(f"| {f['id']} | {STATUS_FA.get(f['status'], f['status'])} | "
                  f"{ev.get('error_type')} {ev.get('rw') or ''} | "
                  f"{ev.get('mechanism')} | "
                  f"{top.get('func')} @ {top.get('file')}:{top.get('line')} | "
                  f"`{f.get('input')}` | {CORR_FA.get(corr.get('status'), corr.get('status'))} |\n")
            for f in jr["findings"]:
                ev = f.get("evidence") or {}
                w(f"\n### {f['id']} — {STATUS_FA.get(f['status'], f['status'])} — "
                  f"`{f['signature']}`\n\n")
                w(f"- Criterion: {f.get('why')}\n")
                w(f"- Evidence summary: `{ev.get('summary_line')}`\n")
                if ev.get("frames"):
                    stack = " ← ".join(f"{fr.get('func')}" for fr in ev["frames"][:6])
                    w(f"- Call stack: {stack}\n")
                w(f"- Triggering inputs: {', '.join(f.get('inputs', []))}\n")
                corr = f.get("correlation") or {}
                w(f"- Correlation evidence: {corr.get('evidence')}\n")
                w(f"- Changed functions: "
                  f"{', '.join(corr.get('changed_functions') or []) or '—'}\n")
                d = corr.get("differential") or {}
                if d:
                    w(f"- Differential evidence (same input on both versions): {d.get('note')}\n")
                rv = f.get("release_view") or {}
                if rv:
                    w("- Termination in all four builds:\n")
                    for var in ("base_release", "base_sanitized",
                                "patched_release", "patched_sanitized"):
                        w(f"  - {VARIANT_FA[var]}: {_term(rv.get(var))}\n")
                if f.get("replay"):
                    rp = f["replay"]
                    w(f"- Stability: {'stable' if rp['stable'] else 'unstable'} "
                      f"({len(rp['runs'])} replays: "
                      f"{', '.join(str(r.get('signature')) for r in rp['runs'])})\n")
                if f.get("minimize"):
                    m = f["minimize"]
                    w(f"- Minimization: {m['original_size']} → {m['minimized_size']} bytes "
                      f"({m['calls']} executions; verified signature: {m.get('verified_signature')})\n")
                if f.get("bundle"):
                    w(f"- Reproduction bundle: `{f['bundle']}`\n")
                if f.get("regression_entry"):
                    w(f"- Regression entry: `{f['regression_entry']}`\n")
                wt = f.get("witness")
                if wt:
                    w(f"- **Patch bypass witness** (still triggers the patched version): "
                      f"`{wt.get('input')}`")
                    wm = wt.get("minimize") or {}
                    if wm:
                        w(f" — minimized on the candidate: {wm.get('original_size')} → "
                          f"{wm.get('minimized_size')} bytes")
                    w("\n")
                    if wt.get("bundle"):
                        w(f"  - Candidate reproduction bundle: `{wt['bundle']}`\n")
                    if wt.get("regression_entry"):
                        w(f"  - Bypass regression entry: `{wt['regression_entry']}`\n")
        else:
            w("No findings recorded.\n")

        an = jr.get("anomalies") or {}
        if any(an.get(k) for k in an):
            w("\n## Events with insufficient evidence\n\n")
            for key, label in (("unclassified_terminations", "Unclassified termination"),
                               ("protection_only_detections", "Binary-protection-only detection"),
                               ("resource_limit_events", "Time/resource limit exceeded"),
                               ("unstable_findings", "Unstable finding")):
                for item in an.get(key, []):
                    w(f"- {label}: {item}\n")

        w("\n## Functional tests (independent reference)\n\n")
        if jr.get("func_results"):
            w("| Test | Category | Expectation | Base | Patched | Status |\n|---|---|---|---|---|---|\n")
            for t in jr["func_results"]:
                status = "✓" if t["ok"] else ("✗ regression" if t.get("regression")
                                              else "✗ (base also failed the reference)")
                w(f"| `{t['name']}` | {t.get('kind')} | exit={t['expect_exit']}"
                  f"{' «' + str(t['expect_stdout']) + '»' if t.get('expect_stdout') else ''} | "
                  f"{t['base']} | {t['patched']} | {status} |\n")

        tests = jr.get("tests") or {}
        if tests:
            w("\n## Full execution matrix (four builds, matching settings)\n\n")
            w("| Test | Category | Base/release | Base/sanitized | Patched/release | Patched/sanitized |\n"
              "|---|---|---|---|---|---|\n")
            for name, t in tests.items():
                r = t["results"]

                def cell(x):
                    s = "TIMEOUT" if x["timed_out"] else (
                        f"sig={x['signal']}" if x.get("signal") else f"exit={x['exit_code']}")
                    return s + (f" **{x['signature']}**" if x.get("signature") else "")
                w(f"| `{name}` | {t['kind']} | {cell(r['base_release'])} | "
                  f"{cell(r['base_sanitized'])} | {cell(r['patched_release'])} | "
                  f"{cell(r['patched_sanitized'])} |\n")

    h = jr.get("hardening")
    if h and h.get("base"):
        w("\n## Binary hardening (release build)\n\n")
        w("| Protection | Base | Patched | Base evidence | Patched evidence |\n|---|---|---|---|---|\n")
        hb, hp = h["base"], h["patched"]
        rows = (("PIE", "pie", "enabled"), ("NX", "nx", "enabled"),
                ("Stack Canary", "stack_canary", "present"))
        for label, k, key in rows:
            w(f"| {label} | {'✓' if hb[k][key] else '✗'} | {'✓' if hp[k][key] else '✗'} | "
              f"{hb[k]['evidence']} | {hp[k]['evidence']} |\n")
        w(f"| RELRO | {hb['relro']['level']} | {hp['relro']['level']} | "
          f"{hb['relro']['evidence']} | {hp['relro']['evidence']} |\n")
        if hb.get("fortify_source"):
            w(f"| FORTIFY (supplementary) | {'✓' if hb['fortify_source']['present'] else '✗'} | "
              f"{'✓' if hp['fortify_source']['present'] else '✗'} | "
              f"{hb['fortify_source']['evidence']} | {hp['fortify_source']['evidence']} |\n")
        for warn in (h.get("comparison") or {}).get("warnings", []):
            w(f"\n- ⚠ {warn}\n")
        for c in hb.get("caveats", []):
            w(f"- Caveat: {c}\n")

    summ = jr.get("summary") or {}
    if summ.get("runs_total"):
        w("\n## Recorded executions\n\n")
        w(f"Total: {summ['runs_total']} target executions "
          f"({summ.get('runs_release')} release, {summ.get('runs_sanitized')} "
          f"instrumented); tests: {summ.get('tests')}.\n")
    rs = jr.get("regression_suite")
    if rs:
        w("\n## Regression test suite\n\n")
        w(f"- Existing entries: {rs['total']} (in `{rs.get('dir')}`)\n"
          f"- Verified this run: {rs['verified_ok']}\n"
          f"- New entries this run: {', '.join(rs.get('added', [])) or '—'}\n")
        for row in rs.get("verification", []):
            chk = row.get("checks") or {}
            na = "" if row.get("base_applicable", True) else " (different base; base-side result is informational)"
            w(f"  - `{row['id']}` {row['expect']}: {'✓' if row['ok'] else '✗'} "
              f"(base: {(chk.get('base') or {}).get('signature')}, "
              f"patched: {(chk.get('patched') or {}).get('signature')}){na}\n")

    w("\n## Evidence and settings\n\n")
    builds = jr.get("builds") or {}
    for k, b in builds.items():
        w(f"- `{k}`: sha256=`{b.get('sha256')}` — `{b.get('command')}`\n")
    if jr.get("environment"):
        w(f"- Runtime environment: `{jr['environment']}`\n")
    w(f"- Configuration file: `{jr.get('config_path')}`\n")
    if jr.get("diff_stat"):
        w(f"\n### Diff statistics\n\n```\n{jr['diff_stat']}\n```\n")
    return buf.getvalue()
