"""Correlate findings with patch changes (Patch-to-Finding Correlation).

Correlation evidence, strongest to weakest:
1. STRONG — the top error frame is in a changed function.
2. MODERATE — a changed function occurs deeper in the error stack.
3. SAME_FILE — only the error's file changed; its function did not.
4. NONE — no overlap; report an inconclusive patch relationship.

Assignment requirements addressed here:
- The error need not occur on a changed line; a change in a caller can affect
  another function, so intermediate stack frames also provide evidence.
- Visual proximity of a static warning to changed code is insufficient:
  without execution evidence, the relationship is inconclusive.
"""
import os

from .cparse import scan_functions, functions_overlapping


def enrich_diff_with_functions(diff: dict, base_dir: str, patched_dir: str) -> dict:
    """Add changed function names to diff_hunks using both source versions."""
    for path, info in diff["files"].items():
        for side, src_root, ranges, key in (
            ("old", base_dir, info["old_ranges"], "old_functions"),
            ("new", patched_dir, info["new_ranges"], "new_functions"),
        ):
            full = os.path.join(src_root, path)
            if os.path.isfile(full):
                with open(full, encoding="utf-8", errors="replace") as f:
                    funcs = scan_functions(f.read())
                info[key] = [f["name"] for f in functions_overlapping(funcs, ranges)]
            else:
                info[key] = []
    return diff


def differential(finding: dict, row_runs: dict) -> dict:
    """Differential evidence: the same input on both versions with matching settings.

    row_runs: {variant: evidence-dict} for the representative input. Return a summary
    of whether the same signature was observed in each version/build and its interpretation.
    """
    from .evidence import signature
    sig = finding["signature"]
    seen = {}
    for variant, ev in row_runs.items():
        s = signature(ev) if ev.get("confirmed") else None
        seen[variant] = {"signature": s, "same": s == sig,
                         "mechanism": ev.get("mechanism")}
    b, p = seen.get("base_sanitized", {}), seen.get("patched_sanitized", {})
    if b.get("same") and not p.get("same"):
        note = "Same input: error on the base but not the candidate — behavior changed after the patch"
    elif p.get("same") and not b.get("same"):
        note = "Same input: error only after the patch — new behavior following the patch changes"
    elif b.get("same") and p.get("same"):
        note = "Same input produces the same signature on both versions — the patch leaves this path open"
    else:
        note = "The representative input produced the expected signature on neither version"
    return {"by_variant": seen, "note": note}


def correlate(finding: dict, diff: dict) -> dict:
    """Correlate a finding and its frames with changed functions/files."""
    frames = [f for f in finding["evidence"].get("frames", []) if f.get("func")]
    changed_funcs = set()
    changed_files = set()
    for path, info in diff["files"].items():
        changed_files.add(os.path.basename(path))
        for k in ("old_functions", "new_functions"):
            changed_funcs.update(info.get(k) or [])

    top = finding["evidence"].get("top") or {}
    top_func = top.get("func")
    matched_frames = []
    for f in frames:
        if f["func"] in changed_funcs:
            matched_frames.append(f)

    if top_func and top_func in changed_funcs:
        status, why = "STRONG", (f"The top error frame is in changed function '{top_func}'")
    elif matched_frames:
        status = "MODERATE"
        why = "Changed functions occur in the error stack: " + \
              ", ".join(sorted({f['func'] for f in matched_frames}))
    elif top.get("file") and top["file"] in changed_files:
        status, why = "SAME_FILE", (
            f"File '{top['file']}' changed, but the error's function "
            f"'{top_func or '?'}' did not change directly")
    else:
        status, why = "NONE", (
            "No changed function or file overlaps the error location; "
            "the patch relationship for this finding is inconclusive")

    return {
        "status": status,
        "evidence": why,
        "changed_functions": sorted(changed_funcs),
        "changed_files": sorted(changed_files),
        "matched_frames": matched_frames[:6],
    }


def classify_findings(base_findings, patched_findings) -> list:
    """Classify findings: FIXED / INCOMPLETE_FIX / NEW_ISSUE / UNCHANGED.

    base_findings, patched_findings: findings with signatures and triggering inputs.
    Matching uses signatures; details of each
    input are also retained.
    """
    base_sigs = {f["signature"]: f for f in base_findings}
    patched_sigs = {f["signature"]: f for f in patched_findings}
    out = []
    for sig, f in base_sigs.items():
        if sig in patched_sigs:
            pf = patched_sigs[sig]
            out.append({**f, "status": "INCOMPLETE_FIX",
                        "patched_inputs": pf.get("inputs", []),
                        # Bypass witness: an input that still triggers the patched version
                        "witness": {"id": pf.get("id"), "input": pf.get("input"),
                                    "input_path": pf.get("input_path"),
                                    "evidence": pf.get("evidence")},
                        "why": "The same error signature was also observed in the patched version"})
        else:
            out.append({**f, "status": "FIXED",
                        "patched_inputs": [],
                        "why": "No longer observed within the defined tests"})
    for sig, pf in patched_sigs.items():
        if sig not in base_sigs:
            out.append({**pf, "status": "NEW_ISSUE",
                        "base_inputs": [],
                        "why": "An error signature not observed in the base version"})
    return out
