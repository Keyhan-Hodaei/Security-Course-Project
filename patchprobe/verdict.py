"""Final verdict and standard exit codes.

Exit-code priority follows assignment section 3.5 exactly:
    When conditions coexist, priority is 30, 10, 20, 40, then 0.

1. 30 BUILD_OR_CONFIG_ERROR — build/configuration/tool failure prevents further
   judgment. The CLI reports this early, without combining it with security
   findings or patch approval.
2. 10 VULN_REMAINS — the original issue remains in the candidate (INCOMPLETE_FIX),
   a new memory/security issue has valid sanitizer evidence (NEW_ISSUE),
   or a regression-suite signature reappeared on the candidate.
   An unclassified termination alone never produces code 10.
3. 20 FUNC_REGRESSION — at least one functional test with an independent reference
   passed on the base but failed on the candidate; this condition is recorded
   independently of the security findings.
4. 40 INCONCLUSIVE — mandatory checks were incomplete or evidence insufficient:
   no reproduced base finding, unstable findings, unclassified termination, time/resource
   limits, or a regression entry no longer reproducing on its recorded base revision.
5. 0 PASS — none of the above: the base issue reproduced, was not observed on
   the candidate, no other confirmed security issue was recorded, and all functional
   tests and mandatory checks succeeded and completed.

Independent security, functionality, and analysis-completeness conditions are returned
in flags separately from the final code, preserving them in JSON.
"""

PRIORITY = (30, 10, 20, 40, 0)

NAMES = {
    0: "PASS",
    10: "VULN_REMAINS",
    20: "FUNC_REGRESSION",
    30: "BUILD_OR_CONFIG_ERROR",
    40: "INCONCLUSIVE",
}


def _inconclusive_reasons(state: dict) -> list:
    reasons = []
    if not state.get("base_confirmed_findings"):
        reasons.append("No confirmed memory error reproduced on the base within "
                       "the test scope; a security judgment about the patch is not possible "
                       "(base issue did not reproduce).")
    for f in state.get("unstable_findings") or []:
        reasons.append(f"Unstable finding (the same signature did not repeat in every replay): {f}")
    for t in state.get("unclassified_terminations") or []:
        reasons.append(f"Unclassified termination (without sanitizer evidence): {t}")
    for t in state.get("resource_limit_events") or []:
        reasons.append(f"Time/resource limit exceeded; this test was not completed: {t}")
    for t in state.get("stale_suite_entries") or []:
        reasons.append(t)
    if not state.get("mandatory_complete", True):
        reasons.append("Mandatory checks were incomplete (some tests could not be executed).")
    return reasons


def decide(state: dict) -> dict:
    """Accept CLI state; return {exit_code, name, reasons[], flags{}}.

    flags preserves independent conditions: for example, a patch with both a remaining
    issue and a functional regression returns code 10 and flags.func_regression=True.
    """
    if state.get("build_error"):
        return {"exit_code": 30, "name": NAMES[30],
                "reasons": [state["build_error"]],
                "flags": {"build_or_config_error": True},
                "priority": list(PRIORITY)}

    vuln = list(state.get("vuln_remains") or [])
    func = list(state.get("func_regressions") or [])
    inconc = _inconclusive_reasons(state)

    flags = {
        "build_or_config_error": False,
        "vuln_remains": bool(vuln),
        "func_regression": bool(func),
        "inconclusive": bool(inconc),
    }

    if vuln:
        code, reasons = 10, vuln
    elif func:
        code, reasons = 20, func
    elif inconc:
        code, reasons = 40, inconc
    else:
        code = 0
        reasons = ["The target issue reproduced on the base and was not observed on the "
                   "patched version within the test scope; no other confirmed security issue "
                   "was recorded, and all functional tests and mandatory checks succeeded "
                   "and completed."]

    # Include simultaneous lower-priority conditions in reasons without changing the code
    secondary = []
    if code == 10 and func:
        secondary += [f"[Concurrent, lower priority — 20] {t}" for t in func]
    if code in (10, 20) and inconc:
        secondary += [f"[Concurrent, lower priority — 40] {t}" for t in inconc]

    return {"exit_code": code, "name": NAMES[code],
            "reasons": reasons + secondary, "flags": flags,
            "priority": list(PRIORITY)}
