"""PatchProbe — automated security patch validation and regression testing in CI/CD.

Data and Network Security course project — Sharif University of Technology.
"""
import os

__version__ = "1.1.0"

# ------------------------------------------------------------------ Exit codes
# 0   PASS               Valid patch: the base issue reproduced and was not observed
#                       in the candidate within the test scope; functional checks passed.
# 10  VULN_REMAINS      The original issue remains, or a new security issue (NEW_ISSUE)
#                       was confirmed with valid evidence.
# 20  FUNC_REGRESSION   At least one functional reference test that passed on the base
#                       failed on the candidate, independently of security findings.
# 30  BUILD_OR_CONFIG_ERROR  Target build failure, invalid configuration, or tool/environment error.
# 40  INCONCLUSIVE      Mandatory checks were incomplete or evidence was insufficient
#                       (no base reproduction, unstable finding, unclassified termination).
#
# Priority for concurrent conditions (assignment, section 3.5): 30, 10, 20, 40, 0 — verdict.py
EXIT_PASS = 0
EXIT_VULN_REMAINS = 10
EXIT_FUNC_REGRESSION = 20
EXIT_BUILD_OR_CONFIG_ERROR = 30
EXIT_INCONCLUSIVE = 40

EXIT_CODE_NAMES = {
    EXIT_PASS: "PASS",
    EXIT_VULN_REMAINS: "VULN_REMAINS",
    EXIT_FUNC_REGRESSION: "FUNC_REGRESSION",
    EXIT_BUILD_OR_CONFIG_ERROR: "BUILD_OR_CONFIG_ERROR",
    EXIT_INCONCLUSIVE: "INCONCLUSIVE",
}


def project_root_from(path: str) -> str:
    """Find the project root from the config path: first ancestor with targets/ or patchprobe/."""
    d = os.path.dirname(os.path.abspath(path))
    for _ in range(4):
        if os.path.isdir(os.path.join(d, "targets")) or os.path.isdir(os.path.join(d, "patchprobe")):
            return d
        d = os.path.dirname(d)
    return os.path.dirname(os.path.abspath(path))
