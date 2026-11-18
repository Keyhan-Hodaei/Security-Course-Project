"""Automatic input reduction using delta debugging (ddmin).

Preserving the same error requires the candidate input, on the instrumented build
of the version where the finding occurred, to produce confirmed evidence with the
same error type and top function (signature); a nonzero exit alone is insufficient.
"""
import logging
import os
import tempfile

from . import evidence

log = logging.getLogger("patchprobe.minimize")


def ddmin(data: bytes, predicate) -> bytes:
    """Byte-based ddmin using complement deletion.

    predicate(candidate) is True if the same signature occurs. Divide the input into n
    chunks and try deleting each chunk; on success continue with a coarser partition,
    otherwise double the granularity until
    single-byte deletions are reached. A 1-minimal result means no single byte can be
    removed while preserving the error, subject to the execution budget.
    """
    cur = data
    n = 2
    while len(cur) >= 2:
        chunk = max(1, len(cur) // n)
        reduced = False
        start = 0
        while start < len(cur):
            cand = cur[:start] + cur[start + chunk:]
            if cand and predicate(cand):
                cur = cand
                n = max(n - 1, 2)
                reduced = True
                break
            start += chunk
        if not reduced:
            if chunk == 1:
                break
            n = min(len(cur), n * 2)
    return cur


class Minimizer:
    def __init__(self, run_fn, budget=60, workdir=None):
        """run_fn(input_path) → RunResult."""
        self.run = run_fn
        self.budget = budget
        self.calls = 0
        self.tmpdir = tempfile.mkdtemp(prefix="pp-min-", dir=workdir)

    def _check(self, data: bytes, want_sig: str) -> bool:
        if self.calls >= self.budget:
            return False
        self.calls += 1
        p = os.path.join(self.tmpdir, "cand.bin")
        with open(p, "wb") as f:
            f.write(data)
        res = self.run(p)
        if res.get("timed_out") or not res.get("ran"):
            return False
        ev = evidence.analyze(res)
        return bool(ev.get("confirmed")) and evidence.signature(ev) == want_sig

    def minimize(self, input_path: str, want_sig: str) -> dict:
        """Return {minimized_path, original_size, minimized_size, calls, success, verified}."""
        with open(input_path, "rb") as f:
            data = f.read()
        out_path = os.path.join(self.tmpdir, "minimized.bin")
        try:
            small = ddmin(data, lambda d: self._check(d, want_sig))
        except Exception as e:  # pragma: no cover
            log.warning("minimize failed: %s", e)
            small = data
        with open(out_path, "wb") as f:
            f.write(small)
        budget_hit = self.calls >= self.budget
        # Final verification outside the budget: reduced input must preserve the signature
        res = self.run(out_path)
        ev = evidence.analyze(res)
        verified = bool(ev.get("confirmed")) and evidence.signature(ev) == want_sig
        if not verified:  # Never keep a reduction that fails to preserve the signature
            small = data
            with open(out_path, "wb") as f:
                f.write(small)
        return {"original_size": len(data), "minimized_size": len(small),
                "calls": self.calls, "budget": self.budget,
                "budget_exhausted": budget_hit,
                "minimized_path": out_path, "success": len(small) < len(data),
                "verified_signature": want_sig if verified else None}
