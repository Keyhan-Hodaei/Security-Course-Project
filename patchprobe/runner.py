"""Execute the target program on one input with process-level controls.

Process-level isolation:
- RLIMIT_CPU / RLIMIT_FSIZE / RLIMIT_NOFILE and RLIMIT_CORE=0 (no core dumps
  in the working directory), installed through preexec_fn;
- A separate process group (setsid) to terminate child processes on timeout;
- A wall-clock timeout enforced by the parent.

Important: RLIMIT_AS applies to release builds by default. AddressSanitizer needs
a huge virtual address space (several virtual terabytes) for shadow memory;
an ordinary limit can break ASan itself ('failed to allocate'). Actual memory
limits and disabled networking are supplied by docker-compose.yml.
"""
import os
import resource
import signal
import subprocess

# Effective sanitizer settings recorded in reports and reproduction bundles
SANITIZER_ENV = {
    "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0:exitcode=1:"
                    "allocator_may_return_null=1:symbolize=1",
    "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1:symbolize=1",
}


class RunResult(dict):
    """Execution result: exit_code, signal, stdout, stderr, timed_out, and related fields."""


def _make_preexec(cpu_sec, as_mb, fsize_mb, nofile):
    def apply():
        def setlim(res, soft, hard):
            try:
                resource.setrlimit(res, (soft, hard))
            except (ValueError, OSError):
                pass
        os.setsid()  # Separate session/process group for terminating the process tree
        setlim(resource.RLIMIT_CORE, 0, 0)
        setlim(resource.RLIMIT_CPU, cpu_sec, cpu_sec + 1)
        setlim(resource.RLIMIT_FSIZE, fsize_mb << 20, fsize_mb << 20)
        setlim(resource.RLIMIT_NOFILE, nofile, nofile)
        if as_mb:
            setlim(resource.RLIMIT_AS, as_mb << 20, as_mb << 20)
    return apply


def effective_env(sanitized: bool) -> dict:
    """Return effective execution environment settings for reports/bundles."""
    return dict(SANITIZER_ENV) if sanitized else {}


def build_argv(binary: str, input_path: str, method: str):
    if method == "stdin":
        return [binary]
    return [binary, input_path]


def is_sanitizer_runtime_failure(res: dict) -> bool:
    """Detect an ASan runtime startup failure (environment issue, not a finding).

    Older ASan runtimes (such as gcc 12) on kernels with high mmap randomization
    (vm.mmap_rnd_bits=32) can fail at startup with AddressSanitizer:DEADLYSIGNAL
    and no detailed ERROR report. That symptom is not evidence of a target memory error.
    """
    err = res.get("stderr") or ""
    return (bool(res.get("sanitized")) and res.get("ran")
            and "AddressSanitizer:DEADLYSIGNAL" in err
            and "ERROR: AddressSanitizer" not in err
            and "runtime error:" not in err)


_SETARCH = {"checked": False, "ok": False}


def _setarch_available() -> bool:
    """Check whether setarch -R (disable ASLR for this process only) is permitted."""
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
    """Run binary on input_path, retrying sanitizer runtime failures.

    If ASan fails at startup due to the environment, retry up to sanitizer_retries
    attempts. From the second attempt onward, use
    setarch -R (without ASLR) when available. If all attempts fail, mark the result
    sanitizer_runtime_failure so the tool reports an environment error (30)
    rather than a security finding.
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
    res["note"] = ("The sanitizer runtime failed at startup on every attempt "
                   "(environment issue: possibly high vm.mmap_rnd_bits with an older ASan runtime)")
    return res


def _run_once(binary, input_path, method, limits, sanitized, cwd, env_extra, prefix):
    timeout = float(limits.get("timeout_sec", 5))
    cpu = int(limits.get("cpu_sec", 10))
    as_mb = int(limits.get("rlimit_as_mb_sanitized" if sanitized else "rlimit_as_mb", 0) or 0)
    fsize = int(limits.get("rlimit_fsize_mb", 64))
    nofile = int(limits.get("rlimit_nofile", 64))

    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("ASAN_", "UBSAN_", "LSAN_", "MSAN_"))}
    env.update(SANITIZER_ENV)  # Ineffective in normal builds; retained for matching settings
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
                       note=f"Execution time limit exceeded ({timeout:g} seconds) — TIMEOUT")
    except Exception as e:  # Tool/environment error during execution
        res.update(exit_code=None, signal=0, timed_out=False, ran=False,
                   stdout="", stderr=str(e), note="Tool execution error")
    finally:
        if stdin_file is not None:
            stdin_file.close()
    return res
