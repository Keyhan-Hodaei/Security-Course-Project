"""Load and validate target configuration.

Each evaluation target has a JSON configuration containing everything needed
to add a new program through configuration alone:
build command, binary path, input interface, and test suite.

Build-command placeholders use simple text replacement instead of str.format,
preserving shell expressions such as ${VAR}:
  {src}     Exported source tree for this version/build combination (optional)
  {cflags}  Release or sanitized build flags (required to separate the builds)
  {mode}    release | sanitized
  {out}     Run work directory
"""
import json
import os
import subprocess

DEFAULT_LIMITS = {
    "timeout_sec": 5.0,
    "cpu_sec": 10,
    # RLIMIT_AS applies to release builds by default; ASan needs a very large
    # virtual address space for shadow memory and fails under a small limit.
    "rlimit_as_mb": 512,
    "rlimit_as_mb_sanitized": 0,   # 0 = unlimited
    "rlimit_fsize_mb": 64,
    "rlimit_nofile": 64,
}

# -U_FORTIFY_SOURCE in instrumented builds: on distributions enabling FORTIFY_SOURCE
# by default (such as Ubuntu), __*_chk checks can abort the program before ASan
# and hide detailed sanitizer evidence (error type/stack). The normal build
# keeps compiler defaults to observe the actual behavior of the final binary.
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
    """Restore the target repo if absent and an adjacent repo.bundle exists.

    Target repositories are stored as Git bundles in the project (nested repositories
    are not tracked as ordinary files). Return True if restoration was performed.
    """
    bundle = repo.rstrip("/") + ".bundle"
    if os.path.isdir(os.path.join(repo, ".git")) or not os.path.isfile(bundle):
        return False
    r = subprocess.run(["git", "clone", "-q", bundle, repo], capture_output=True, text=True)
    if r.returncode != 0:
        raise ConfigError(f"Failed to restore target repository from {bundle}: {r.stderr.strip()[:300]}")
    # Create local branches for all bundle branches (main, patch-*, ...)
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
            raise ConfigError("Configuration root must be a JSON object")
        for k in REQUIRED_KEYS:
            if k not in data:
                raise ConfigError(f"Incomplete configuration: missing key '{k}'")
        self.name = str(data["target"])
        self.repo = os.path.join(root, data["repo"])
        restore_repo_from_bundle(self.repo)
        if not os.path.isdir(os.path.join(self.repo, ".git")):
            raise ConfigError(f"Git repository not found: {self.repo} "
                              f"(restore with: bash scripts/setup_targets.sh)")

        b = data["build"]
        if not isinstance(b, dict):
            raise ConfigError("build must be an object")
        for k in ("command", "binary"):
            if not b.get(k):
                raise ConfigError("build must contain 'command' and 'binary'")
        self.build_command = b["command"]
        if "{cflags}" not in self.build_command:
            raise ConfigError("build.command must contain the {cflags} placeholder; otherwise "
                              "the instrumented and normal builds become identical")
        self.binary_relpath = b["binary"]
        self.flags = dict(DEFAULT_BUILD_FLAGS)
        self.flags.update(b.get("flags", {}))
        for mode in ("release", "sanitized"):
            if not isinstance(self.flags.get(mode), str):
                raise ConfigError(f"build.flags.{mode} must be a string")
        if "-fsanitize=" not in self.flags["sanitized"]:
            raise ConfigError("build.flags.sanitized must contain -fsanitize=...")
        if "-fsanitize=" in self.flags["release"]:
            raise ConfigError("build.flags.release must not enable sanitizers "
                              "(normal and instrumented results must remain separate)")

        inp = data["input"]
        m = inp.get("method") if isinstance(inp, dict) else None
        if m not in ("stdin", "file"):
            raise ConfigError("input.method must be 'stdin' or 'file'")
        self.input_method = m

        t = data["tests"]
        if not isinstance(t, dict):
            raise ConfigError("tests must be an object")
        for k in TEST_KINDS:
            if not isinstance(t.get(k), list):
                raise ConfigError(f"tests.{k} must be a list of test cases")
        self.tests = t
        self.tests_dir = os.path.join(root, data.get("tests_dir", ""))
        self.limits = dict(DEFAULT_LIMITS)
        self.limits.update(data.get("limits", {}))

        seen = set()
        for kind in TEST_KINDS:
            for i, case in enumerate(self.tests[kind]):
                if not isinstance(case, dict) or not case.get("name"):
                    raise ConfigError(f"tests.{kind}[{i}] must be an object with 'name'")
                if case["name"] in seen:
                    raise ConfigError(f"Duplicate test name: {case['name']}")
                seen.add(case["name"])
                p = os.path.join(self.tests_dir, case["name"])
                if not os.path.isfile(p):
                    raise ConfigError(f"Test file not found: {p} ({kind}[{i}])")
                if "expect_exit" in case and not isinstance(case["expect_exit"], int):
                    raise ConfigError(f"expect_exit for test {case['name']} must be an integer")
                case["_path"] = p
        if not seen:
            raise ConfigError("The test suite is empty")

    def all_cases(self):
        """Yield all test cases with their categories."""
        for kind in TEST_KINDS:
            for case in self.tests[kind]:
                yield kind, case

    def expect(self, case):
        """Return functional expectations: (exit code, exact stdout, stdout pattern)."""
        return (case.get("expect_exit"),
                case.get("expect_stdout"),
                case.get("expect_stdout_pattern"))


def load_config(path: str, root: str = None) -> TargetConfig:
    if not os.path.isfile(path):
        raise ConfigError(f"Configuration file not found: {path}")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ConfigError(f"Invalid configuration JSON: {e}") from e
    if root is None:
        from . import project_root_from
        root = project_root_from(path)
    return TargetConfig(path, root, data)
