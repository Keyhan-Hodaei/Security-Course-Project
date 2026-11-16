"""Git operations: resolve refs, export source trees, and calculate structured diffs."""
import io
import re
import subprocess
import tarfile


class GitError(Exception):
    pass


def _git(repo, *args, check=True):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True)
    if check and r.returncode != 0:
        raise GitError(f"git {' '.join(args)}: "
                       f"{r.stderr.decode('utf-8', 'replace').strip()[:400]}")
    return r


def _text(r):
    return r.stdout.decode("utf-8", "replace")


def resolve_commit(repo: str, ref: str) -> str:
    r = _git(repo, "rev-parse", "--verify", "--quiet", ref + "^{commit}", check=False)
    if r.returncode != 0:
        raise GitError(f"Invalid or missing ref: {ref}")
    return _text(r).strip()


def commit_subject(repo: str, ref: str) -> str:
    return _text(_git(repo, "log", "-1", "--format=%s", ref)).strip()


def export_tree(repo: str, ref: str, dest: str) -> None:
    """Export revision ref into dest without modifying the repository worktree."""
    r = _git(repo, "archive", "--format=tar", ref, check=False)
    if r.returncode != 0:
        raise GitError(f"git archive {ref} failed: "
                       f"{r.stderr.decode('utf-8', 'replace')[:200]}")
    try:
        with tarfile.open(fileobj=io.BytesIO(r.stdout)) as tf:
            for m in tf.getmembers():
                # Reject unsafe paths in the archive
                if m.name.startswith("/") or ".." in m.name.split("/"):
                    raise GitError(f"Unsafe archive path: {m.name}")
            try:
                tf.extractall(dest, filter="data")
            except TypeError:  # Older Python versions without the filter parameter
                tf.extractall(dest)
    except tarfile.TarError as e:
        raise GitError(f"Failed to extract source tree: {e}") from e


HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def parse_diff(text: str) -> dict:
    """Parse unified diff text into {path: old/new line ranges}.

    Use the new path as the key, or the old path for deleted files (+++ /dev/null),
    so their hunks are not incorrectly attributed to the preceding file.
    """
    files = {}
    cur = None
    old_path = None
    for line in text.splitlines():
        if line.startswith("diff --git "):
            cur, old_path = None, None
            continue
        if line.startswith("--- "):
            p = line[4:].strip()
            old_path = p[2:] if p.startswith("a/") else None
            continue
        if line.startswith("+++ "):
            p = line[4:].strip()
            new_path = p[2:] if p.startswith("b/") else None
            cur = new_path or old_path
            if cur:
                files.setdefault(cur, {"old_ranges": [], "new_ranges": [],
                                       "old_path": old_path, "new_path": new_path,
                                       "old_functions": [], "new_functions": []})
            continue
        m = HUNK_RE.match(line)
        if m and cur is not None:
            o1, o2, n1, n2 = m.groups()
            o1, n1 = int(o1), int(n1)
            o_len = int(o2) if o2 is not None else 1
            n_len = int(n2) if n2 is not None else 1
            if o_len:
                files[cur]["old_ranges"].append((o1, o1 + o_len - 1))
            if n_len:
                files[cur]["new_ranges"].append((n1, n1 + n_len - 1))
    return files


def diff_hunks(repo: str, base: str, patched: str) -> dict:
    """Structured diff between two revisions: {'files': {...}, 'text': full diff}.

    Use --unified=0 to identify actual changed lines, excluding context;
    otherwise an unchanged neighboring function could be counted as changed.
    """
    text0 = _text(_git(repo, "diff", "--no-color", "--no-ext-diff", "-M",
                       "--unified=0", base, patched))
    text3 = _text(_git(repo, "diff", "--no-color", "--no-ext-diff", "-M",
                       "--unified=3", base, patched))
    return {"files": parse_diff(text0), "text": text3}


def diff_stat(repo: str, base: str, patched: str) -> str:
    return _text(_git(repo, "diff", "--stat", base, patched)).strip()
