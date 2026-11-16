"""Build release and instrumented binaries from source trees and compute binary hashes.

- Each version/build combination has its own source tree. Remove any existing
  binary before building, otherwise make may reuse an up-to-date binary from
  another mode and the instrumented build may actually be the normal build.
- -ffile-prefix-map removes temporary source paths from debugging information
  for reproducible builds: rebuilding the same revision with the same command
  produces the same SHA-256, allowing the reproducer to compare binary hashes.
- Verify build separation using evidence: sanitized binaries must have
  ASan/UBSan runtime symbols, while release binaries must not.
"""
import hashlib
import os
import subprocess


class BuildError(Exception):
    pass


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def effective_cflags(cfg, mode: str, src_dir: str) -> str:
    return f"{cfg.flags[mode]} -ffile-prefix-map={src_dir}=."


def render_command(cfg, mode: str, src_dir: str, workdir: str) -> str:
    return (cfg.build_command.replace("{src}", src_dir)
            .replace("{cflags}", effective_cflags(cfg, mode, src_dir))
            .replace("{mode}", mode).replace("{out}", workdir))


def instrumentation(binary: str) -> dict:
    """Inspect instrumentation evidence in the symbol table using readelf."""
    r = subprocess.run(["readelf", "-W", "-s", "--dyn-syms", binary],
                       capture_output=True, text=True)
    syms = r.stdout
    return {"asan": "__asan_init" in syms or "__asan_report" in syms,
            "ubsan": "__ubsan_handle" in syms}


def build(src_dir: str, cfg, mode: str, workdir: str) -> dict:
    """Build mode (release|sanitized) from src_dir.

    Returns: {mode, binary, sha256, command, log_tail, instrumentation, ok}
    """
    cmd = render_command(cfg, mode, src_dir, workdir)
    binary = os.path.join(src_dir, cfg.binary_relpath)
    if os.path.exists(binary):
        os.remove(binary)
    env = dict(os.environ, LC_ALL="C", SOURCE_DATE_EPOCH="0")
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                       cwd=src_dir, timeout=600, env=env)
    log = (r.stdout + "\n" + r.stderr).strip()
    if r.returncode != 0 or not os.path.isfile(binary):
        why = (f"exit code {r.returncode}" if r.returncode != 0
               else f"binary '{cfg.binary_relpath}' not found after building")
        raise BuildError(f"Failed to build {mode} ({why})\n{log[-2000:]}")
    inst = instrumentation(binary)
    if mode == "sanitized" and not (inst["asan"] or inst["ubsan"]):
        raise BuildError("The sanitized build is not instrumented (__asan_init/"
                         "__ubsan_handle symbols not found). The build system may ignore external "
                         "CFLAGS; correct the build configuration")
    if mode == "release" and (inst["asan"] or inst["ubsan"]):
        raise BuildError("The release build contains a sanitizer runtime; the two builds "
                         "are not separated")
    return {
        "mode": mode,
        "binary": binary,
        "sha256": sha256_file(binary),
        "command": cmd,
        "cflags": effective_cflags(cfg, mode, src_dir),
        "instrumentation": inst,
        "log_tail": log[-1500:],
        "ok": True,
    }
