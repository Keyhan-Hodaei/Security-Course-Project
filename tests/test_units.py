"""PatchProbe unit tests (hermetic, without requiring target builds).

Run: python3 -m pytest tests/ -q
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from patchprobe import evidence, cparse, verdict, correlate, minimize  # noqa: E402


# ------------------------------------------------------------------ evidence
ASAN_SAMPLE = """==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50200000001a
READ of size 1 at 0x50200000001a thread T0
    #0 0x5567 in parse_string /src/cJSON.c:660
    #1 0x5567 in parse_value /src/cJSON.c:1173
    #2 0x5567 in main /src/jsoncheck.c:112
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/cJSON.c:660 in parse_string"""

ASAN_MEMCPY_SAMPLE = """==1==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffd
WRITE of size 100 at 0x7ffd thread T0
    #0 0x1 in memcpy /usr/lib/x86_64-linux-gnu/libasan.so.5+0x1
    #1 0x2 in memcpy /src/../../sanitizer_common_interceptors_memintrinsics.inc:115
    #2 0x3 in main /src/jsoncheck.c:118
"""

UBSAN_SAMPLE = """stb_image.h:1990:17: runtime error: index 257 out of bounds for type 'stbi_uc [257]'
    #0 0x1 in stbi__build_huffman /src/stb_image.h:1990
    #1 0x2 in stbi__process_marker /src/stb_image.h:3108
"""


def test_asan_heap_overflow():
    ev = evidence.analyze({"stderr": ASAN_SAMPLE, "exit_code": 1, "signal": 0,
                           "timed_out": False, "ran": True})
    assert ev["confirmed"] and ev["error_type"] == "HEAP_BUFFER_OVERFLOW"
    assert ev["mechanism"] == "sanitizer:ASan"
    assert ev["rw"] == "READ" and ev["size"] == 1
    assert ev["top"]["func"] == "parse_string" and ev["top"]["file"] == "cJSON.c"
    assert evidence.signature(ev) == "HEAP_BUFFER_OVERFLOW/READ@parse_string"


def test_asan_interceptor_frame_filtered():
    ev = evidence.analyze({"stderr": ASAN_MEMCPY_SAMPLE, "exit_code": 1,
                           "signal": 0, "timed_out": False, "ran": True})
    assert ev["confirmed"] and ev["error_type"] == "STACK_BUFFER_OVERFLOW"
    assert ev["rw"] == "WRITE" and ev["size"] == 100
    # A sanitizer memcpy intermediary must not be selected as the top application frame
    assert ev["top"]["func"] == "main"
    assert evidence.signature(ev) == "STACK_BUFFER_OVERFLOW/WRITE@main"


def test_ubsan_index_oob():
    ev = evidence.analyze({"stderr": UBSAN_SAMPLE, "exit_code": 1, "signal": 0,
                           "timed_out": False, "ran": True})
    assert ev["confirmed"] and ev["error_type"] == "INDEX_OUT_OF_BOUNDS"
    assert ev["mechanism"] == "sanitizer:UBSan"
    assert ev["top"]["func"] == "stbi__build_huffman"
    assert ev["detail"] == "index 257 out of bounds for type stbi_uc [257]"
    assert evidence.signature(ev) == "INDEX_OUT_OF_BOUNDS@stbi__build_huffman"
    # Same error type and function but different access direction means a different error
    w = dict(evidence.analyze({"stderr": ASAN_SAMPLE.replace("READ of", "WRITE of"),
                               "exit_code": 1, "ran": True}))
    assert evidence.signature(w) == "HEAP_BUFFER_OVERFLOW/WRITE@parse_string"


def test_timeout_and_signal():
    ev = evidence.analyze({"stderr": "", "timed_out": True, "ran": True})
    assert ev["mechanism"] == "resource-limit:timeout" and not ev["confirmed"]
    assert ev["resource_limit"] and not ev["unclassified_crash"]
    ev = evidence.analyze({"stderr": "", "exit_code": -11, "signal": 0,
                           "ran": True})
    assert ev["unclassified_crash"] and ev["error_type"] == "UNCLASSIFIED_SIGNAL"
    # Not every termination is a vulnerability; without evidence it is unclassified
    ev = evidence.analyze({"stderr": "plain failure", "exit_code": 1,
                           "signal": 0, "ran": True})
    assert not ev["confirmed"] and not ev["unclassified_crash"]


# ------------------------------------------------------------------ cparse
C_SAMPLE = """#include <stdio.h>
#define X 1

static int helper(int a, int b)
{
    return a + b;
}

CJSON_PUBLIC(cJSON *) cJSON_Parse(const char *value)
{
    return cJSON_ParseWithOpts(value, 0, 0);
}

int main(int argc, char **argv)
{
    return 0;
}
"""


def test_cparse_functions():
    funcs = cparse.scan_functions(C_SAMPLE)
    names = [f["name"] for f in funcs]
    assert names == ["helper", "cJSON_Parse", "main"]
    pf = next(f for f in funcs if f["name"] == "cJSON_Parse")
    assert cparse.function_at(funcs, pf["start"]) is pf
    assert cparse.functions_overlapping(funcs, [(pf["start"], pf["end"])])


# ------------------------------------------------------------------ minimize
def test_ddmin():
    # Preserve byte 'X'; minimization should reduce the input to one byte
    data = b"aaXbbXccX"
    def pred(d):
        return b"X" in d
    out = minimize.ddmin(data, pred)
    assert out == b"X"

    # Irreducible: the entire input is required
    out2 = minimize.ddmin(b"AB", lambda d: d == b"AB")
    assert out2 == b"AB"


# ------------------------------------------------------------------ verdict
def test_verdict_priority():
    """Assignment priority: 30 > 10 > 20 > 40 > 0."""
    B = [{"id": "B01"}]
    # 30 takes precedence
    v = verdict.decide({"build_error": "compile failed", "vuln_remains": ["x"]})
    assert v["exit_code"] == 30
    # 10 outranks 20; simultaneous regression remains in flags
    v = verdict.decide({"base_confirmed_findings": B,
                        "func_regressions": ["Test v2 failed"],
                        "vuln_remains": ["B01 remains"]})
    assert v["exit_code"] == 10 and v["name"] == "VULN_REMAINS"
    assert v["flags"]["func_regression"] and v["flags"]["vuln_remains"]
    # 10 outranks 40: confirmed new issue even without base reproduction
    v = verdict.decide({"base_confirmed_findings": [], "vuln_remains": ["NEW_ISSUE"]})
    assert v["exit_code"] == 10 and v["flags"]["inconclusive"]
    # 20 outranks 40
    v = verdict.decide({"base_confirmed_findings": [], "func_regressions": ["x"]})
    assert v["exit_code"] == 20
    # 40: base issue did not reproduce
    v = verdict.decide({"base_confirmed_findings": []})
    assert v["exit_code"] == 40
    # 40: unstable finding / unclassified termination / resource limit
    for key in ("unstable_findings", "unclassified_terminations", "resource_limit_events"):
        v = verdict.decide({"base_confirmed_findings": B, key: ["t1"]})
        assert v["exit_code"] == 40, key
    v = verdict.decide({"base_confirmed_findings": B, "mandatory_complete": False})
    assert v["exit_code"] == 40
    # 0
    v = verdict.decide({"base_confirmed_findings": B, "mandatory_complete": True})
    assert v["exit_code"] == 0 and not any(v["flags"].values())


# ------------------------------------------------------------------ correlate
def _mk_finding(sig, func, file):
    return {"signature": sig, "version": "base",
            "evidence": {"error_type": sig.split("@")[0],
                         "top": {"func": func, "file": file, "line": 10},
                         "frames": [{"idx": 0, "func": func, "file": file, "line": 10}]}}


def test_classify_and_correlate():
    b = [_mk_finding("HEAP_BUFFER_OVERFLOW@parse_string", "parse_string", "cJSON.c")]
    p = []
    out = correlate.classify_findings(b, p)
    assert out[0]["status"] == "FIXED"

    p2 = [_mk_finding("HEAP_BUFFER_OVERFLOW@parse_string", "parse_string", "cJSON.c")]
    out = correlate.classify_findings(b, p2)
    assert out[0]["status"] == "INCOMPLETE_FIX"

    p3 = [_mk_finding("STACK_BUFFER_OVERFLOW@main", "main", "jsoncheck.c")]
    out = correlate.classify_findings(b, p3)
    assert out[1]["status"] == "NEW_ISSUE"

    diff = {"files": {"cJSON.c": {"old_ranges": [(657, 680)],
                                  "new_ranges": [(657, 682)],
                                  "old_functions": ["parse_string"],
                                  "new_functions": ["parse_string"]}}}
    c = correlate.correlate(out[0], diff)
    assert c["status"] == "STRONG"

    diff2 = {"files": {"jsoncheck.c": {"old_functions": ["main"],
                                       "new_functions": ["main"]}}}
    c2 = correlate.correlate(_mk_finding("X@parse_string", "parse_string", "cJSON.c"),
                             diff2)
    assert c2["status"] == "NONE"

    # Visual proximity is insufficient: same file without function overlap
    c3 = correlate.correlate(_mk_finding("X@parse_value", "parse_value", "cJSON.c"), diff)
    assert c3["status"] == "SAME_FILE"


# ------------------------------------------------------------------ harden
def test_harden_on_real_binaries(tmp_path):
    import subprocess
    from patchprobe import harden
    src = tmp_path / "t.c"
    src.write_text(
        "int work(int n){char b[32]; for(int i=0;i<32;i++) b[i]=(char)(i+n);"
        "return b[5];}\n"
        "int main(void){return work(1);}")
    # Normal build: PIE + NX + partial RELRO, explicitly without a canary
    b1 = tmp_path / "default"
    # Explicit partial RELRO: some distributions such as Ubuntu default to -z now
    subprocess.run(["gcc", str(src), "-fno-stack-protector",
                    "-Wl,-z,relro,-z,lazy", "-o", str(b1)], check=True)
    h1 = harden.check_hardening(str(b1))
    assert h1["pie"]["enabled"] is True
    assert h1["nx"]["enabled"] is True
    assert h1["relro"]["level"] == "partial"
    assert h1["stack_canary"]["present"] is False
    # Hardened build: canary + full RELRO; weak build: no PIE and executable stack
    b2 = tmp_path / "hardened"
    subprocess.run(["gcc", str(src), "-fstack-protector-strong",
                    "-Wl,-z,now", "-o", str(b2)], check=True)
    h2 = harden.check_hardening(str(b2))
    assert h2["stack_canary"]["present"] is True
    assert h2["relro"]["level"] == "full"
    b3 = tmp_path / "weak"
    subprocess.run(["gcc", str(src), "-no-pie", "-Wl,-z,execstack",
                    "-Wl,-z,norelro", "-fno-stack-protector",
                    "-o", str(b3)], check=True)
    h3 = harden.check_hardening(str(b3))
    assert h3["pie"]["enabled"] is False
    assert h3["nx"]["enabled"] is False
    assert h3["relro"]["level"] == "none"
    # Comparison: weaker protection should produce a warning
    cmp_res = harden.compare(h1, h3)
    assert any("PIE" in w for w in cmp_res["warnings"])
    assert any("NX" in w for w in cmp_res["warnings"])


# ------------------------------------------------------------------ config
def test_config_load_and_errors(tmp_path):
    import json
    from patchprobe import config as cmod
    root = os.path.join(os.path.dirname(__file__), "..")
    cfg = cmod.load_config(os.path.join(root, "targets/jsoncheck/config.json"))
    assert cfg.name == "jsoncheck" and cfg.input_method == "stdin"
    raw = json.load(open(os.path.join(root, "targets/jsoncheck/config.json"), encoding="utf-8"))
    n = sum(1 for _ in cfg.all_cases())
    # Derive counts from configuration so adding a case does not break this test
    assert n == sum(len(raw["tests"][k]) for k in ("valid", "boundary", "invalid")) >= 3
    assert all(len(cfg.tests[k]) >= 1 for k in ("valid", "boundary", "invalid"))
    assert all("_path" in c for _, c in cfg.all_cases())
    # Sanitized flags must disable FORTIFY to preserve ASan evidence
    assert "-U_FORTIFY_SOURCE" in cfg.flags["sanitized"]

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"target": "x"}))
    try:
        cmod.load_config(str(bad))
        assert False, "Expected a configuration error"
    except cmod.ConfigError:
        pass

    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    try:
        cmod.load_config(str(broken))
        assert False
    except cmod.ConfigError:
        pass

    # Reject build commands without {cflags}; otherwise the two builds could be identical
    good = json.load(open(os.path.join(root, "targets/jsoncheck/config.json")))
    good["repo"] = os.path.abspath(os.path.join(root, good["repo"]))
    good["tests_dir"] = os.path.abspath(os.path.join(root, good["tests_dir"]))
    good["build"]["command"] = "make -C {src} jsoncheck"
    nocf = tmp_path / "nocflags.json"
    nocf.write_text(json.dumps(good))
    try:
        cmod.load_config(str(nocf), root=str(tmp_path))
        assert False, "A build command without {cflags} must be rejected"
    except cmod.ConfigError as e:
        assert "{cflags}" in str(e)


# ------------------------------------------------------------------ Additional evidence tests
UAF_SAMPLE = """==7==ERROR: AddressSanitizer: heap-use-after-free on address 0x6020 at pc 0x1
READ of size 4 at 0x6020 thread T0
    #0 0x1 in use_item /src/lib.c:40
    #1 0x2 in main /src/app.c:12
0x6020 is located 0 bytes inside of 4-byte region
freed by thread T0 here:
    #0 0x3 in free ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:52
    #1 0x4 in release_item /src/lib.c:30
previously allocated by thread T0 here:
    #0 0x5 in malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:69
    #1 0x6 in make_item /src/lib.c:20
"""


def test_evidence_first_stack_only_and_types():
    ev = evidence.analyze({"stderr": UAF_SAMPLE, "exit_code": 1, "ran": True})
    assert ev["error_type"] == "USE_AFTER_FREE" and ev["rw"] == "READ"
    # Only the error stack; freed/allocated stacks must not enter correlation
    assert [f["func"] for f in ev["frames"]] == ["use_item", "main"]
    df = evidence.analyze({"stderr": "==1==ERROR: AddressSanitizer: attempting double-free"
                                     " on 0x602 in thread T0:\n    #0 0x1 in free x.cpp:52\n"
                                     "    #1 0x2 in Foo::drop(int) /s/foo.cpp:9\n",
                           "exit_code": 1, "ran": True})
    assert df["error_type"] == "DOUBLE_FREE" and df["top"]["func"] == "Foo::drop"
    nul = evidence.analyze({"stderr": "==1==ERROR: AddressSanitizer: SEGV on unknown address "
                                      "0x000000000008 (pc 0x1 bp 0x2 sp 0x3 T0)\n"
                                      "==1==The signal is caused by a READ memory access.\n"
                                      "    #0 0x1 in get /s/a.c:3\n", "ran": True})
    assert nul["error_type"] == "NULL_DEREF" and nul["rw"] == "READ"
    cpp = evidence.analyze({"stderr": "src/parse.cpp:77:9: runtime error: division by zero\n",
                            "ran": True})
    assert cpp["error_type"] == "DIV_BY_ZERO" and cpp["top"]["file"] == "parse.cpp"


def test_evidence_binary_protections_and_limits():
    # FORTIFY_SOURCE and stack canaries are binary protections, not bare signals
    fort = evidence.analyze({"stderr": "*** buffer overflow detected ***: terminated\n",
                             "exit_code": -6, "ran": True})
    assert fort["confirmed"] and fort["mechanism"] == "protection:fortify-source"
    can = evidence.analyze({"stderr": "*** stack smashing detected ***: terminated\n",
                            "exit_code": -6, "ran": True})
    assert can["mechanism"] == "protection:stack-canary"
    assert can["error_type"] == "STACK_BUFFER_OVERFLOW"
    # CPU limit exceeded: a resource limit, not a vulnerability
    xcpu = evidence.analyze({"stderr": "", "exit_code": -24, "ran": True})
    assert xcpu["resource_limit"] and not xcpu["confirmed"] and not xcpu["unclassified_crash"]
    segv = evidence.analyze({"stderr": "", "exit_code": -11, "ran": True})
    assert segv["mechanism"] == "signal:SIGSEGV" and segv["unclassified_crash"]


# ------------------------------------------------------------------ gitops / regress / runner
def test_parse_diff_deleted_and_added_files():
    from patchprobe import gitops
    text = """diff --git a/old.c b/old.c
deleted file mode 100644
--- a/old.c
+++ /dev/null
@@ -1,3 +0,0 @@
-int a;
diff --git a/lib.c b/lib.c
--- a/lib.c
+++ b/lib.c
@@ -10,0 +11,2 @@ int f(void)
+    x++;
+    y++;
@@ -20 +22 @@
-old
+new
"""
    files = gitops.parse_diff(text)
    assert files["old.c"]["old_ranges"] == [(1, 3)] and files["old.c"]["new_ranges"] == []
    assert files["lib.c"]["old_ranges"] == [(20, 20)]
    assert files["lib.c"]["new_ranges"] == [(11, 12), (22, 22)]


def test_regression_entries_do_not_collide(tmp_path):
    from patchprobe import regress
    inp1 = tmp_path / "a.bin"; inp1.write_bytes(b"AAAA")
    inp2 = tmp_path / "b.bin"; inp2.write_bytes(b"BB")
    f1 = {"id": "B01", "signature": "HEAP_BUFFER_OVERFLOW@f", "input": "a",
          "input_path": str(inp1), "evidence": {"error_type": "HEAP_BUFFER_OVERFLOW",
                                                "top": {"func": "f"}}}
    f2 = dict(f1, signature="USE_AFTER_FREE@g", input_path=str(inp2))
    e1, new1 = regress.add_entry(str(tmp_path), "t", f1, None, "r1", "c1")
    e2, new2 = regress.add_entry(str(tmp_path), "t", f2, None, "r2", "c1")
    assert new1 and new2 and e1["id"] != e2["id"]
    # Repeated signature: reuse the existing entry and replace its input with a smaller one
    small = tmp_path / "s.bin"; small.write_bytes(b"A")
    e3, new3 = regress.add_entry(str(tmp_path), "t", dict(f1, input_path=str(small)),
                                 None, "r3", "c2")
    assert not new3 and e3["id"] == e1["id"]
    suite = regress.load_suite(str(tmp_path), "t")
    assert len(suite["entries"]) == 2
    assert (tmp_path / "t" / e1["input"]).read_bytes() == b"A"
    assert {p["base_commit"] for p in suite["entries"][0]["provenance"]} == {"c1", "c2"}


def test_runner_signal_timeout_and_no_core(tmp_path):
    import subprocess
    from patchprobe import runner
    src = tmp_path / "p.c"
    src.write_text('#include <signal.h>\n#include <unistd.h>\n#include <stdio.h>\n'
                   'int main(int c,char**v){int ch=getchar();'
                   'if(ch==\'S\') raise(SIGSEGV); if(ch==\'L\') for(;;){} '
                   'puts("ok"); return 3;}')
    exe = tmp_path / "p"
    subprocess.run(["gcc", str(src), "-o", str(exe)], check=True)
    lim = {"timeout_sec": 1, "cpu_sec": 5}
    def run(data):
        f = tmp_path / "in"; f.write_bytes(data)
        return runner.run_input(str(exe), str(f), "stdin", lim, False, cwd=str(tmp_path))
    r = run(b"x")
    assert r["exit_code"] == 3 and r["stdout"].strip() == "ok" and r["signal"] == 0
    r = run(b"S")
    assert r["signal"] == 11 and r["exit_code"] == -11
    assert not any(p.name.startswith("core") for p in tmp_path.iterdir())
    r = run(b"L")
    assert r["timed_out"] and evidence.analyze(r)["resource_limit"]


def test_sanitizer_runtime_failure_is_environment_not_finding():
    from patchprobe import runner
    dead = {"sanitized": True, "ran": True, "exit_code": -11, "signal": 11,
            "stderr": "AddressSanitizer:DEADLYSIGNAL\nAddressSanitizer:DEADLYSIGNAL\n"}
    assert runner.is_sanitizer_runtime_failure(dead)
    # A genuine SEGV reported by ASan is not an environment failure
    real = dict(dead, stderr="AddressSanitizer:DEADLYSIGNAL\n==1==ERROR: AddressSanitizer: "
                              "SEGV on unknown address 0x000000000000\n    #0 0x1 in f /a.c:1\n")
    assert not runner.is_sanitizer_runtime_failure(real)
    assert not runner.is_sanitizer_runtime_failure(dict(dead, sanitized=False))
    ev = evidence.analyze(dict(dead, sanitizer_runtime_failure=True))
    assert ev["env_error"] and not ev["confirmed"] and not ev["unclassified_crash"]
