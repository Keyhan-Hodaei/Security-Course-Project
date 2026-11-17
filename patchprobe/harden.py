"""Inspect ELF hardening: NX, PIE, RELRO level, and stack canaries.

Evidence comes from readelf rather than filenames or guesses:
- PIE: ELF type (ET_DYN versus ET_EXEC)
- NX: PT_GNU_STACK flags (RWE means disabled)
- RELRO: PT_GNU_RELRO plus BIND_NOW (full/partial/none)
- Canary: presence of __stack_chk_fail in dynamic symbols

Important caveats required by the assignment:
- PIE does not establish that runtime ASLR is enabled.
- A canary symbol does not establish that every function is protected.
"""
import re
import subprocess


def _readelf(binary, *args):
    r = subprocess.run(["readelf", "-W", *args, binary],
                       capture_output=True, text=True)
    return r.stdout


def check_hardening(binary: str) -> dict:
    hdr = _readelf(binary, "-h")
    phdrs = _readelf(binary, "-l")
    dyn = _readelf(binary, "-d")
    syms = _readelf(binary, "--dyn-syms")
    if "__stack_chk_fail" not in syms:
        # For static binaries or missing dynamic symbols, also inspect the full symbol table
        syms += _readelf(binary, "-s")

    pie = re.search(r"Type:\s+(\w+)", hdr)
    pie_val = pie.group(1) if pie else "?"
    is_pie = pie_val == "DYN"

    # NX: executable GNU_STACK permission (E) means NX is disabled
    stack_flags = None
    for line in phdrs.splitlines():
        if "GNU_STACK" not in line:
            continue
        # Flag column: a token consisting only of R/W/E letters
        for tok in line.split():
            if tok and all(c in "RWE" for c in tok):
                stack_flags = tok
                break
        break
    if stack_flags is None:
        # Without PT_GNU_STACK, interpret the default stack as executable: NX disabled
        nx, stack_flags = False, "no GNU_STACK marker (executable stack assumed by default)"
    else:
        nx = "E" not in stack_flags

    # RELRO
    has_relro_seg = "GNU_RELRO" in phdrs
    bind_now = bool(re.search(r"(BIND_NOW|FLAGS_1.*NOW|FLAGS.*NOW)", dyn))
    if has_relro_seg and bind_now:
        relro = "full"
    elif has_relro_seg:
        relro = "partial"
    else:
        relro = "none"

    # Stack Canary
    canary = "__stack_chk_fail" in syms
    # FORTIFY_SOURCE is supplementary, outside the four required protections
    fortified = sorted(set(re.findall(r"\b(__\w+_chk)\b", syms)) - {"__stack_chk_fail"})

    return {
        "binary": binary,
        "pie": {"enabled": is_pie, "evidence": f"ELF type: {pie_val}"},
        "nx": {"enabled": nx, "evidence": f"GNU_STACK flags: {stack_flags or 'no marker'}"},
        "relro": {"level": relro,
                  "evidence": (f"PT_GNU_RELRO={'present' if has_relro_seg else 'absent'}; "
                               f"BIND_NOW={'yes' if bind_now else 'no'}")},
        "stack_canary": {"present": canary,
                         "evidence": ("__stack_chk_fail symbol in dynamic symbols"
                                      if canary else
                                      "__stack_chk_fail symbol not found")},
        "fortify_source": {"present": bool(fortified),
                           "evidence": (", ".join(fortified[:6]) if fortified
                                        else "No __*_chk functions found")},
        "caveats": [
            "PIE does not establish that runtime ASLR is enabled.",
            "A canary symbol does not establish that every function is protected.",
        ],
    }


def compare(base: dict, patched: dict) -> dict:
    """Compare protections between versions and warn about weakening."""
    changes, warnings = [], []
    for key in ("pie", "nx", "stack_canary"):
        b, p = base[key]["enabled" if key != "stack_canary" else "present"], \
               patched[key]["enabled" if key != "stack_canary" else "present"]
        if b != p:
            changes.append({"protection": key, "base": b, "patched": p})
            if p is False or p == "none":
                warnings.append(
                    f"Protection {key.upper()} weakened in the patched version "
                    f"({base[key].get('evidence')} → {patched[key].get('evidence')})")
    if base["relro"]["level"] != patched["relro"]["level"]:
        changes.append({"protection": "relro", "base": base["relro"]["level"],
                        "patched": patched["relro"]["level"]})
        order = {"none": 0, "partial": 1, "full": 2}
        if order[patched["relro"]["level"]] < order[base["relro"]["level"]]:
            warnings.append(f"RELRO level reduced: {base['relro']['level']} → "
                            f"{patched['relro']['level']}")
    return {"changed": changes, "warnings": warnings}
