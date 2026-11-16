"""Lightweight C/C++ function scanner mapping function names to line ranges.

This is not a compiler parser; it is a simple C-style source heuristic
for correlating findings with changed functions. Rules:

- A function starts at column zero, has '(' in its signature,
  does not end with ';', and has an opening '{' on that line
  or a subsequent line.
- The function name is the last identifier immediately preceding '(' in the signature
  (so declarations such as CJSON_PUBLIC(...) cJSON_Parse(...)
  yield the intended cJSON_Parse name).
- A function ends at the first '}' at column zero after its start.
"""
import re

SIG_START = re.compile(r"^[A-Za-z_#][\w\s\*&:,()\[\]]*\(")
NAME_BEFORE_PAREN = re.compile(r"([A-Za-z_]\w*)\s*\(")


def scan_functions(source: str):
    """Return a list of {name, start, end} with one-based line numbers."""
    lines = source.splitlines()
    funcs = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if (line.startswith("#") or line.startswith("}")):
            i += 1
            continue
        if SIG_START.match(line) and not line.rstrip().endswith(";") \
                and "=" not in line.split("(")[0]:
            sig = line
            j = i
            # Accumulate the signature until '{' or ';'
            while j < n and "{" not in lines[j] and ";" not in lines[j] \
                    and not lines[j].startswith("#"):
                sig += "\n" + lines[j]
                j += 1
            if j < n and "{" in lines[j]:
                # Function name: last identifier followed by '(' in the signature
                names = NAME_BEFORE_PAREN.findall(sig)
                name = names[-1] if names else None
                if name and name not in ("if", "for", "while", "switch", "return"):
                    # Find the end: '}' at column zero
                    k = j
                    while k < n and not lines[k].startswith("}"):
                        k += 1
                    if k < n:
                        funcs.append({"name": name, "start": i + 1, "end": k + 1})
                        i = k
                        i += 1
                        continue
        i += 1
    return funcs


def function_at(funcs, line: int):
    """Return the function containing the one-based line number, or None."""
    for f in funcs:
        if f["start"] <= line <= f["end"]:
            return f
    return None


def functions_overlapping(funcs, ranges):
    """Return functions overlapping any inclusive range [(s, e)]."""
    out = []
    for f in funcs:
        for s, e in ranges:
            if f["start"] <= e and s <= f["end"]:
                out.append(f)
                break
    return out
