#!/usr/bin/env python3
"""Generate jsoncheck test inputs (valid/boundary/invalid).

Expected results for valid tests come from Python's independent json module
and are printed for inclusion in the configuration.
Outputs are written into this directory (targets/jsoncheck/tests).
"""
import json
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))

VALID = {
    "valid_basic.json": {"name": "cJSON", "n": 42, "ok": True, "arr": [1, 2, 3]},
    "valid_long_string.json": [
        "this string value is deliberately much longer than thirty-two characters"
    ],
    "valid_numbers.json": [0, -1, 3.5, 1e3, -2.5e-2],
    "valid_nested.json": {"a": {"b": {"c": [True, False, None]}}},
    "valid_unicode.json": {"سلام": "دنیا", "note": "متن فارسی UTF-8"},
    "valid_100.json": list(range(100)),
}

BOUNDARY_VALID = {
    "bound_256str.json": ["a" * 256],
    "bound_escapes.json": {"esc": "line1\nline2\ttab\"quote\\slash A"},
}
BOUNDARY_INVALID = {
    "bound_empty.json": "",
    "bound_ws.json": "   \n\t  ",
    "bound_obj_only.json": "{",
    "bound_quote_end.json": '{"a":"x"',
    "invalid_number.json": '{"n":12',
}

INVALID = {
    "crash_unterminated_string.json": '{"a":"abc',
    "crash_unterminated_brace.json": '{"a":"abc}',
    "invalid_long_garbage.json": "{" * 100,
    "invalid_double_comma.json": "[1,,2]",
    "invalid_text.txt": "hello world is not json",
}


def oracle(doc):
    """Compute the harness's expected output using an independent reference."""
    if isinstance(doc, dict):
        return f"PARSE_OK type=object n={len(doc)}"
    if isinstance(doc, list):
        return f"PARSE_OK type=array n={len(doc)}"
    return f"PARSE_OK type=number n=0"


def main():
    expected = {}
    for name, doc in {**VALID, **BOUNDARY_VALID}.items():
        text = json.dumps(doc, ensure_ascii=False)
        json.loads(text)  # Validate with the independent reference
        with open(os.path.join(HERE, name), "w", encoding="utf-8") as f:
            f.write(text)
        expected[name] = oracle(doc)

    for name, text in {**BOUNDARY_INVALID, **INVALID}.items():
        mode = "wb" if isinstance(text, bytes) else "w"
        with open(os.path.join(HERE, name), mode) as f:
            f.write(text)

    rng = random.Random(1405)
    data = bytes(rng.randrange(256) for _ in range(256))
    with open(os.path.join(HERE, "invalid_random.bin"), "wb") as f:
        f.write(data)

    print("Generated. Expected values (reference: Python json module):")
    for k, v in sorted(expected.items()):
        print(f"  {k}: exit=0 stdout='{v}'")


if __name__ == "__main__":
    main()
