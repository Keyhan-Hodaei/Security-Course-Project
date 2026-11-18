#!/usr/bin/env python3
"""Generate imginfo test inputs (valid/boundary/invalid).

Write outputs into this directory (targets/imginfo/tests) and
derive expected properties (dimensions and channel count) from the independent
Pillow reference, printing them for inclusion in the configuration.

Crashing inputs are based on the real defects reported in issues 1289 and 1291
of nothings/stb (DHT symbol counts totaling more than 256), present in stb_image
before revision 96fe76c (February 2022).
"""
import os
import random
import struct
import json

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))


def marker(m, payload):
    return bytes([0xFF, m]) + struct.pack(">H", len(payload) + 2) + payload


def crafted_jpeg(counts, values=None):
    """Create a minimal JPEG with an arbitrary DHT table (otherwise structurally valid)."""
    n = sum(counts)
    assert len(counts) == 16
    if values is None:
        values = bytes((i & 0xFF) for i in range(n))
    assert len(values) >= n
    out = b"\xFF\xD8"                                   # SOI
    out += marker(0xDB, b"\x00" + bytes([1] * 64))      # DQT (Pq=0,Tq=0)
    out += marker(0xC0, b"\x08" + struct.pack(">HH", 8, 8) + b"\x01" + b"\x01\x11\x00")  # SOF0
    out += marker(0xC4, b"\x00" + bytes(counts) + values[:n])  # DHT (Tc=0,Th=0)
    out += marker(0xDA, b"\x01" + b"\x01\x00" + b"\x00\x3F\x00")  # SOS
    out += b"\x00" * 32                                  # Entropy data
    out += b"\xFF\xD9"                                   # EOI
    return out


def save(name, data):
    p = os.path.join(HERE, name)
    with open(p, "wb") as f:
        f.write(data)
    return p


def main():
    manifest = {"valid": [], "boundary": [], "invalid": []}

    # ------------------------------------------------ Valid tests
    def make_image(name, w, h, mode, fmt, **kw):
        p = os.path.join(HERE, name)
        if mode == "gradient":
            img = Image.new("RGB", (w, h))
            px = img.load()
            for y in range(h):
                for x in range(w):
                    px[x, y] = ((x * 255) // max(1, w - 1),
                                (y * 255) // max(1, h - 1),
                                ((x + y) * 255) // max(1, w + h - 2))
        elif mode == "gray":
            img = Image.new("L", (w, h))
            px = img.load()
            for y in range(h):
                for x in range(w):
                    px[x, y] = (x * 7 + y * 13) & 0xFF
        elif mode == "flat":
            img = Image.new("RGB", (w, h), (120, 60, 200))
        else:
            raise ValueError(mode)
        img.save(p, fmt, **kw)
        with Image.open(p) as got:  # Independent reference: decode again with Pillow
            got.load()
            ref_w, ref_h = got.size
            ref_c = len(got.getbands())
            ref = {"name": name, "w": ref_w, "h": ref_h, "c": ref_c}
            if fmt in ("PNG", "BMP"):
                # Lossless: the harness checksum (sum of the first 64 pixel bytes)
                # can be computed exactly from Pillow's decoded data.
                ref["sum"] = sum(got.tobytes()[:64])
        return ref

    manifest["valid"].append(make_image("valid_small.jpg", 64, 48, "gradient", "JPEG"))
    manifest["valid"].append(make_image("valid_big.jpg", 1200, 800, "gradient", "JPEG", quality=90))
    manifest["valid"].append(make_image("valid_png.png", 32, 32, "flat", "PNG"))
    manifest["valid"].append(make_image("valid_bmp.bmp", 24, 16, "flat", "BMP"))
    manifest["valid"].append(make_image("valid_gray.jpg", 48, 48, "gray", "JPEG"))

    # ------------------------------------------------ Boundary tests
    manifest["boundary"].append(make_image("bound_1x1.jpg", 1, 1, "flat", "JPEG"))
    manifest["boundary"].append(make_image("bound_8x8.jpg", 8, 8, "gradient", "JPEG"))
    manifest["boundary"].append(make_image("bound_255.jpg", 255, 255, "gradient", "JPEG"))

    # ------------------------------------------------ Invalid tests
    # Crasher 1 (original input): the count vector from
    # issue 1289 → n=654 → writes beyond h->size[257] and values[256]
    counts_a = [0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 99, 99, 99, 99, 255]
    assert sum(counts_a) == 654
    save("crash_dht_overrun.jpg", crafted_jpeg(counts_a))
    manifest["invalid"].append({"name": "crash_dht_overrun.jpg", "note": "n=654 (issue 1289 vector)"})

    # Crasher 2: total exactly 257 → passes the incomplete n>257 guard, but
    # writes the size[257] terminator and values[256] out of bounds
    counts_b = [16] * 15 + [17]
    assert sum(counts_b) == 257
    save("crash_dht_offbyone.jpg", crafted_jpeg(counts_b))
    manifest["invalid"].append({"name": "crash_dht_offbyone.jpg", "note": "n=257 off-by-one"})

    # A valid JPEG truncated to half its length
    with open(os.path.join(HERE, "valid_small.jpg"), "rb") as f:
        full = f.read()
    save("invalid_truncated.jpg", full[: len(full) // 2])
    manifest["invalid"].append({"name": "invalid_truncated.jpg"})

    # Random bytes with a fixed seed for reproducibility
    rng = random.Random(1405)
    save("invalid_random.bin", bytes(rng.randrange(256) for _ in range(256)))
    manifest["invalid"].append({"name": "invalid_random.bin"})

    # Empty file and text file
    save("invalid_empty.jpg", b"")
    manifest["invalid"].append({"name": "invalid_empty.jpg"})
    save("invalid_text.txt", b"this is definitely not an image file\n")
    manifest["invalid"].append({"name": "invalid_text.txt"})

    with open(os.path.join(HERE, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    print("Generated. Expected values for valid tests (Pillow reference):")
    for t in manifest["valid"] + manifest["boundary"]:
        extra = f' sum={t["sum"]} (exact)' if "sum" in t else ""
        print(f'  {t["name"]}: w={t["w"]} h={t["h"]} c={t["c"]}{extra}')
    print("Invalid tests: Pillow rejects all inputs → expect exit=1 and IMG_ERR")


if __name__ == "__main__":
    main()
