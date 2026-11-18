#!/usr/bin/env python3
"""تولید مجموعه آزمون‌های هدف imginfo (معتبر/مرزی/نامعتبر).

خروجی‌ها در همین دایرکتوری (targets/imginfo/tests) نوشته می‌شود و
مقادیر موردانتظار آزمون‌های معتبر (ابعاد و تعداد کانال) از مرجع مستقل
Pillow استخراج و در انتهای اجرا چاپ می‌شود تا در فایل پیکربندی ثبت شود.

ورودی‌های خراب‌کننده بر اساس اشکال واقعی گزارش‌شده در issue های 1289 و 1291
مخزن nothings/stb هستند (DHT با مجموع تعدادها > 256) که تا پیش از کامیت
96fe76c (فوریه ۲۰۲۲) در stb_image وجود داشتند.
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
    """JPEG مینیمال با یک جدول DHT دلخواه (ساختاری معتبر جز جدول)."""
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
    out += b"\x00" * 32                                  # داده انتروپی
    out += b"\xFF\xD9"                                   # EOI
    return out


def save(name, data):
    p = os.path.join(HERE, name)
    with open(p, "wb") as f:
        f.write(data)
    return p


def main():
    manifest = {"valid": [], "boundary": [], "invalid": []}

    # ------------------------------------------------ آزمون‌های معتبر
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
        with Image.open(p) as got:  # مرجع مستقل: خواندن مجدد با Pillow
            got.load()
            ref_w, ref_h = got.size
            ref_c = len(got.getbands())
            ref = {"name": name, "w": ref_w, "h": ref_h, "c": ref_c}
            if fmt in ("PNG", "BMP"):
                # بی‌اتلاف: checksum هارنس (مجموع ۶۴ بایت نخست پیکسل‌ها) دقیقاً
                # از داده رمزگشایی‌شده Pillow قابل محاسبه است
                ref["sum"] = sum(got.tobytes()[:64])
        return ref

    manifest["valid"].append(make_image("valid_small.jpg", 64, 48, "gradient", "JPEG"))
    manifest["valid"].append(make_image("valid_big.jpg", 1200, 800, "gradient", "JPEG", quality=90))
    manifest["valid"].append(make_image("valid_png.png", 32, 32, "flat", "PNG"))
    manifest["valid"].append(make_image("valid_bmp.bmp", 24, 16, "flat", "BMP"))
    manifest["valid"].append(make_image("valid_gray.jpg", 48, 48, "gray", "JPEG"))

    # ------------------------------------------------ آزمون‌های مرزی
    manifest["boundary"].append(make_image("bound_1x1.jpg", 1, 1, "flat", "JPEG"))
    manifest["boundary"].append(make_image("bound_8x8.jpg", 8, 8, "gradient", "JPEG"))
    manifest["boundary"].append(make_image("bound_255.jpg", 255, 255, "gradient", "JPEG"))

    # ------------------------------------------------ آزمون‌های نامعتبر
    # ورودی خراب‌کننده ۱ (ورودی «اولیه»): همان بردار تعدادهای گزارش‌شده در
    # تحلیل issue 1289 → n=654 → نوشتن خارج از h->size[257] و values[256]
    counts_a = [0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 99, 99, 99, 99, 255]
    assert sum(counts_a) == 654
    save("crash_dht_overrun.jpg", crafted_jpeg(counts_a))
    manifest["invalid"].append({"name": "crash_dht_overrun.jpg", "note": "n=654 (issue 1289 vector)"})

    # ورودی خراب‌کننده ۲: مجموع دقیقاً ۲۵۷ → عبور از گارد ناقصِ n>257 اما
    # نوشتن size[257] (ترمیناتور) و values[256] خارج از محدوده
    counts_b = [16] * 15 + [17]
    assert sum(counts_b) == 257
    save("crash_dht_offbyone.jpg", crafted_jpeg(counts_b))
    manifest["invalid"].append({"name": "crash_dht_offbyone.jpg", "note": "n=257 off-by-one"})

    # فایل JPEG معتبر نصف‌شده
    with open(os.path.join(HERE, "valid_small.jpg"), "rb") as f:
        full = f.read()
    save("invalid_truncated.jpg", full[: len(full) // 2])
    manifest["invalid"].append({"name": "invalid_truncated.jpg"})

    # بایت‌های تصادفی با seed ثابت (قابل‌تکرار)
    rng = random.Random(1405)
    save("invalid_random.bin", bytes(rng.randrange(256) for _ in range(256)))
    manifest["invalid"].append({"name": "invalid_random.bin"})

    # فایل خالی و فایل متنی
    save("invalid_empty.jpg", b"")
    manifest["invalid"].append({"name": "invalid_empty.jpg"})
    save("invalid_text.txt", b"this is definitely not an image file\n")
    manifest["invalid"].append({"name": "invalid_text.txt"})

    with open(os.path.join(HERE, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    print("تولید شد. مقادیر موردانتظار آزمون‌های معتبر (مرجع Pillow):")
    for t in manifest["valid"] + manifest["boundary"]:
        extra = f' sum={t["sum"]} (دقیق)' if "sum" in t else ""
        print(f'  {t["name"]}: w={t["w"]} h={t["h"]} c={t["c"]}{extra}')
    print("آزمون‌های نامعتبر: Pillow همه را رد می‌کند → انتظار exit=1 و IMG_ERR")


if __name__ == "__main__":
    main()
