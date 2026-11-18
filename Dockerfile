# محیط ایزوله اجرای PatchProbe — مطابق ضابطه «محیط آزمایش ایزوله»
# ساخت:   docker build -t patchprobe .
# اجرای کل ماتریس سناریو با محدودیت منابع و شبکه قطع:
#   docker compose up --exit-code-from validate
FROM debian:12-slim

RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    gcc libc6-dev make git python3 python3-pytest binutils ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 10001 tester \
 && install -d -o tester -g tester /workspace

WORKDIR /workspace
COPY --chown=tester:tester . /workspace
USER tester
RUN git config --global --add safe.directory '*' \
 && bash scripts/setup_targets.sh

# آزمون‌های واحد + ماتریس کامل سناریوها با تأیید کدهای خروج
CMD ["bash", "-c", "python3 -m pytest tests/ -q && bash scenarios/run_all.sh"]
