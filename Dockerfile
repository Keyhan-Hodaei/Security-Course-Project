# Isolated PatchProbe environment — satisfies the isolated testing requirement
# Build:   docker build -t patchprobe .
# Run the full scenario matrix with resource limits and no network:
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

# Unit tests and the full scenario matrix with exit-code assertions
CMD ["bash", "-c", "python3 -m pytest tests/ -q && bash scenarios/run_all.sh"]
