# Standalone Dockerfile for the iSTARS-SMU/trustchain-tools public repo.
# Build context = this tool's own directory (NOT monorepo root).
#
# Uses prebuilt dalfox release binaries (linux/amd64 + linux/arm64) rather
# than `go install` from source — same rationale as nuclei: ~5s per arch
# vs ~30 min under QEMU. Releases at:
#   https://github.com/hahwul/dalfox/releases
# Asset names: dalfox-linux-<arch>.tar.gz (single binary inside, named
# `dalfox-linux-<arch>` — we rename to `dalfox` after extraction).

FROM python:3.11-slim

ARG TARGETARCH
ARG DALFOX_VERSION=2.13.0

WORKDIR /app
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && curl -fsSL "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox-linux-${TARGETARCH}.tar.gz" \
        -o /tmp/dalfox.tgz \
    && tar -xzf /tmp/dalfox.tgz -C /tmp \
    && mv "/tmp/dalfox-linux-${TARGETARCH}" /usr/local/bin/dalfox \
    && rm /tmp/dalfox.tgz \
    && chmod +x /usr/local/bin/dalfox \
    && dalfox version \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir -e .

EXPOSE 9223
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "9223"]
