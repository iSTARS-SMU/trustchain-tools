# Standalone Dockerfile for the iSTARS-SMU/trustchain-tools public repo.
# Build context = this tool's own directory (NOT monorepo root).
# Synced from monorepo by `bash trustchain/scripts/push-tools.sh nuclei`.
#
# Uses ProjectDiscovery's prebuilt nuclei binaries (linux/amd64 + linux/arm64)
# rather than `go install` from source. Why: `go install` under QEMU
# arm64 emulation in GHA takes 25-40 min; downloading the prebuilt binary
# takes ~5 sec per arch. Multi-arch image build drops from ~30 min → ~1 min.
#
# To bump nuclei: edit NUCLEI_VERSION below; ProjectDiscovery publishes
# `nuclei_<ver>_linux_{amd64,arm64}.zip` for every release at
# https://github.com/projectdiscovery/nuclei/releases.

FROM python:3.11-slim

ARG TARGETARCH
ARG NUCLEI_VERSION=3.8.0

WORKDIR /app
ENV PYTHONUNBUFFERED=1

# ca-certificates stays for runtime HTTPS; curl + unzip purged after use to
# keep image small + reduce supply-chain surface.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" \
        -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei \
    && nuclei -version \
    && apt-get purge -y curl unzip \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir -e .

EXPOSE 9214
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "9214"]
