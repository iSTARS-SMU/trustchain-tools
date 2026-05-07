# Standalone Dockerfile for the iSTARS-SMU/trustchain-tools public repo.
# Build context = this tool's own directory (NOT monorepo root).
#
# commix is a python tool whose canonical install is `git clone`. Upstream
# does not publish a stable PyPI release; we pin a specific commit/tag for
# reproducible builds. Symlinked into /usr/local/bin so it's on PATH.

FROM python:3.11-slim

ARG COMMIX_REF=v3.9

WORKDIR /app
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && git clone --depth 1 --branch "${COMMIX_REF}" https://github.com/commixproject/commix.git /opt/commix \
    && ln -s /opt/commix/commix.py /usr/local/bin/commix \
    && chmod +x /opt/commix/commix.py \
    && commix --version 2>&1 | head -1 \
    && apt-get purge -y git \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir -e .

EXPOSE 9222
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "9222"]
