# Standalone Dockerfile for the iSTARS-SMU/trustchain-tools public repo.
# Build context = this tool's own directory (NOT monorepo root).
#
# sqlmap's canonical install is `git clone` from sqlmapproject/sqlmap.
# We pin a specific tag for reproducible builds. Symlinked into
# /usr/local/bin so it's on PATH.

FROM python:3.11-slim

ARG SQLMAP_REF=1.8.5

WORKDIR /app
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && git clone --depth 1 --branch "${SQLMAP_REF}" https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap \
    && chmod +x /opt/sqlmap/sqlmap.py \
    && sqlmap --version \
    && apt-get purge -y git \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir -e .

EXPOSE 9221
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "9221"]
