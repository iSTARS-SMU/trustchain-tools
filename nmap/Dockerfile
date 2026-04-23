# Standalone Dockerfile for the iSTARS-SMU/trustchain-tools public repo.
# Build context = this tool's own directory (NOT monorepo root).
# Synced from monorepo by `bash trustchain/scripts/push-tools.sh nmap`.
#
# Usage (from inside ./nmap of the public repo):
#   docker build -t trustchain-tool-nmap .

FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

# nmap binary itself + minimal deps. apt cache wiped to keep image lean.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir -e .

EXPOSE 9211
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "9211"]
