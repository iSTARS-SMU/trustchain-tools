# Standalone Dockerfile for the iSTARS-SMU/trustchain-tools umbrella repo.
# Build context = this tool's own directory. Synced from monorepo by
# `bash trustchain/scripts/push-tools.sh`.

FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends whois \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir -e .

EXPOSE 9208
CMD ["uvicorn", "whois.main:app", "--host", "0.0.0.0", "--port", "9208"]
