# Standalone Dockerfile for the iSTARS-SMU/trustchain-tools public repo.
# Build context = this tool's own directory (NOT monorepo root).
# Synced from monorepo by `bash trustchain/scripts/push-tools.sh http_fetch`.
#
# Unlike the other 7 tools, http_fetch imports `HttpFetchRequest` /
# `HttpFetchResult` from trustchain-contracts. push-tools.sh rsyncs the
# contracts source into ./vendor/contracts/ at sync time, and we install
# it from there. This is the same pattern push-engine.sh uses for engines.

FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

# Install bundled trustchain-contracts (vendored from monorepo at push time).
COPY vendor/contracts /opt/contracts
RUN pip install --no-cache-dir /opt/contracts

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir -e .

EXPOSE 9220
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "9220"]
