# Standalone Dockerfile for the iSTARS-SMU/trustchain-tools public repo.
# Build context = this tool's own directory (NOT monorepo root).
# Synced from monorepo by `bash trustchain/scripts/push-tools.sh nuclei`.
#
# Two-stage: golang builder compiles nuclei, python runtime hosts the wrapper.

FROM golang:1.24 AS builder
RUN GOTOOLCHAIN=auto go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY --from=builder /go/bin/nuclei /usr/local/bin/nuclei

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir -e .

EXPOSE 9214
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "9214"]
