# Standalone Dockerfile for the iSTARS-SMU/trustchain-tools umbrella repo.
# Build context = this tool's own directory. Synced from monorepo by
# `bash trustchain/scripts/push-tools.sh`.

FROM golang:1.22-alpine AS builder
RUN go install github.com/tomnomnom/waybackurls@latest

FROM python:3.11-slim

COPY --from=builder /go/bin/waybackurls /usr/local/bin/waybackurls

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir -e .

EXPOSE 9104
CMD ["uvicorn", "waybackurls.main:app", "--host", "0.0.0.0", "--port", "9104"]
