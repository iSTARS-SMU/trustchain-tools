# Standalone Dockerfile for the iSTARS-SMU/trustchain-tools public repo.
# Build context = this tool's own directory (NOT monorepo root).
# Synced from monorepo by `bash trustchain/scripts/push-tools.sh exa-search`.
#
# EXA_API_KEY is expected to be injected at runtime (compose env / docker run
# -e). The image itself does NOT bake any key — rotating keys = compose
# restart, no rebuild.

FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir -e .

EXPOSE 9216
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "9216"]
