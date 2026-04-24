# Standalone Dockerfile for the iSTARS-SMU/trustchain-tools public repo.
# Build context = this tool's own directory (NOT monorepo root).
# Synced from monorepo by `bash trustchain/scripts/push-tools.sh nvd-search`.

FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir -e .

EXPOSE 9217
CMD ["uvicorn", "nvd_search.main:app", "--host", "0.0.0.0", "--port", "9217"]
