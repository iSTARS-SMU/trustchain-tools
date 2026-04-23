# Standalone Dockerfile for the iSTARS-SMU/trustchain-tools public repo.
# Build context = this tool's own directory (NOT monorepo root).
# Synced from monorepo by `bash trustchain/scripts/push-tools.sh wafw00f`.
#
# wafw00f is a pure-python package (pip-installable). No apt dependency.

FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir wafw00f

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir -e .

EXPOSE 9213
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "9213"]
