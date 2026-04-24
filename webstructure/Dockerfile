# Standalone Dockerfile for the iSTARS-SMU/trustchain-tools umbrella repo.
# Build context = this tool's own directory.
# Synced from monorepo by `bash trustchain/scripts/push-tools.sh`.

FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir -e .

EXPOSE 9218
CMD ["uvicorn", "webstructure.main:app", "--host", "0.0.0.0", "--port", "9218"]
