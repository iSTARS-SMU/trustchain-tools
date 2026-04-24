# Standalone Dockerfile for the iSTARS-SMU/trustchain-tools umbrella repo.
# Build context = this tool's own directory. Synced from monorepo by
# `bash trustchain/scripts/push-tools.sh`.

FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth=1 https://github.com/GerbenJavado/LinkFinder.git /opt/linkfinder \
    && pip install --no-cache-dir -r /opt/linkfinder/requirements.txt

WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV LINKFINDER_PATH=/opt/linkfinder/linkfinder.py

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir -e .

EXPOSE 9105
CMD ["uvicorn", "linkfinder.main:app", "--host", "0.0.0.0", "--port", "9105"]
