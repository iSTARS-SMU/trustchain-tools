# Standalone Dockerfile for the iSTARS-SMU/trustchain-tools public repo.
# Build context = this tool's own directory (NOT monorepo root).
# Synced from monorepo by `bash trustchain/scripts/push-tools.sh feroxbuster`.
#
# Uses kalilinux/kali-rolling because feroxbuster is in the Kali apt repo
# and the binary is auto-updated. Image is heavy (~1 GB) but reproducible.

FROM kalilinux/kali-rolling

WORKDIR /app
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip feroxbuster \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --break-system-packages -e .

EXPOSE 9215
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "9215"]
