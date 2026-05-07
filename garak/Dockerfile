# Standalone Dockerfile for the iSTARS-SMU/trustchain-tools public repo.
# Build context = this tool's own directory (NOT monorepo root).
#
# garak (NVIDIA, Apache-2.0) is a Python LLM-safety probe orchestrator.
# Unlike dalfox / nuclei (single statically-linked binary), garak is pip-
# installed and pulls torch + transformers + langchain + litellm transitive
# deps. Resulting image is ~9 GB; build cost amortizes over comprehensive
# sweep runs (infrequent — the engine cap that consumes this is opt-in via
# playbook `cap_filter: coverage_tier: comprehensive`).

FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir -e .

# Sanity check — fail the build if garak isn't importable
RUN python -c "import garak; print('garak', garak.__version__)"

# Non-root runtime user
RUN useradd --create-home --shell /bin/bash --uid 1000 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 9224
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "9224"]
