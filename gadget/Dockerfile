# Standalone Dockerfile for the iSTARS-SMU/trustchain-tools public repo.
# Build context = this tool's own directory (NOT monorepo root).
#
# The pickle backend is pure stdlib — no external binary needed. To add
# the Java / PHP backends, bundle their CLIs here the same way the
# commix/sqlmap Dockerfiles do (e.g. download a pinned ysoserial jar +
# a JRE, and phpggc + php-cli), then wire them into build_gadget().

FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir -e .

EXPOSE 9295
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "9295"]
