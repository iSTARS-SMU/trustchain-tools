# Standalone Dockerfile for the iSTARS-SMU/trustchain-tools public repo.
# Build context = this tool's own directory (NOT monorepo root).
# Synced from monorepo by `bash trustchain/scripts/push-tools.sh whatweb`.
#
# WhatWeb is Ruby — base ruby:3.2-slim + bundle install of upstream repo.

FROM ruby:3.2-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-pip git curl build-essential libyaml-dev \
 && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb \
 && cd /opt/whatweb \
 && bundle install --without development \
 && ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb

COPY pyproject.toml ./
COPY src ./src
RUN pip3 install --no-cache-dir --break-system-packages -e .

EXPOSE 9212
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "9212"]
