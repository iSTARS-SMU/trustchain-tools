# http_fetch

Engine egress proxy. The ONLY legal way for an engine to make outbound HTTP
requests against a target (spec §5.2 R6, engine-contract §4.5).

## Wire

`POST /invoke` accepts a [`HttpFetchRequest`](../../contracts/trustchain_contracts/tools.py)
and returns a [`HttpFetchResult`](../../contracts/trustchain_contracts/tools.py).

The service does **not** authenticate or scope-check — that lives in core.
Engines never reach this service directly; they go through
`{callbacks.tools_url}/http_fetch/invoke` on the orchestrator, which:

1. Validates the per-attempt callback token
2. Scope-checks the URL against `run.targets[*].authorized_scope`
3. Forwards the `request` field to this service
4. Wraps the response in a `ToolResponse` envelope

## Run locally (without docker)

```bash
pip install -e '.[dev]'
uvicorn src.main:app --port 9220
```

## Run via compose

`docker-compose.dev.yml` registers this service as `http-fetch-svc:9220`. Core
finds it via `TRUSTCHAIN_TOOL_SERVICE_URLS_HTTP_FETCH=http://http-fetch-svc:9220`.
