# trustchain-tool-garak

FastAPI wrapper around [NVIDIA garak](https://github.com/NVIDIA/garak)
(Apache-2.0) — comprehensive LLM-safety probe orchestrator.

Consumed by pentest-engine's `garak_wrapper` distillation
(`coverage_tier=comprehensive`, opt-in via playbook `cap_filter`).

## Endpoints

```
POST /api/v1/garak/scan       → {"task_id": "...", "status": "queued"}
GET  /api/v1/tasks/{task_id}  → {"status", "report_jsonl", ...}
GET  /healthz                 → {"status": "healthy", "service": "garak"}
```

Async-task because comprehensive sweeps regularly exceed any reasonable
sync HTTP timeout (default `TASK_TIMEOUT=1800` = 30 min).

## Config (engine-side)

```jsonc
PENTEST_TOOL_URLS = {
  "garak": {
    "url": "http://localhost:9224",
    "submit_path": "/api/v1/garak/scan",
    "poll_path": "/api/v1/tasks/{task_id}",
    "submit_id_field": "task_id",
    "poll_status_field": "status",
    "done_status_values": ["completed"],
    "failed_status_values": ["failed"]
  }
}
```

## Build + run

```sh
docker build -t trustchain-tool-garak:dev .
docker run --rm -p 9224:9224 trustchain-tool-garak:dev
curl http://localhost:9224/healthz
```

Image is ~9 GB (torch + transformers + langchain + litellm + …). Build
cost ~10 min on first run; cached after.

## Smoke a real scan

```sh
curl -X POST http://localhost:9224/api/v1/garak/scan \
  -H 'Content-Type: application/json' \
  -d '{
    "target_url": "https://api.example.com",
    "framework": "openai-compat",
    "model_name": "Qwen/Qwen3-7B",
    "probes": ["dan.Dan_11_0"]
  }'
# → {"task_id": "...", "status": "queued"}

curl http://localhost:9224/api/v1/tasks/<task_id>
# → {"status": "completed", "report_jsonl": "...", ...}
```

## Tests

```sh
pip install -e '.[dev]'
pytest -q
```

(Smoke tests don't actually run garak — that requires the full image.)

## Security

Scope-checking is the **caller's** responsibility. This service trusts
`target_url` and runs garak against it. Operator deploys behind an
internal service mesh / scoped reverse-proxy as appropriate.

`probes` and `model_name` reject leading-dash forms to prevent argv
injection; everything else is passed through to garak.
