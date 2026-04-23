# nuclei

Async wrapper around the [`nuclei`](https://github.com/projectdiscovery/nuclei)
template-based vulnerability scanner. Stateless tool service; only core
orchestrator calls it (after scope-checking `target` against the run's
`authorized_scope`).

## Wire

`POST /invoke` accepts a `NucleiRequest`:

```json
{
  "target": "https://target.example",
  "timeout_s": 300              // optional, 10..1800
}
```

Returns a `NucleiResult`:

```json
{
  "target": "https://target.example",
  "command": "nuclei -u https://target.example -jsonl -silent",
  "returncode": 0,
  "stdout": "{\"template-id\":\"...\",\"info\":{...},\"matched-at\":\"...\"}\n...",
  "stderr": "",
  "duration_ms": 8421,
  "success": true
}
```

`stdout` is **JSONL** — one finding per line. Engines parse with
`json.loads` per line:

```python
import json
result = await ctx.call_tool("nuclei", {"target": "https://target.example"})
findings = [json.loads(line) for line in result["stdout"].splitlines() if line]
for f in findings:
    severity = f["info"]["severity"]
    template = f["template-id"]
    matched_at = f["matched-at"]
    ...
```

## What we don't expose (yet)

`extra_args` / `-tags` / `-severity` / `-templates` are intentionally NOT
exposed in 0.1-alpha. Adding free-form flag pass-through reopens the argument
injection surface; we'll add explicit fields (e.g. `severity: list[Literal[...]]`)
when an engine needs them.

## Engine usage

Engines never reach this service directly. Core's `/api/v1/tools/nuclei/invoke`:

1. Validates the per-attempt callback token
2. **Scope-checks** the target URL against `run.targets[*].authorized_scope`
   via `url_in_scope`
3. Forwards to `http://nuclei-svc:9214/invoke`
4. Wraps response in `ToolResponse`

## Run locally (without docker)

Requires the `nuclei` binary on PATH. Install via:
- macOS: `brew install nuclei`
- Linux: `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`

```bash
pip install -e '.[dev]'
uvicorn src.main:app --port 9214
```

## Run via compose

`docker-compose.dev.yml` registers this as `nuclei-svc:9214` (Go-builder
multi-stage Dockerfile bundles the binary). Core finds it via
`TRUSTCHAIN_TOOL_SERVICE_URLS`.
