# exa-search

Thin async wrapper over the [Exa.ai](https://exa.ai/) web search API.
Stateless tool service used by LLM-driven engines (initial consumer:
`weakness-gather-exa` in Phase 3).

## Wire

`POST /invoke`:

```json
{
  "query": "Django 4.2 CVE vulnerabilities",
  "num_results": 20,
  "search_type": "auto",
  "include_domains": ["nvd.nist.gov", "cve.mitre.org"],
  "exclude_domains": null,
  "timeout_s": 30
}
```

Returns an `ExaSearchResult`:

```json
{
  "query": "Django 4.2 CVE vulnerabilities",
  "results": [
    {
      "title": "CVE-2024-... — Django path traversal",
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-...",
      "text": "First 1000 chars of Exa's LLM-friendly excerpt ...",
      "score": 0.94,
      "publishedDate": "2024-07-15T00:00:00Z"
    }
  ],
  "num_results_requested": 20,
  "num_results_returned": 17,
  "duration_ms": 1240,
  "success": true,
  "error": null
}
```

**Fail-soft**: rate limits / auth failures / transport errors all surface
as `success=false` + a human-readable `error` string. Engines should treat
this like any other tool soft-fail — keep going with degraded signal.

## Secret management

`EXA_API_KEY` lives in the tool's container env (set via compose /
docker run `-e`). It is **never** exposed to engines — `ctx.secrets`
doesn't carry it. Engines only see `ExaSearchResult`. Same model as
nmap binary / nuclei binary being in the tool's image, not the engine's.

Rotate: change the env value, restart the `exa-search-svc` container.

## Engine usage

```python
result = await ctx.call_tool(
    "exa-search",
    {"query": "Django 4.2 CVE", "num_results": 20},
)
if not result["success"]:
    ctx.logger.warning("exa unavailable: %s", result["error"])
    # fall back to upstream-only signal
else:
    for hit in result["results"]:
        url = hit["url"]
        excerpt = hit.get("text", "")
        ...
```

Note: `ctx.call_tool` does NOT raise on `success=false` — the tool's
result is the SDK return value. Engines MUST check `success` themselves.
(This diverges slightly from the `scans[N].returncode` convention of
subprocess-wrapping tools; Exa is a remote API, not a binary.)

## Run locally (without docker)

```bash
export EXA_API_KEY=<your-exa-key>
pip install -e '.[dev]'
uvicorn src.main:app --port 9216
```

## Run via compose

`docker-compose.dev.yml` registers this as `exa-search-svc:9216`. Core
finds it via `TRUSTCHAIN_TOOL_SERVICE_URLS`. Set `EXA_API_KEY` in
`.env.lab` (or shell env in local dev) — compose passes it through.

## Why not use `ctx.fetch("https://api.exa.ai/search")` directly from an engine?

Two reasons:

1. **Scope check**: `ctx.fetch` URL-scope-gates against Run's
   `authorized_scope`. `api.exa.ai` isn't a target, so it'd never be in
   scope. We'd have to carve a bypass — ugly.
2. **Secret placement**: engine would need `ctx.secrets.exa`, pushing the
   key into every Run's submission payload. For a shared platform-infra
   key (lab admin's), that's wrong — the key should stay server-side.

Wrapping as a tool solves both.
