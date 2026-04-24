# trustchain-tool-webstructure

HTML structure-discovery tool. Recursively crawls a target site and
returns `web_pages`, `forms`, and `api_hints`. Used by recon engines
to find endpoints that wordlist-based tools like feroxbuster miss
(form actions, in-page links, API-doc endpoints).

Port of
[`LLMAppSec/services/webstructure-collector/`](../../../../LLMAppSec/services/webstructure-collector/)
(2426 LOC, 4-stage PageDiscovery → PageRetrieval → FunctionDiscovery →
RequestExtraction) distilled to a single `/invoke` endpoint.

## Status

**Current version: `0.1.0`**. Covers link crawl + form extraction +
API-doc hints over plain HTML. **No Playwright / SPA support in v0.1** —
deferred; adding Chromium would ~triple the image size.

| Feature | v0.1 | deferred |
|---|---|---|
| Same-origin recursive link crawl | ✅ | |
| `<form>` → structured fields (name / type / required) | ✅ | |
| API-doc hint flagging (`/openapi.json`, `/swagger.json`, etc.) | ✅ | |
| `max_depth` / `max_pages` caps | ✅ | |
| JS-rendered SPA pages (Playwright) | ❌ | v0.2 |
| robots.txt parsing / respect | ❌ | v0.2 (pentest context usually ignores anyway) |
| OpenAPI / Swagger dereferencing → full endpoint list | ❌ | v0.2 |
| Auth-walled crawl (session cookies) | ❌ | v0.2 |

## Request / Response

```
POST /invoke
{
  "target_url": "https://app.example/",
  "max_depth": 2,          // optional, default 2, max 4
  "max_pages": 50,         // optional, default 50, max 500
  "same_origin_only": true,
  "timeout_sec": 10.0,
  "concurrency": 4
}
```

```json
{
  "success": true,
  "web_pages": [
    {"path": "/",       "status_code": 200, "title": "Home",  "content_type": "text/html", "size_bytes": 4829},
    {"path": "/login",  "status_code": 200, "title": "Login", "content_type": "text/html", "size_bytes": 1122}
  ],
  "forms": [
    {"page_path": "/login", "method": "POST", "action": "https://app.example/login",
     "fields": [{"name": "username", "type": "text",     "required": true},
                {"name": "password", "type": "password", "required": true}]}
  ],
  "api_hints": ["/openapi.json"],
  "pages_crawled": 2,
  "duration_sec": 0.31
}
```

## Soft-fail behavior

- Invalid `target_url` (missing scheme) → `success=false`, `error="bad_request: ..."`
- Connection error on seed → `success=true` with one `web_pages` entry that has `status_code=0` — crawl aborts early but doesn't raise
- Partial crawl failures (some pages unreachable) → `status_code=0` on those entries, others render normally
- Caller (recon engine) decides whether to treat `success=false` or `pages_crawled=0` as a soft-fail

## Local run

```bash
source .venv/bin/activate
pip install -e 'trustchain/tools/webstructure[dev]'

# 12 unit tests (respx-mocked network, no real fetches)
(cd trustchain/tools/webstructure && pytest -q)

# Run standalone
uvicorn webstructure.main:app --port 9218
curl -X POST http://localhost:9218/invoke -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com/", "max_depth": 1}' | jq .
```

## Publishing

Follows the same flow as the other tools — `push-tools.sh` rsyncs into
`iSTARS-SMU/trustchain-tools`, tag `tools-webstructure-v0.1.0` triggers
the umbrella's GHA build, image lands at
`ghcr.io/istars-smu/trustchain-tool-webstructure:0.1.0` (public).
