# feroxbuster

Async wrapper around [`feroxbuster`](https://github.com/epi052/feroxbuster) —
a recursive content/path discovery tool. Stateless tool service; only core
orchestrator calls it (after scope-checking `target`).

## API v0.2

`POST /invoke` accepts a `FeroxbusterRequest`:

```json
{
  "target": "https://target.example",
  "timeout_s": 300,
  "rate_limit": 10,
  "wordlist_name": "ai-app",
  "max_requests": 200,
  "max_depth": 1
}
```

| field | type | default | notes |
|---|---|---|---|
| `target` | str | required | http(s) URL; engine MUST scope-check before calling |
| `timeout_s` | int (10–1800) | 300 | Server wall-clock kill timer |
| `rate_limit` | int (1–10000)\|null | null | Outbound req/sec cap → `--rate-limit` |
| `wordlist_name` | enum: `common`, `ai-app` | `common` | Which baked wordlist (see § Wordlists) |
| `max_requests` | int (1–1000000)\|null | null | Approximate budget; needs `rate_limit` to be effective (see § Budget) |
| `max_depth` | int (1–10) | 1 | Recursion depth → `--depth` |

Returns `FeroxbusterResult`:

```json
{
  "target": "https://target.example",
  "command": "feroxbuster -u https://target.example --no-state -q -w /app/wordlists/ai-app.txt --depth 1 --rate-limit 10 --time-limit 20s",
  "returncode": 0,
  "stdout": "https://target.example/admin\nhttps://target.example/login\n...",
  "stderr": "",
  "duration_ms": 12345,
  "success": true,
  "wordlist_name": "ai-app",
  "rate_limit": 10,
  "max_requests": 200,
  "max_depth": 1
}
```

`stdout` is **one CANDIDATE URL per line**. The trailing reflection fields
echo what budget / wordlist / rate the run actually used (so the engine
ledger can record it without re-parsing the request).

## ⚠️  Output contract — candidate URLs only, NOT live status

`stdout` is candidate URLs as feroxbuster discovered them. **No live
HTTP status, no method, no response body**. The engine collector MUST
post-verify each candidate via its own HTTP client (HEAD/GET) and only
emit a `ReconSurface` on `2xx/3xx/401/403`. Lines whose verify lands on
`404/410/4xx/5xx/timeout/connection refused` MUST be dropped, not
emitted.

This is a load-bearing rule from the pentest-engine
`endpoint-discovery-spec` security envelope:

> Discovered URLs MUST be re-fetched by pentest-engine via
> `ModuleHttpClient`. Only on 2xx/3xx/401/403 do we emit a ReconSurface;
> 404/410/400/5xx → drop. … the tool services are external; their fetch
> may not enforce our auth/scope/budget; and we want the artifact in
> our own ledger so downstream caps can replay deterministically.

The tool service does not perform verification — it deliberately stops
at "candidate". This keeps the service simple, isolates the verify
logic + auth state in one place (the engine), and prevents the tool
from inflating recall via dead URLs from old wordlists.

## Wordlists

Two baked options in v0.2:

| `wordlist_name` | Source | Size | Use when |
|---|---|---|---|
| `common` | feroxbuster's compiled-in default | ~4500 generic web paths | Generic web app; nothing AI-specific known |
| `ai-app` | `wordlists/ai-app.txt` (this repo) | ~196 paths | Target profile suggests AI / LLM / agent component (chat / completions / embeddings / mcp / langserve etc.) |

`raft-large-words` is reserved in the spec but not yet shipped — would
require vendoring `SecLists/Discovery/Web-Content/raft-large-words.txt`
(~1.4 MB). Defer to v0.3 when there's a documented use case.

The `ai-app` wordlist is curated from generic AI-application conventions
(OpenAI-shape `/v1/*`, MCP `/sse`, LangServe `/chain/*`, vector-DB
`/api/v1/collections`, etc.) — no per-product / per-customer paths.
Customer-specific paths belong in the recon engine's KB layer, not in
the wordlist.

## Budget semantics — `max_requests`

feroxbuster does **not** have a native global request counter, so
`max_requests` is approximate:

- If `rate_limit` is also set → service derives
  `--time-limit = ceil(max_requests / rate_limit) seconds`. feroxbuster
  terminates when the time budget is exhausted; the actual request count
  is `≤ rate_limit × time_limit_s`.
- If `rate_limit` is unset → `max_requests` is a **hint** the engine
  collector enforces post-hoc by truncating the URL list to the first
  N entries before verification.

In both cases the engine should also enforce its own pre-call /
post-call request budget via `ExternalCollectorRun.requests_spent`
(security envelope, defense in depth).

## Engine usage

Engines never reach this service directly. Pentest-engine's
`recon/collectors/external/feroxbuster.py` (Phase A2):

1. Pre-call: builds the `FeroxbusterRequest` from scan profile,
   scope-checks `target`, picks `wordlist_name` from target shape.
2. POSTs to `http://feroxbuster-svc:9215/invoke`.
3. Splits `stdout` on newlines → candidate URLs.
4. Filters: drops anything outside engagement scope.
5. Verifies each survivor via `ModuleHttpClient.head_or_get(url)`.
6. Emits `ReconSurface(source_kind="wordlist")` only on
   `2xx/3xx/401/403`; everything else dropped silently.
7. Records `ExternalCollectorRun(raw_count, filtered_count,
   verified_count, requests_spent, ...)` ledger entry.

## Run locally (without docker)

Requires the `feroxbuster` binary on PATH. Install via:

- macOS: `brew install feroxbuster`
- Debian/Kali: `apt install feroxbuster`

Tests + dev:

```bash
pip install -e '.[dev]'
pytest tests/ -q
```

The wordlist registry defaults to `/app/wordlists` (the path inside the
container). For local dev, set `FEROXBUSTER_WORDLIST_DIR` to point at
this repo's `wordlists/` directory:

```bash
FEROXBUSTER_WORDLIST_DIR=$PWD/wordlists \
  uvicorn src.main:app --port 9215
```

## Run via compose

`docker-compose.yml` registers this as `feroxbuster-svc:9215`. The
Dockerfile bakes `wordlists/` into `/app/wordlists/` so no mount is
needed in production.

## Backward compatibility

API v0.2 is fully backward-compatible with v0.1: requests with only
`{"target": "..."}` continue to work, defaulting to `wordlist_name=common`,
`max_depth=1`, and no rate limit / no request cap. The new fields in the
response (`wordlist_name`, `rate_limit`, `max_requests`, `max_depth`)
are additive — old engine clients ignoring them is fine.
