# nvd-search

Thin HTTP wrapper over NVD 2.0 REST API
(`https://services.nvd.nist.gov/rest/json/cves/2.0`). Shipped as a
TrustChain Pentest tool service; consumed by the weakness-gather-exa
engine (and any future engine that needs authoritative CVE data).

Port: **9217**.

## Why NVD alongside Exa?

`exa-search` gives web-search-based results (good for PoCs and
recent blog discussions) but noisy (marketing pages, outdated
forum threads). NVD is the authoritative CVE database — every CVE
has a fixed ID, CVSS metrics, CPE-matched configurations, and
primary/secondary references. Using NVD for structured CVE lookup
+ Exa for narrative context gives higher-signal weakness candidates
than either alone.

See [doc/TODO.md](../../../doc/TODO.md) "Choice 5 — dual-source
weakness_gather" for the design rationale.

## Config

| env var      | required?      | notes                                          |
|--------------|----------------|------------------------------------------------|
| `NVD_API_KEY`| optional       | Without it: 5 requests / 30s (rolling).        |
|              |                | With it: 50 requests / 30s. Free signup at     |
|              |                | https://nvd.nist.gov/developers/request-an-api-key |

## Request shape

```json
POST /invoke
{
  "cpe_name": "cpe:2.3:a:django:django:4.2.0:*:*:*:*:*:*:*",
  "cvss_v3_severity": "HIGH",
  "results_per_page": 20
}
```

One of `cpe_name` / `keyword_search` / `cve_id` MUST be set — NVD
rejects unfiltered queries (would return the entire DB). Optional
filters compose on top.

## Response shape

```json
{
  "request_echo": {...},
  "total_results": 42,
  "vulnerabilities": [... raw NVD entries ...],
  "duration_ms": 318,
  "success": true,
  "error": null
}
```

All failure modes (429 rate limit / 401-403 auth / timeout / transport
error / non-JSON response / 5xx upstream / 400 client error) return
**HTTP 200** with `success=false` + human-readable `error` field.
Lets engines' ctx.call_tool loops treat tool calls as always-200 and
branch on the inner success flag. Mirrors the pattern used by
exa-search.

Special case: `404 Not Found` for a specific `cve_id` is treated as
`success=true, vulnerabilities=[]` (empty result, not an error) — NVD
returns 404 for unknown CVE IDs and engines iterating lists of CVE
IDs shouldn't get spammed with error notices.

## Local development

```bash
# From monorepo root
pip install -e trustchain/tools/nvd-search'[dev]'
pytest trustchain/tools/nvd-search/

# Run the service locally
uvicorn nvd_search.main:app --port 9217

# Real query (needs network; 5/30s rate limit without NVD_API_KEY)
curl -X POST http://localhost:9217/invoke \
    -H 'Content-Type: application/json' \
    -d '{"cve_id": "CVE-2021-44228"}'
# → log4shell CVE
```
