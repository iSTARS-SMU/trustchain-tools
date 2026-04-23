# nmap

Async wrapper around the `nmap` binary. Stateless tool service; only core
orchestrator calls it (after scope-checking `target` against the run's
`authorized_scope`).

## Wire

`POST /invoke` accepts an `NmapRequest`:

```json
{
  "target": "scanme.nmap.org",
  "mode": "basic",         // basic | comprehensive | web
  "timeout_s": 300         // optional, 10..1800
}
```

Returns an `NmapResult`:

```json
{
  "target": "scanme.nmap.org",
  "mode": "basic",
  "scans": [
    {
      "name": "basic",
      "command": "nmap -Pn -T4 -sV -sC scanme.nmap.org",
      "returncode": 0,
      "stdout": "...",
      "stderr": "",
      "duration_ms": 4321
    }
  ],
  "success": true
}
```

## Modes

| mode | command(s) | typical use |
|---|---|---|
| `basic` | `nmap -Pn -T4 -sV -sC` | quick service detection (default) |
| `comprehensive` | full port + NSE default/safe + web enum (3 scans) | deep recon |
| `web` | `-p 80,443,8080,8443 -sV --script http-*` | HTTP-only enum |

## Engine usage

```python
result = await ctx.call_tool("nmap", {
    "target": "target.example",
    "mode": "comprehensive",
})
for run in result["scans"]:
    if run["returncode"] != 0:
        ctx.logger.warning("scan %s failed: %s", run["name"], run["stderr"])
    parse(run["stdout"])
```

Engines never reach this service directly. Core's `/api/v1/tools/nmap/invoke`:

1. Validates the per-attempt callback token
2. **Scope-checks** `target` against `run.targets[*].authorized_scope` via
   `host_in_scope` (domain wildcard / IPv4 / IPv6 / CIDR)
3. Forwards to `http://nmap-svc:9211/invoke`
4. Wraps response in `ToolResponse`

## Run locally (without docker)

```bash
# Requires nmap on PATH (e.g. brew install nmap or apt install nmap)
pip install -e '.[dev]'
uvicorn src.main:app --port 9211
```

## Run via compose

`docker-compose.dev.yml` registers this as `nmap-svc:9211`. Core finds it via
the `TRUSTCHAIN_TOOL_SERVICE_URLS` JSON map.
