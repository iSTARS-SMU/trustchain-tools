# feroxbuster

Async wrapper around [`feroxbuster`](https://github.com/epi052/feroxbuster) —
a recursive content/path discovery tool. Stateless tool service; only core
orchestrator calls it (after scope-checking `target`).

## Wire

`POST /invoke` accepts a `FeroxbusterRequest`:

```json
{
  "target": "https://target.example",
  "timeout_s": 300              // optional, 10..1800
}
```

Returns a `FeroxbusterResult`:

```json
{
  "target": "https://target.example",
  "command": "feroxbuster -u https://target.example --no-state -q",
  "returncode": 0,
  "stdout": "https://target.example/admin\nhttps://target.example/login\n...",
  "stderr": "",
  "duration_ms": 12345,
  "success": true
}
```

`stdout` is **one discovered URL per line** (`-q` strips banner/progress).
Engines split on newlines:

```python
result = await ctx.call_tool("feroxbuster", {"target": "https://target.example"})
discovered = [u.strip() for u in result["stdout"].splitlines() if u.strip()]
```

## What we don't expose (yet)

`--wordlist`, `--depth`, `--threads`, `--extensions` are intentionally NOT
exposed in 0.1-alpha. Adding free-form flag pass-through reopens the argument
injection surface; we'll add explicit fields when an engine needs them. The
default wordlist (built into feroxbuster) is good enough for thin-slice work.

## Engine usage

Engines never reach this service directly. Core's
`/api/v1/tools/feroxbuster/invoke`:

1. Validates the per-attempt callback token
2. **Scope-checks** the target URL against `run.targets[*].authorized_scope`
   via `url_in_scope`
3. Forwards to `http://feroxbuster-svc:9215/invoke`
4. Wraps response in `ToolResponse`

## Run locally (without docker)

Requires the `feroxbuster` binary on PATH. Install via:
- macOS: `brew install feroxbuster`
- Debian/Kali: `apt install feroxbuster`

```bash
pip install -e '.[dev]'
uvicorn src.main:app --port 9215
```

## Run via compose

`docker-compose.dev.yml` registers this as `feroxbuster-svc:9215` (image
based on `kalilinux/kali-rolling` which ships feroxbuster in apt). Core
finds it via `TRUSTCHAIN_TOOL_SERVICE_URLS`.
