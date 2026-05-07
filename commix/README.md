# commix

Command-injection scanner wrapper around
[commix](https://github.com/commixproject/commix). Stateless; core proxies
engine calls after URL scope check.

## Wire

`POST /invoke`:

```json
{
  "target": "http://target.example/?cmd=ls",
  "param": "cmd",
  "method": "GET",
  "cookie": "session=abc",
  "level": 1,
  "timeout_s": 300
}
```

POST mode requires non-empty `data`.

Returns a `CommixResult` whose `stdout` is commix's text output. Engines
grep for `is vulnerable to` / `Technique:` / payload extraction to build
findings.

## Engine usage

```python
result = await ctx.call_tool("commix", {
    "target": "http://t.example/?cmd=ls",
    "param": "cmd",
})
if "is vulnerable to" in result["stdout"]:
    ...
```

## Run locally

```bash
pip install commix
pip install -e '.[dev]'
uvicorn src.main:app --port 9222
```
