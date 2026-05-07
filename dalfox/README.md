# dalfox

XSS scanner wrapper around [dalfox](https://github.com/hahwul/dalfox).
Stateless; core proxies engine calls after URL scope check.

## Wire

`POST /invoke`:

```json
{
  "target": "http://target.example/?q=test",
  "param": "q",
  "method": "GET",
  "cookie": "PHPSESSID=abc; security=low",
  "timeout_s": 120
}
```

POST mode requires non-empty `data`.

Returns a `DalfoxResult` whose `stdout` is dalfox's JSON output (one
finding per line). Empty stdout = no XSS detected.

## Engine usage

```python
import json
result = await ctx.call_tool("dalfox", {
    "target": "http://t.example/?q=test",
    "param": "q",
})
for line in result["stdout"].splitlines():
    if not line.strip():
        continue
    finding = json.loads(line)
    # finding["type"] == "V" / "R" / "G" — verified / reflected / generic
    ...
```

## Run locally

```bash
# Get the dalfox binary on PATH (releases at github.com/hahwul/dalfox/releases)
pip install -e '.[dev]'
uvicorn src.main:app --port 9223
```
