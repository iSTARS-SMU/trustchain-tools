# wafw00f

WAF detection wrapper around [wafw00f](https://github.com/EnableSecurity/wafw00f).
Stateless; core proxies engine calls after URL scope check.

## Wire

`POST /invoke`:

```json
{"target": "https://target.example", "find_all": true, "timeout_s": 120}
```

Returns a `Wafw00fResult` whose `stdout` is wafw00f's JSON output.

Engines:

```python
import json
result = await ctx.call_tool("wafw00f", {"target": "https://t.example"})
data = json.loads(result["stdout"])   # list of {url, detected, firewall, manufacturer}
for entry in data:
    if entry.get("detected"):
        waf_name = entry.get("firewall")
        ...
```

## Run locally

`pip install wafw00f` then:

```bash
pip install -e '.[dev]'
uvicorn src.main:app --port 9213
```
