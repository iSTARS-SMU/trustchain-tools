# whatweb

Async wrapper around [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
(Ruby). Stateless; core proxies engine calls after URL scope check.

## Wire

`POST /invoke` accepts a `WhatwebRequest`:

```json
{"target": "https://target.example", "timeout_s": 300}
```

Returns a `WhatwebResult` whose `stdout` is WhatWeb's `--log-json=-` output
(one JSON per plugin hit, separated by newlines). Engines parse:

```python
import json
result = await ctx.call_tool("whatweb", {"target": "https://target.example"})
hits = [json.loads(line) for line in result["stdout"].splitlines() if line.strip()]
for hit in hits:
    for plugin_name, details in hit.get("plugins", {}).items():
        ...
```

## Run locally (without docker)

Requires WhatWeb installed. On macOS: `brew install whatweb`. On Linux:
install from source per upstream docs.

```bash
pip install -e '.[dev]'
uvicorn src.main:app --port 9212
```

## Run via compose

`docker-compose.dev.yml` registers as `whatweb-svc:9212`. Image bundles
Ruby + WhatWeb via apt + git clone.
