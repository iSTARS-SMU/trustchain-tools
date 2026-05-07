# sqlmap

SQL-injection scanner wrapper around [sqlmap](https://sqlmap.org/).
Stateless; core proxies engine calls after URL scope check.

## Wire

`POST /invoke`:

```json
{
  "target": "http://target.example/?id=1",
  "param": "id",
  "method": "GET",
  "cookie": "PHPSESSID=abc; security=low",
  "level": 1,
  "risk": 1,
  "timeout_s": 300
}
```

POST mode requires non-empty `data`:

```json
{
  "target": "http://target.example/login",
  "param": "username",
  "method": "POST",
  "data": "username=admin&password=x"
}
```

Returns a `SqlmapResult` whose `stdout` is sqlmap's text output. Engines
grep for `is vulnerable` / `Type:` / `Payload:` / detected DBMS to build
findings.

## Engine usage

```python
result = await ctx.call_tool("sqlmap", {
    "target": "http://t.example/?id=1",
    "param": "id",
})
if "is vulnerable" in result["stdout"]:
    ...
```

## Run locally

```bash
pip install sqlmap
pip install -e '.[dev]'
uvicorn src.main:app --port 9221
```
