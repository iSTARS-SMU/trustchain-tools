# dig

DNS record lookup wrapper. Stateless tool service; core proxies engine
calls to it after scope-checking the target domain.

## Wire

`POST /invoke` accepts a `DigRequest`:

```json
{
  "target": "example.com",
  "record_types": ["A", "AAAA", "MX", "NS", "TXT"],
  "timeout_s": 30
}
```

Returns a `DigResult`:

```json
{
  "target": "example.com",
  "records": [
    {"record_type": "A",    "values": ["93.184.216.34"]},
    {"record_type": "AAAA", "values": ["2606:2800:220:1:248:1893:25c8:1946"]},
    {"record_type": "MX",   "values": ["10 mail.example.com"]},
    {"record_type": "NS",   "values": ["a.iana-servers.net", "b.iana-servers.net"]},
    {"record_type": "TXT",  "values": ["v=spf1 -all"]}
  ],
  "duration_ms": 120,
  "success": true
}
```

All requested record types run in parallel (1 subprocess per type).
`success=false` means every query errored — NXDOMAIN still gives `success=true`
with empty `values` arrays.

## Engine usage

```python
result = await ctx.call_tool("dig", {"target": "target.example"})
for rec in result["records"]:
    ctx.logger.info("%s → %s", rec["record_type"], rec["values"])
```

## Run locally (without docker)

Requires `dig` binary (`apt install dnsutils` / `brew install bind`).

```bash
pip install -e '.[dev]'
uvicorn src.main:app --port 9207
```

## Run via compose

`docker-compose.dev.yml` registers this as `dig-svc:9207`.
