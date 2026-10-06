# gadget

Builds **OOB-callback deserialization gadgets** for the pentest-engine
`deser_oob_rce_check` cap (insecure deserialization — OWASP A08:2021 /
CWE-502, engine issue #81). Stateless. **Authorized security testing
only**, same contract as the `sqlmap` / `commix` wrappers here.

This service only *builds* bytes. It never contacts the target and
never deserializes anything. The engine injects the returned gadget at
the target and watches its own OOB listener; a hit proves the target
deserialized attacker-controlled bytes and executed them.

## Wire

`POST /invoke`:

```json
{
  "framework": "auto",
  "callback_url": "http://host.docker.internal:9290/oob/<cid>",
  "callback_type": "http"
}
```

Returns a `GadgetResult`:

```json
{
  "supported": true,
  "variant": "python-pickle",
  "gadget_b64": "<base64 serialized gadget>",
  "callback_url": "http://host.docker.internal:9290/oob/<cid>"
}
```

- `callback_url` — the engine's OOB HTTP listener. The gadget performs a
  single **HTTP GET** here on deserialization (a minimal beacon, not a
  destructive command-exec chain — enough to prove code-exec-on-deser).
- `callback_type` — only `http` (the OOB listener is HTTP; a DNS-only
  gadget such as ysoserial `URLDNS` would never register).

### Backends

| `framework` | backend | status |
|---|---|---|
| `auto` / `python` / `pickle` / `flask` / `django` | Python pickle (`__reduce__` → `urllib.urlopen`) | **built, tested** (stdlib) |
| `java` | ysoserial | not bundled → `supported: false` |
| `php` | phpggc | not bundled → `supported: false` |
| `ruby` / `dotnet` / `node` | — | not bundled → `supported: false` |

Add a backend the same way the `commix` / `sqlmap` Dockerfiles bundle
their CLIs (download a pinned ysoserial jar + JRE, or phpggc + php-cli),
then wire it into `build_gadget()`.

## Engine usage

Driven by the cap's `pre_fire` hook — opt in by adding a `gadget` entry
to `PENTEST_TOOL_URLS`:

```
PENTEST_TOOL_URLS='{"gadget": "http://gadget-svc:9295"}'
```

Without it the cap falls back to its in-band deserializer-error oracle
(candidate tier). With it, an OOB callback confirms RCE.

## Run locally

```bash
docker compose build gadget-svc && docker compose up -d gadget-svc
# or: uvicorn src.main:app --port 9295
pytest   # unit tests (incl. a real deserialize-and-beacon check)
```
