# trustchain-tools

Scanning + recon tool services for the [TrustChain Pentest](https://github.com/iSTARS-SMU)
platform. Each subdirectory is one stateless FastAPI HTTP wrapper around an
external CLI binary or REST API (nmap, nuclei, exa-search, …).

**This repo is for student / external developers** who want to run the same
tool services locally that the TrustChain lab runs. Source is mirrored from
the (private) trustchain monorepo via `push-tools.sh`.

## Quickstart — pull pre-built images

```bash
git clone https://github.com/iSTARS-SMU/trustchain-tools.git
cd trustchain-tools
docker compose up -d nmap-svc http-fetch-svc dig-svc
```

By default `docker-compose.yml` uses `image:` references pointing at GHCR
(`ghcr.io/istars-smu/trustchain-tool-<name>:latest`), so the first
`compose up` just pulls. No build environment needed on your machine.

For specific versions, edit `docker-compose.yml` and pin tags
(e.g. `ghcr.io/istars-smu/trustchain-tool-nmap:0.1.0`).

## Quickstart — build locally

If you want to hack on a tool wrapper:

```bash
docker compose build nmap-svc           # uses ./nmap/Dockerfile, ~30s
docker compose up -d nmap-svc
curl -X POST http://localhost:9211/invoke \
     -H "Content-Type: application/json" \
     -d '{"target":"scanme.nmap.org","mode":"basic"}'
```

## Tools in this repo

| Tool         | Port | Image                                                  |
|--------------|------|--------------------------------------------------------|
| `dig`        | 9207 | `ghcr.io/istars-smu/trustchain-tool-dig`               |
| `exa-search` | 9216 | `ghcr.io/istars-smu/trustchain-tool-exa-search`        |
| `feroxbuster`| 9215 | `ghcr.io/istars-smu/trustchain-tool-feroxbuster`       |
| `http_fetch` | 9220 | `ghcr.io/istars-smu/trustchain-tool-http_fetch`        |
| `nvd-search` | 9217 | `ghcr.io/istars-smu/trustchain-tool-nvd-search`        |
| `nmap`       | 9211 | `ghcr.io/istars-smu/trustchain-tool-nmap`              |
| `nuclei`     | 9214 | `ghcr.io/istars-smu/trustchain-tool-nuclei`            |
| `wafw00f`    | 9213 | `ghcr.io/istars-smu/trustchain-tool-wafw00f`           |
| `whatweb`    | 9212 | `ghcr.io/istars-smu/trustchain-tool-whatweb`           |

Each tool exposes:
- `POST /invoke` — run the underlying scan; request/response shapes vary
  per tool (see each `<tool>/README.md` and `<tool>/src/main.py` model
  classes)
- `GET /healthz` — liveness

## Using these with your own engine

Pair this repo with the
[TrustChain SDK](https://github.com/iSTARS-SMU/engine-template)'s
`DevHarness` for a complete local dev stack — your engine + real tools, no
core needed:

```python
from trustchain_sdk.testing import DevHarness

async with DevHarness(
    engine_app=MyEngine(),
    tool_urls={
        "nmap":       "http://localhost:9211",
        "http_fetch": "http://localhost:9220",
    },
    authorized_scope=["scanme.nmap.org"],
) as harness:
    result = await harness.run_once(target=..., config={"mode": "basic"})
```

See [iSTARS-SMU/engine-template](https://github.com/iSTARS-SMU/engine-template)
for the engine-side dev flow.

## Source

Each tool's source lives in this repo's subdirectories. Original development
happens in the (private) trustchain monorepo; `push-tools.sh` mirrors here on
release. Issues and PRs are welcome here — they get triaged + back-ported.

## Releases

Tag pattern `tools-<name>-v<X.Y.Z>` triggers a multi-platform GHA build that
publishes the corresponding image to GHCR. See `.github/workflows/build-tool.yml`.

## License

Each tool's wrapper code is MIT-licensed (see the LICENSE file in each subdir
or the upstream tool's own license for the underlying binary).
