"""garak tool service — async-task wrapper around the `garak` Python CLI.

Stateless single-replica. The pentest-engine `garak_wrapper` cap calls
``ctx.tools.call_tool('garak', {...})`` AFTER scope-checking the target,
which fans out to:

    POST /api/v1/garak/scan       → {"task_id", "status": "queued"}
    GET  /api/v1/tasks/{task_id}  → {"status", "report_jsonl", ...}

Async-task (not sync `/invoke`) because comprehensive garak sweeps regularly
take 5–30 min — well past any reasonable HTTP timeout.

## Probe selection

Caller supplies `probes: list[str]`. Special value `"all"` runs garak's
default-active set. Specific names match garak's `--probes` flag (e.g.
`promptinject.HijackHateHumansFull`, `dan.Dan_11_0`,
`latentinjection.LatentInjectionFactCheckerFull`).

## Framework dispatch

Caller supplies `framework: 'openai-compat'|'ollama'|'tgi'|'rest'`; we map
to garak's `--model_type` + `--model_name` flags. For 'openai-compat' the
target_url should be the BASE URL (e.g. `https://api.example.com`); garak
appends `/v1/chat/completions` itself.

## Endpoints

POST /api/v1/garak/scan  → submit a scan (GarakScanRequest)
GET  /api/v1/tasks/{id}  → poll a scan
GET  /healthz            → liveness probe

## Security

- `target_url` must parse as an http(s) URL — operator is responsible
  for scope-checking before calling this service. The service does not
  re-enforce the engine's lab-host gate; trustchain-tools' philosophy
  is that scope is decided one layer up.
- `probes` and `model_name` are passed verbatim to garak, which validates
  them itself; we still reject leading-dash forms to avoid argv injection.
- subprocess runs garak via `python -m garak` (list-form, no shell).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))


_TASK_TIMEOUT_S = int(os.environ.get("TASK_TIMEOUT", "1800"))     # 30 min
_REPORT_TAIL_BYTES = 4096
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,256}$")          # probe/model names (':' for ollama name:tag)

# In-memory task table. Single-replica service; that's fine for v1.
# If multi-replica becomes a need, persist to MinIO / Postgres.
_tasks: dict[str, dict] = {}


# ─── Request / response models ──────────────────────────────────────


class GarakScanRequest(BaseModel):
    model_config = {"extra": "forbid"}

    target_url: str = Field(..., min_length=8, max_length=2048)
    framework: Literal["openai-compat", "ollama", "tgi", "rest"] = Field(
        default="openai-compat",
    )
    model_name: str = Field(default="default", max_length=256)
    probes: list[str] = Field(
        default_factory=lambda: ["all"],
        description=(
            "garak probe names. 'all' = garak's default-active set."
        ),
    )
    timeout_s: int = Field(default=_TASK_TIMEOUT_S, ge=60, le=3600)
    rest_config: dict | None = Field(
        default=None,
        description=(
            "Required iff framework='rest' — garak rest model config "
            "(headers, body templates, etc.). See garak/generators/rest.py."
        ),
    )

    @field_validator("target_url")
    @classmethod
    def _check_target_url(cls, v: str) -> str:
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("target_url must be http(s)")
        if not parsed.hostname:
            raise ValueError("target_url has no host")
        return v

    @field_validator("model_name")
    @classmethod
    def _check_model_name(cls, v: str) -> str:
        if v.startswith("-") or not _SAFE_NAME_RE.match(v):
            raise ValueError("model_name contains disallowed characters")
        return v

    @field_validator("probes")
    @classmethod
    def _check_probes(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("probes must not be empty")
        for p in v:
            if p.startswith("-") or not _SAFE_NAME_RE.match(p):
                raise ValueError(
                    f"probe {p!r} contains disallowed characters"
                )
        return v


class GarakScanSubmit(BaseModel):
    task_id: str
    status: Literal["queued"]


# ─── App + lifespan ─────────────────────────────────────────────────


_garak_importable: bool = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _garak_importable
    if shutil.which("python") is None:
        logger.warning("python interpreter missing in image")
    try:
        import garak  # noqa: F401 — import-only check
        _garak_importable = True
        logger.info("garak service ready (TASK_TIMEOUT=%ds)", _TASK_TIMEOUT_S)
    except Exception as e:
        # Don't fail the lifespan — let healthz report degraded so the
        # service still serves error responses to scan submits with a
        # clear reason. Tests can run without garak installed.
        logger.warning("garak not importable: %s", e)
    yield


app = FastAPI(title="trustchain-tool-garak", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict:
    return {
        "status": "healthy" if _garak_importable else "degraded",
        "service": "garak",
        "garak_importable": _garak_importable,
    }


@app.post("/api/v1/garak/scan", response_model=GarakScanSubmit)
async def submit_scan(
    req: GarakScanRequest, bg: BackgroundTasks,
) -> GarakScanSubmit:
    task_id = str(uuid.uuid4())
    _tasks[task_id] = {
        "status": "queued",
        "tool": "garak",
        "target": req.target_url,
        "framework": req.framework,
        "probes": req.probes,
        "started_at": None,
        "ended_at": None,
        "report_path": None,
        "report_jsonl": "",
        "stderr_tail": "",
        "error": None,
    }
    bg.add_task(_run_garak, task_id, req)
    return GarakScanSubmit(task_id=task_id, status="queued")


@app.get("/api/v1/tasks/{task_id}")
async def get_task(task_id: str) -> dict:
    t = _tasks.get(task_id)
    if t is None:
        raise HTTPException(404, f"task {task_id!r} not found")
    return t


# ─── Garak subprocess runner ────────────────────────────────────────


def _build_garak_argv(
    req: GarakScanRequest, report_dir: Path,
) -> list[str]:
    """Build the `python -m garak ...` argv list for `req`. We stay in
    list-form (no shell) and never interpolate user strings into a
    string template.
    """
    argv: list[str] = ["python", "-m", "garak"]

    if req.framework == "openai-compat":
        argv += ["--model_type", "openai.OpenAICompatible"]
        # garak openai-compat reads OPENAI_BASE_URL / OPENAI_API_KEY
        # from env at probe time; we set them in _run_garak.
        argv += ["--model_name", req.model_name]
    elif req.framework == "ollama":
        # garak's ollama generator is `ollama` (garak.generators.ollama) in the
        # pinned 0.15.x — `rest.OllamaGenerator` does not exist there. ollama
        # host defaults to 127.0.0.1:11434 (OLLAMA_HOST overridable).
        argv += ["--model_type", "ollama"]
        argv += ["--model_name", req.model_name]
    elif req.framework == "tgi":
        argv += ["--model_type", "huggingface.InferenceAPI"]
        argv += ["--model_name", req.model_name]
    elif req.framework == "rest":
        argv += ["--model_type", "rest.RestGenerator"]
        argv += ["--model_name", req.model_name or "rest"]
    else:  # defensive — pydantic enum already constrains
        raise ValueError(f"unknown framework {req.framework!r}")

    if req.probes == ["all"]:
        # Default garak active set (probes with active=True).
        pass
    else:
        argv += ["--probes", ",".join(req.probes)]

    argv += ["--report_prefix", str(report_dir / "report")]
    return argv


def _run_garak(task_id: str, req: GarakScanRequest) -> None:
    """Synchronous subprocess runner — invoked via FastAPI BackgroundTasks
    so the HTTP submit returns immediately while the scan continues.
    """
    t = _tasks[task_id]
    t["status"] = "running"
    t["started_at"] = datetime.now(timezone.utc).isoformat()

    with tempfile.TemporaryDirectory(prefix=f"garak-{task_id}-") as tmpdir:
        report_dir = Path(tmpdir)
        argv = _build_garak_argv(req, report_dir)

        # garak openai-compat reads OpenAI-style env. Forward base_url +
        # a placeholder API key (most self-hosted endpoints accept any
        # bearer; operators wiring real auth must set OPENAI_API_KEY at
        # the service level).
        env = os.environ.copy()
        if req.framework == "openai-compat":
            env["OPENAI_BASE_URL"] = req.target_url.rstrip("/") + "/v1"
            env.setdefault("OPENAI_API_KEY", "placeholder")
        elif req.framework == "ollama":
            env["OLLAMA_HOST"] = req.target_url.rstrip("/")
        elif req.framework == "rest" and req.rest_config:
            # Operator-supplied rest config goes to a tempfile referenced
            # by --generator_option_file. (Garak parses JSON from that.)
            cfg_path = report_dir / "rest_config.json"
            cfg_path.write_text(json.dumps(req.rest_config))
            argv += ["--generator_option_file", str(cfg_path)]

        # Record argv + env hint for debug visibility — without this the
        # operator gets "no report.jsonl produced" and zero stderr when
        # garak fast-rejects an invalid --model_type or argv flag.
        t["argv"] = argv
        t["env_hint"] = {
            "OPENAI_BASE_URL": env.get("OPENAI_BASE_URL"),
            "OLLAMA_HOST": env.get("OLLAMA_HOST"),
            "GARAK_ROOT_DIR": env.get("GARAK_ROOT_DIR"),
        }

        try:
            proc = subprocess.run(
                argv, env=env, capture_output=True,
                timeout=req.timeout_s, text=True,
            )
        except subprocess.TimeoutExpired as e:
            t["status"] = "failed"
            t["ended_at"] = datetime.now(timezone.utc).isoformat()
            t["error"] = f"timeout after {req.timeout_s}s"
            t["stderr_tail"] = (e.stderr or "")[-_REPORT_TAIL_BYTES:]
            return
        except Exception as e:
            t["status"] = "failed"
            t["ended_at"] = datetime.now(timezone.utc).isoformat()
            t["error"] = f"{type(e).__name__}: {e}"
            return

        # Capture both streams + returncode so a fast-exit garak (eg
        # invalid argv) gives the operator something to read.
        t["returncode"] = proc.returncode
        t["stdout_tail"] = (proc.stdout or "")[-_REPORT_TAIL_BYTES:]

        # Locate report.jsonl — garak writes it to ~/.local/share/garak/
        # by default. Our --report_prefix forces a path inside tmpdir,
        # but garak versions vary on whether they honor the prefix dir
        # or just the filename stem. Search both tmpdir AND garak's
        # default home in case the prefix only takes the basename.
        search_roots = [report_dir]
        garak_home = Path(env.get("HOME", "/root")) / ".local/share/garak"
        if garak_home.exists():
            search_roots.append(garak_home)
        candidates: list[Path] = []
        for root in search_roots:
            candidates.extend(root.rglob("report*.jsonl"))
        report_jsonl = ""
        report_path = None
        if candidates:
            # Pick newest by mtime — multiple runs may stack in garak_home.
            candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            report_path = str(candidates[0])
            try:
                report_jsonl = candidates[0].read_text()
            except Exception as e:
                report_jsonl = f"[failed to read report: {e}]"

        t["report_path"] = report_path
        t["report_jsonl"] = report_jsonl
        t["stderr_tail"] = (proc.stderr or "")[-_REPORT_TAIL_BYTES:]
        t["ended_at"] = datetime.now(timezone.utc).isoformat()

        if proc.returncode == 0 and report_jsonl:
            t["status"] = "completed"
        else:
            t["status"] = "failed"
            if proc.returncode != 0:
                t["error"] = f"garak exit {proc.returncode}"
            elif not report_jsonl:
                t["error"] = "no report.jsonl produced"
