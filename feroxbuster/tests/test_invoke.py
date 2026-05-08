"""Unit tests for the feroxbuster tool service.

Mocks ``asyncio.create_subprocess_exec`` so CI doesn't need the binary.

Coverage:
    - argv construction (`_build_command`) — pure unit
    - `/invoke` end-to-end via ASGITransport (mocked subprocess)
    - schema validation (FeroxbusterRequest)
    - `/healthz` reflects API version + wordlist inventory
"""

from __future__ import annotations

import asyncio
import os

import httpx
import pytest
from httpx import ASGITransport
from pydantic import ValidationError

# Point the wordlist registry at the repo's bundled wordlists/ dir BEFORE
# importing src.main so the module-level lookup uses the right path.
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ["FEROXBUSTER_WORDLIST_DIR"] = os.path.join(_HERE, "wordlists")

from src.main import FeroxbusterRequest, _build_command, app  # noqa: E402


class _FakeProc:
    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr

    async def wait(self) -> int:
        return self.returncode

    def kill(self) -> None:
        pass


def _install_subprocess_fake(monkeypatch, factory):
    captured: list[list[str]] = []

    async def fake_exec(*cmd, stdout=None, stderr=None):
        captured.append(list(cmd))
        return factory(list(cmd))

    monkeypatch.setattr("src.main.asyncio.create_subprocess_exec", fake_exec)
    return captured


# ─── _build_command (pure unit) ────────────────────────────────────────
def test_build_command_default_uses_feroxbuster_default_wordlist():
    """wordlist_name='common' → no -w flag (feroxbuster's compiled-in default)."""
    cmd = _build_command(
        "https://t.example",
        wordlist_name="common", rate_limit=None, max_requests=None, max_depth=1,
    )
    assert "-w" not in cmd
    assert "feroxbuster" in cmd
    assert "-u" in cmd and "https://t.example" in cmd
    assert "--no-state" in cmd and "-q" in cmd
    assert "--depth" in cmd and "1" in cmd


def test_build_command_ai_app_wordlist_passes_w_flag():
    cmd = _build_command(
        "https://t.example",
        wordlist_name="ai-app", rate_limit=None, max_requests=None, max_depth=1,
    )
    assert "-w" in cmd
    w_idx = cmd.index("-w")
    wordlist_path = cmd[w_idx + 1]
    assert wordlist_path.endswith("/ai-app.txt")


def test_build_command_rate_limit_and_depth():
    cmd = _build_command(
        "https://t.example",
        wordlist_name="common", rate_limit=10, max_requests=None, max_depth=3,
    )
    assert "--rate-limit" in cmd
    rl_idx = cmd.index("--rate-limit")
    assert cmd[rl_idx + 1] == "10"
    d_idx = cmd.index("--depth")
    assert cmd[d_idx + 1] == "3"


def test_build_command_max_requests_with_rate_derives_time_limit():
    """max_requests=200, rate_limit=10 → --time-limit 20s."""
    cmd = _build_command(
        "https://t.example",
        wordlist_name="common", rate_limit=10, max_requests=200, max_depth=1,
    )
    assert "--time-limit" in cmd
    tl_idx = cmd.index("--time-limit")
    assert cmd[tl_idx + 1] == "20s"


def test_build_command_max_requests_without_rate_no_time_limit():
    """max_requests alone (no rate_limit) → no --time-limit; engine handles."""
    cmd = _build_command(
        "https://t.example",
        wordlist_name="common", rate_limit=None, max_requests=200, max_depth=1,
    )
    assert "--time-limit" not in cmd


def test_build_command_max_requests_ceiling():
    """ceil(7/3) = 3, not 2 — partial budget rounds UP so we don't shortchange."""
    cmd = _build_command(
        "https://t.example",
        wordlist_name="common", rate_limit=3, max_requests=7, max_depth=1,
    )
    tl_idx = cmd.index("--time-limit")
    assert cmd[tl_idx + 1] == "3s"


def test_build_command_minimum_time_limit_one_second():
    """rate_limit very high vs small max_requests must not produce 0s."""
    cmd = _build_command(
        "https://t.example",
        wordlist_name="common", rate_limit=1000, max_requests=1, max_depth=1,
    )
    tl_idx = cmd.index("--time-limit")
    assert cmd[tl_idx + 1] == "1s"


# ─── /invoke roundtrip ────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_invoke_returns_discovered_urls_default(monkeypatch):
    """Backward compat: minimal request with only `target` still works."""
    discovered = (
        b"https://target.example/admin\n"
        b"https://target.example/login\n"
    )
    captured = _install_subprocess_fake(
        monkeypatch, lambda cmd: _FakeProc(stdout=discovered, returncode=0)
    )

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "https://target.example"})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["success"] is True
    assert "/admin" in body["stdout"]
    # Reflection fields show defaults applied.
    assert body["wordlist_name"] == "common"
    assert body["max_depth"] == 1
    assert body["rate_limit"] is None
    assert body["max_requests"] is None

    # argv: feroxbuster -u <url> --no-state -q --depth 1
    assert captured == [[
        "feroxbuster", "-u", "https://target.example",
        "--no-state", "-q", "--depth", "1",
    ]]


@pytest.mark.asyncio
async def test_invoke_with_ai_app_wordlist_and_rate(monkeypatch):
    captured = _install_subprocess_fake(
        monkeypatch, lambda cmd: _FakeProc(stdout=b"", returncode=0)
    )
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={
            "target": "https://target.example",
            "wordlist_name": "ai-app",
            "rate_limit": 5,
            "max_depth": 2,
        })

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["wordlist_name"] == "ai-app"
    assert body["rate_limit"] == 5
    assert body["max_depth"] == 2
    # captured argv
    cmd = captured[0]
    assert "--rate-limit" in cmd
    assert cmd[cmd.index("--rate-limit") + 1] == "5"
    assert "-w" in cmd
    assert cmd[cmd.index("-w") + 1].endswith("/ai-app.txt")
    assert "--depth" in cmd
    assert cmd[cmd.index("--depth") + 1] == "2"


@pytest.mark.asyncio
async def test_invoke_propagates_returncode_failure(monkeypatch):
    _install_subprocess_fake(
        monkeypatch,
        lambda cmd: _FakeProc(stdout=b"", stderr=b"connection refused", returncode=2),
    )
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "https://unreachable.example"})

    body = resp.json()
    assert body["success"] is False
    assert body["returncode"] == 2
    assert "connection refused" in body["stderr"]
    # Reflection still populated even on failure.
    assert body["wordlist_name"] == "common"


@pytest.mark.asyncio
async def test_invoke_subprocess_timeout(monkeypatch):
    killed = {"flag": False}

    class _Hanger:
        returncode = None

        async def communicate(self):
            await asyncio.sleep(0)
            return b"", b""

        def kill(self):
            killed["flag"] = True
            self.returncode = -9

        async def wait(self):
            return -9

    async def fake_exec(*cmd, stdout=None, stderr=None):
        return _Hanger()

    async def fake_wait_for(coro, timeout):
        coro.close()
        raise asyncio.TimeoutError()

    monkeypatch.setattr("src.main.asyncio.create_subprocess_exec", fake_exec)
    monkeypatch.setattr("src.main.asyncio.wait_for", fake_wait_for)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post(
            "/invoke",
            json={"target": "https://target.example", "timeout_s": 10},
        )

    body = resp.json()
    assert body["success"] is False
    assert body["returncode"] == 124
    assert killed["flag"] is True


# ─── schema validation ────────────────────────────────────────────────
def test_request_model_rejects_non_url_targets():
    for bad in [
        "target.example",                # no scheme
        "ftp://target.example",          # wrong scheme
        "https://t com",                 # space in host
        "https://target.example`whoami`",# backtick (shell metachar)
        "https://target.example|nc evil",# pipe
        "javascript:alert(1)",           # wrong scheme
    ]:
        with pytest.raises(ValidationError):
            FeroxbusterRequest(target=bad)

    for ok in [
        "http://target.example",
        "https://target.example/path?q=1",
        "https://10.0.0.1:8443/",
    ]:
        FeroxbusterRequest(target=ok)


def test_request_model_rejects_unknown_wordlist():
    """Literal type guarantees only enum'd wordlists pass — defense against
    arbitrary file path injection."""
    with pytest.raises(ValidationError):
        FeroxbusterRequest(
            target="https://t.example",
            wordlist_name="../../etc/passwd",  # type: ignore[arg-type]
        )
    with pytest.raises(ValidationError):
        FeroxbusterRequest(
            target="https://t.example",
            wordlist_name="raft-large-words",  # type: ignore[arg-type]  # not in v0.2
        )


def test_request_model_rejects_extra_fields():
    """extra='forbid' → unknown fields rejected."""
    with pytest.raises(ValidationError):
        FeroxbusterRequest(
            target="https://t.example",
            shell="; rm -rf /",  # type: ignore[call-arg]
        )


def test_request_model_rate_limit_bounds():
    # ge=1, le=10000
    with pytest.raises(ValidationError):
        FeroxbusterRequest(target="https://t.example", rate_limit=0)
    with pytest.raises(ValidationError):
        FeroxbusterRequest(target="https://t.example", rate_limit=20000)
    FeroxbusterRequest(target="https://t.example", rate_limit=1)
    FeroxbusterRequest(target="https://t.example", rate_limit=10000)


def test_request_model_max_depth_bounds():
    with pytest.raises(ValidationError):
        FeroxbusterRequest(target="https://t.example", max_depth=0)
    with pytest.raises(ValidationError):
        FeroxbusterRequest(target="https://t.example", max_depth=99)


# ─── failure modes ────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_invoke_missing_binary_returns_127(monkeypatch):
    async def boom(*cmd, stdout=None, stderr=None):
        raise FileNotFoundError("feroxbuster")

    monkeypatch.setattr("src.main.asyncio.create_subprocess_exec", boom)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "https://target.example"})

    body = resp.json()
    assert body["success"] is False
    assert body["returncode"] == 127
    assert "feroxbuster binary not found" in body["stderr"]


# ─── /healthz ─────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_healthz():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["api_version"] == "0.2"
    # `common` always reports "default" (no file needed).
    assert body["wordlists"]["common"] == "default"
    # `ai-app` should be `present` because tests point at the repo's wordlists/.
    assert body["wordlists"]["ai-app"] == "present"
