"""Unit tests for the nmap tool service.

Mocks ``asyncio.create_subprocess_exec`` so CI doesn't need the nmap binary.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest
from httpx import ASGITransport
from pydantic import ValidationError

from src.main import NmapRequest, app


# ---------- Subprocess fake ----------


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
    """`factory(cmd)` returns a _FakeProc (or raises) per call."""
    captured: list[list[str]] = []

    async def fake_exec(*cmd, stdout=None, stderr=None):
        captured.append(list(cmd))
        return factory(list(cmd))

    monkeypatch.setattr("src.main.asyncio.create_subprocess_exec", fake_exec)
    return captured


# ---------- Tests ----------


@pytest.mark.asyncio
async def test_invoke_basic_mode(monkeypatch):
    captured = _install_subprocess_fake(
        monkeypatch,
        lambda cmd: _FakeProc(stdout=b"22/tcp open  ssh\n", returncode=0),
    )

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post(
            "/invoke",
            json={"target": "scanme.nmap.org", "mode": "basic"},
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["target"] == "scanme.nmap.org"
    assert body["mode"] == "basic"
    assert body["success"] is True
    assert len(body["scans"]) == 1
    scan = body["scans"][0]
    assert scan["name"] == "basic"
    assert scan["returncode"] == 0
    assert "22/tcp" in scan["stdout"]

    # Argv shape: nmap + flags, target last.
    assert captured == [
        ["nmap", "-Pn", "-T4", "-sV", "-sC", "scanme.nmap.org"],
    ]


@pytest.mark.asyncio
async def test_invoke_comprehensive_runs_three_scans(monkeypatch):
    captured = _install_subprocess_fake(
        monkeypatch,
        lambda cmd: _FakeProc(stdout=f"ran {cmd[1]}".encode(), returncode=0),
    )

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post(
            "/invoke",
            json={"target": "10.0.0.1", "mode": "comprehensive", "timeout_s": 60},
        )

    body = resp.json()
    assert body["success"] is True
    names = [s["name"] for s in body["scans"]]
    assert names == ["full_port_scan", "nse_basic", "web_enum"]
    assert len(captured) == 3
    # All three argv lists carry the target.
    for cmd in captured:
        assert cmd[0] == "nmap"
        assert "10.0.0.1" in cmd


@pytest.mark.asyncio
async def test_invoke_propagates_returncode_failure(monkeypatch):
    _install_subprocess_fake(
        monkeypatch,
        lambda cmd: _FakeProc(stdout=b"", stderr=b"unresolved", returncode=1),
    )

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "host.invalid"})

    body = resp.json()
    assert body["success"] is False
    assert body["scans"][0]["returncode"] == 1
    assert "unresolved" in body["scans"][0]["stderr"]


@pytest.mark.asyncio
async def test_invoke_subprocess_timeout(monkeypatch):
    """If the nmap process exceeds the budget, we kill it and return rc=124.

    We mock both create_subprocess_exec AND asyncio.wait_for so the test
    exits immediately rather than actually waiting for a 10s timeout.
    """

    killed = {"flag": False}

    class _Hanger:
        returncode = None

        async def communicate(self):
            # Never actually awaited — fake_wait_for closes the coroutine
            # before yielding control. Return value is irrelevant.
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
        # Cancel the coroutine to clean it up, then raise TimeoutError.
        coro.close()
        raise asyncio.TimeoutError()

    monkeypatch.setattr("src.main.asyncio.create_subprocess_exec", fake_exec)
    monkeypatch.setattr("src.main.asyncio.wait_for", fake_wait_for)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post(
            "/invoke",
            json={"target": "scanme.nmap.org", "timeout_s": 10},
        )

    body = resp.json()
    assert body["success"] is False
    assert body["scans"][0]["returncode"] == 124  # GNU `timeout` convention
    assert "timeout" in body["scans"][0]["stderr"].lower()
    assert killed["flag"] is True


@pytest.mark.asyncio
async def test_invoke_rejects_argument_injection_target():
    """A target like '-script-args=...' would otherwise be passed to argv as
    a flag. We reject at the model layer so it never reaches subprocess."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post(
            "/invoke",
            json={"target": "-sV --script=evil"},
        )
    assert resp.status_code == 422  # FastAPI validation
    assert "argument injection" in resp.text or "disallowed" in resp.text


def test_request_model_rejects_shell_metachars():
    for bad in ["target.com; rm -rf /", "host && curl evil", "host`whoami`"]:
        with pytest.raises(ValidationError):
            NmapRequest(target=bad)

    # Sanity: well-formed values pass.
    for ok in ["scanme.nmap.org", "10.0.0.1", "10.0.0.0/24", "[::1]"]:
        NmapRequest(target=ok)


@pytest.mark.asyncio
async def test_invoke_missing_binary_returns_127(monkeypatch):
    async def boom(*cmd, stdout=None, stderr=None):
        raise FileNotFoundError("nmap")

    monkeypatch.setattr("src.main.asyncio.create_subprocess_exec", boom)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "scanme.nmap.org"})

    body = resp.json()
    assert body["success"] is False
    assert body["scans"][0]["returncode"] == 127
    assert "nmap binary not found" in body["scans"][0]["stderr"]


@pytest.mark.asyncio
async def test_healthz():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    # `nmap` field is either the binary path or "missing"; either is valid.
    assert "nmap" in body
