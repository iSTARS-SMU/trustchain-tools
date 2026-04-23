"""Unit tests for the feroxbuster tool service.

Mocks ``asyncio.create_subprocess_exec`` so CI doesn't need the binary.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from httpx import ASGITransport
from pydantic import ValidationError

from src.main import FeroxbusterRequest, app


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


@pytest.mark.asyncio
async def test_invoke_returns_discovered_urls(monkeypatch):
    discovered = (
        b"https://target.example/admin\n"
        b"https://target.example/login\n"
        b"https://target.example/static\n"
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
    assert "/login" in body["stdout"]

    # argv: feroxbuster -u <url> --no-state -q
    assert captured == [
        ["feroxbuster", "-u", "https://target.example", "--no-state", "-q"],
    ]


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


@pytest.mark.asyncio
async def test_healthz():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
