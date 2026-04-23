"""Unit tests for whatweb tool. Mocks subprocess — CI has no whatweb binary."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from httpx import ASGITransport
from pydantic import ValidationError

from src.main import WhatwebRequest, app


class _FakeProc:
    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self):
        return self._stdout, self._stderr

    async def wait(self):
        return self.returncode

    def kill(self):
        pass


def _install_subprocess_fake(monkeypatch, factory):
    captured = []

    async def fake_exec(*cmd, stdout=None, stderr=None):
        captured.append(list(cmd))
        return factory(list(cmd))

    monkeypatch.setattr("src.main.asyncio.create_subprocess_exec", fake_exec)
    return captured


@pytest.mark.asyncio
async def test_invoke_returns_jsonl_stdout(monkeypatch):
    """WhatWeb's --log-json=- emits one JSON per plugin hit; we pass it through."""
    jsonl = (
        b'{"target":"https://target.example","plugins":{"nginx":{"version":["1.25"]}}}\n'
        b'{"target":"https://target.example","plugins":{"HTML5":{}}}\n'
    )
    captured = _install_subprocess_fake(
        monkeypatch, lambda cmd: _FakeProc(stdout=jsonl, returncode=0)
    )

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "https://target.example"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert "nginx" in body["stdout"]
    assert "HTML5" in body["stdout"]
    assert captured == [["whatweb", "--color=never", "--log-json=-", "https://target.example"]]


@pytest.mark.asyncio
async def test_invoke_strips_ansi_color_codes(monkeypatch):
    """WhatWeb sometimes still emits ANSI escapes; we must scrub them before
    returning — otherwise downstream JSON parse on engine side chokes."""
    # Red 'nginx' + reset.
    noisy = b'\x1b[31m{"nginx":"1.25"}\x1b[0m\n'
    _install_subprocess_fake(
        monkeypatch, lambda cmd: _FakeProc(stdout=noisy, returncode=0)
    )

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "https://t.example"})

    body = resp.json()
    assert "\x1b[" not in body["stdout"]
    assert '{"nginx":"1.25"}' in body["stdout"]


@pytest.mark.asyncio
async def test_invoke_propagates_returncode(monkeypatch):
    _install_subprocess_fake(
        monkeypatch,
        lambda cmd: _FakeProc(stdout=b"", stderr=b"unreachable", returncode=1),
    )
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "https://t.example"})
    body = resp.json()
    assert body["success"] is False
    assert body["returncode"] == 1


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
            json={"target": "https://t.example", "timeout_s": 10},
        )
    body = resp.json()
    assert body["returncode"] == 124
    assert killed["flag"] is True


@pytest.mark.asyncio
async def test_invoke_missing_binary_returns_127(monkeypatch):
    async def boom(*cmd, stdout=None, stderr=None):
        raise FileNotFoundError("whatweb")

    monkeypatch.setattr("src.main.asyncio.create_subprocess_exec", boom)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "https://t.example"})
    body = resp.json()
    assert body["returncode"] == 127


def test_request_model_rejects_non_url():
    for bad in [
        "target.example",               # no scheme
        "ftp://target.example",         # wrong scheme
        "https://t com",                # space
        "https://x`whoami`",            # backtick
        "https://x|nc evil",            # pipe
    ]:
        with pytest.raises(ValidationError):
            WhatwebRequest(target=bad)

    for ok in ["http://target.example", "https://t.example/path?q=1"]:
        WhatwebRequest(target=ok)


@pytest.mark.asyncio
async def test_healthz():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
