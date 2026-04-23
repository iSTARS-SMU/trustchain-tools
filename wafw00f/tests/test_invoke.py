"""Unit tests for wafw00f tool. Mocks subprocess."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from httpx import ASGITransport
from pydantic import ValidationError

from src.main import Wafw00fRequest, app


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
async def test_invoke_default_args(monkeypatch):
    """Default request → wafw00f -a -f json -o - <target>."""
    jsonl = b'[{"url":"https://t.example","detected":true,"firewall":"Cloudflare","manufacturer":"Cloudflare Inc."}]'
    captured = _install_subprocess_fake(
        monkeypatch, lambda cmd: _FakeProc(stdout=jsonl, returncode=0)
    )

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "https://t.example"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert "Cloudflare" in body["stdout"]
    # -a + -f json + -o - + target
    assert captured == [
        ["wafw00f", "-a", "-f", "json", "-o", "-", "https://t.example"],
    ]


@pytest.mark.asyncio
async def test_invoke_find_all_false_omits_a(monkeypatch):
    captured = _install_subprocess_fake(
        monkeypatch, lambda cmd: _FakeProc(stdout=b"[]", returncode=0)
    )

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post(
            "/invoke", json={"target": "https://t.example", "find_all": False}
        )
    assert resp.status_code == 200
    assert captured == [["wafw00f", "-f", "json", "-o", "-", "https://t.example"]]


@pytest.mark.asyncio
async def test_invoke_no_waf_detected(monkeypatch):
    """wafw00f with no WAF hit: rc=0 with JSON saying detected=false."""
    stdout = b'[{"url":"https://t.example","detected":false,"firewall":null,"manufacturer":null}]'
    _install_subprocess_fake(
        monkeypatch, lambda cmd: _FakeProc(stdout=stdout, returncode=0)
    )
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "https://t.example"})
    body = resp.json()
    assert body["success"] is True  # tool ran fine, just nothing detected
    assert '"detected":false' in body["stdout"] or '"detected": false' in body["stdout"]


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
async def test_invoke_missing_binary(monkeypatch):
    async def boom(*cmd, stdout=None, stderr=None):
        raise FileNotFoundError("wafw00f")

    monkeypatch.setattr("src.main.asyncio.create_subprocess_exec", boom)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "https://t.example"})
    body = resp.json()
    assert body["returncode"] == 127


def test_request_model_rejects_non_url():
    for bad in [
        "target.example",
        "ftp://t.example",
        "https://t com",
        "https://t`whoami`",
        "https://t|nc evil",
    ]:
        with pytest.raises(ValidationError):
            Wafw00fRequest(target=bad)
    for ok in ["http://t.example", "https://t.example/path?q=1"]:
        Wafw00fRequest(target=ok)


@pytest.mark.asyncio
async def test_healthz():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
