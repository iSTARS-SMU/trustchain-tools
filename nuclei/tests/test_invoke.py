"""Unit tests for the nuclei tool service.

Mocks ``asyncio.create_subprocess_exec`` so CI doesn't need the nuclei binary.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from httpx import ASGITransport
from pydantic import ValidationError

from src.main import NucleiRequest, app


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
async def test_invoke_returns_jsonl_stdout(monkeypatch):
    jsonl = (
        b'{"template-id":"http-missing-security-headers","info":{"severity":"info"},"matched-at":"https://target.example/"}\n'
        b'{"template-id":"weak-cipher","info":{"severity":"medium"},"matched-at":"https://target.example/"}\n'
    )
    captured = _install_subprocess_fake(
        monkeypatch, lambda cmd: _FakeProc(stdout=jsonl, returncode=0)
    )

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "https://target.example"})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["success"] is True
    assert body["returncode"] == 0
    assert body["target"] == "https://target.example"
    assert "http-missing-security-headers" in body["stdout"]
    assert "weak-cipher" in body["stdout"]

    # argv: nuclei -u <url> -jsonl -silent
    assert captured == [
        ["nuclei", "-u", "https://target.example", "-jsonl", "-silent"],
    ]


@pytest.mark.asyncio
async def test_invoke_propagates_returncode_failure(monkeypatch):
    _install_subprocess_fake(
        monkeypatch,
        lambda cmd: _FakeProc(stdout=b"", stderr=b"could not connect", returncode=1),
    )

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "https://unreachable.example"})

    body = resp.json()
    assert body["success"] is False
    assert body["returncode"] == 1
    assert "could not connect" in body["stderr"]


@pytest.mark.asyncio
async def test_invoke_subprocess_timeout(monkeypatch):
    """Mock both create_subprocess_exec and asyncio.wait_for to fire a
    TimeoutError immediately so the test exits in <1s rather than waiting
    for a real 10s budget."""
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


@pytest.mark.asyncio
async def test_invoke_rejects_argument_injection_target():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        # Looks like a URL but contains a space → fails regex.
        resp = await ac.post(
            "/invoke",
            json={"target": "https://target.example -severity=critical"},
        )
    assert resp.status_code == 422
    assert "well-formed" in resp.text or "disallowed" in resp.text


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
            NucleiRequest(target=bad)

    for ok in [
        "http://target.example",
        "https://target.example/path?q=1",
        "https://10.0.0.1:8443/admin",
        "https://[::1]:8443/x",
    ]:
        NucleiRequest(target=ok)


@pytest.mark.asyncio
async def test_invoke_missing_binary_returns_127(monkeypatch):
    async def boom(*cmd, stdout=None, stderr=None):
        raise FileNotFoundError("nuclei")

    monkeypatch.setattr("src.main.asyncio.create_subprocess_exec", boom)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "https://target.example"})

    body = resp.json()
    assert body["success"] is False
    assert body["returncode"] == 127
    assert "nuclei binary not found" in body["stderr"]


@pytest.mark.asyncio
async def test_healthz():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
