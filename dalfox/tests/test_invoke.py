"""Unit tests for dalfox tool. Mocks subprocess."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from httpx import ASGITransport
from pydantic import ValidationError

from src.main import DalfoxRequest, app


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
async def test_invoke_default_get(monkeypatch):
    out = b'{"type":"V","poc_type":"plain","method":"GET","data":"http://t.example/?q=<svg/onload=alert(1)>","param":"q"}'
    captured = _install_subprocess_fake(
        monkeypatch, lambda cmd: _FakeProc(stdout=out, returncode=0)
    )

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post(
            "/invoke",
            json={"target": "http://t.example/?q=test", "param": "q"},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert "alert(1)" in body["stdout"]
    cmd = captured[0]
    assert cmd[0] == "dalfox"
    assert cmd[1] == "url"
    assert cmd[2] == "http://t.example/?q=test"
    assert "--format" in cmd and "json" in cmd
    assert "--silence" in cmd
    assert "-p" in cmd and "q" in cmd
    assert "-X" not in cmd  # GET default


@pytest.mark.asyncio
async def test_invoke_post_with_data(monkeypatch):
    captured = _install_subprocess_fake(
        monkeypatch, lambda cmd: _FakeProc(stdout=b"", returncode=0)
    )

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post(
            "/invoke",
            json={
                "target": "http://t.example/comment",
                "param": "msg",
                "method": "POST",
                "data": "msg=hi",
            },
        )

    assert resp.status_code == 200
    cmd = captured[0]
    assert "-X" in cmd
    i = cmd.index("-X")
    assert cmd[i + 1] == "POST"
    assert "-d" in cmd
    j = cmd.index("-d")
    assert cmd[j + 1] == "msg=hi"


@pytest.mark.asyncio
async def test_invoke_post_without_data_returns_error(monkeypatch):
    called = []

    async def fake_exec(*cmd, stdout=None, stderr=None):
        called.append(cmd)
        return _FakeProc()

    monkeypatch.setattr("src.main.asyncio.create_subprocess_exec", fake_exec)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post(
            "/invoke",
            json={"target": "http://t.example/comment", "method": "POST"},
        )
    body = resp.json()
    assert body["returncode"] == 2
    assert called == []


@pytest.mark.asyncio
async def test_invoke_with_cookie(monkeypatch):
    captured = _install_subprocess_fake(
        monkeypatch, lambda cmd: _FakeProc(stdout=b"", returncode=0)
    )
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post(
            "/invoke",
            json={
                "target": "http://t.example/?q=t",
                "param": "q",
                "cookie": "session=abc",
            },
        )
    assert resp.status_code == 200
    cmd = captured[0]
    # dalfox uses -C for cookie (uppercase).
    assert "-C" in cmd
    i = cmd.index("-C")
    assert cmd[i + 1] == "session=abc"


@pytest.mark.asyncio
async def test_invoke_no_xss_empty_stdout(monkeypatch):
    """No XSS detected → empty stdout, rc=0, success=True."""
    _install_subprocess_fake(
        monkeypatch, lambda cmd: _FakeProc(stdout=b"", returncode=0)
    )
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "http://t.example/?q=t"})
    body = resp.json()
    assert body["success"] is True
    assert body["stdout"] == ""


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
            json={"target": "http://t.example/?q=t", "timeout_s": 30},
        )
    body = resp.json()
    assert body["returncode"] == 124
    assert killed["flag"] is True


@pytest.mark.asyncio
async def test_invoke_missing_binary(monkeypatch):
    async def boom(*cmd, stdout=None, stderr=None):
        raise FileNotFoundError("dalfox")

    monkeypatch.setattr("src.main.asyncio.create_subprocess_exec", boom)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "http://t.example/?q=t"})
    body = resp.json()
    assert body["returncode"] == 127


def test_request_model_rejects_bad_target():
    for bad in ["target.example", "ftp://t.example", "https://t com", "https://t`x`"]:
        with pytest.raises(ValidationError):
            DalfoxRequest(target=bad)


def test_request_model_rejects_bad_param():
    for bad in ["-flag", "id;rm", "id`x`", "id|x"]:
        with pytest.raises(ValidationError):
            DalfoxRequest(target="http://t.example/", param=bad)
    for ok in ["q", "search.q", "items[0]"]:
        DalfoxRequest(target="http://t.example/", param=ok)


def test_request_model_rejects_bad_cookie_or_data():
    for bad in ["-rm", "x`whoami`", "x|nc"]:
        with pytest.raises(ValidationError):
            DalfoxRequest(target="http://t.example/", cookie=bad)


@pytest.mark.asyncio
async def test_healthz():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
