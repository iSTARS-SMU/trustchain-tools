"""Unit tests for sqlmap tool. Mocks subprocess."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from httpx import ASGITransport
from pydantic import ValidationError

from src.main import SqlmapRequest, app


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
    """Default request → sqlmap GET against target with default level/risk."""
    out = b"[INFO] GET parameter 'id' is vulnerable. Type: boolean-based blind"
    captured = _install_subprocess_fake(
        monkeypatch, lambda cmd: _FakeProc(stdout=out, returncode=0)
    )

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post(
            "/invoke",
            json={"target": "http://t.example/?id=1", "param": "id"},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert "is vulnerable" in body["stdout"]
    # Verify shape: list-form invocation, no shell, includes -p id and --batch.
    cmd = captured[0]
    assert cmd[0] == "sqlmap"
    assert "-u" in cmd and "http://t.example/?id=1" in cmd
    assert "-p" in cmd and "id" in cmd
    assert "--batch" in cmd
    assert "--level" in cmd and "1" in cmd
    assert "--risk" in cmd
    # Default GET → no --method/--data flags.
    assert "--method" not in cmd
    assert "--data" not in cmd


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
                "target": "http://t.example/login",
                "param": "username",
                "method": "POST",
                "data": "username=admin&password=x",
            },
        )

    assert resp.status_code == 200
    cmd = captured[0]
    assert "--method" in cmd
    i = cmd.index("--method")
    assert cmd[i + 1] == "POST"
    assert "--data" in cmd
    j = cmd.index("--data")
    assert cmd[j + 1] == "username=admin&password=x"


@pytest.mark.asyncio
async def test_invoke_post_without_data_returns_error(monkeypatch):
    """POST without `data` should return rc=2 (input error), not run sqlmap."""
    called = []

    async def fake_exec(*cmd, stdout=None, stderr=None):
        called.append(cmd)
        return _FakeProc()

    monkeypatch.setattr("src.main.asyncio.create_subprocess_exec", fake_exec)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post(
            "/invoke",
            json={"target": "http://t.example/", "method": "POST"},
        )
    body = resp.json()
    assert body["returncode"] == 2
    assert body["success"] is False
    assert "POST requires" in body["stderr"]
    assert called == []  # subprocess never invoked


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
                "target": "http://t.example/?id=1",
                "param": "id",
                "cookie": "PHPSESSID=abc; security=low",
            },
        )
    assert resp.status_code == 200
    cmd = captured[0]
    assert "--cookie" in cmd
    i = cmd.index("--cookie")
    assert cmd[i + 1] == "PHPSESSID=abc; security=low"


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
            json={"target": "http://t.example/?id=1", "timeout_s": 30},
        )
    body = resp.json()
    assert body["returncode"] == 124
    assert killed["flag"] is True


@pytest.mark.asyncio
async def test_invoke_missing_binary(monkeypatch):
    async def boom(*cmd, stdout=None, stderr=None):
        raise FileNotFoundError("sqlmap")

    monkeypatch.setattr("src.main.asyncio.create_subprocess_exec", boom)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "http://t.example/?id=1"})
    body = resp.json()
    assert body["returncode"] == 127


def test_request_model_rejects_bad_target():
    for bad in [
        "target.example",
        "ftp://t.example",
        "https://t com",
        "https://t`whoami`",
        "https://t|nc evil",
    ]:
        with pytest.raises(ValidationError):
            SqlmapRequest(target=bad)


def test_request_model_rejects_bad_param():
    """param must not start with '-' or contain shell metacharacters."""
    for bad in ["-flag", "id;rm", "id`x`", "id|x", "id$(x)", "id with space"]:
        with pytest.raises(ValidationError):
            SqlmapRequest(target="http://t.example/", param=bad)
    for ok in ["id", "user_id", "search.q", "items[0]", "x-y"]:
        SqlmapRequest(target="http://t.example/", param=ok)


def test_request_model_rejects_bad_cookie_or_data():
    """cookie / data must not start with '-' or contain shell metacharacters."""
    for bad in ["-rm", "x`whoami`", "x|nc"]:
        with pytest.raises(ValidationError):
            SqlmapRequest(target="http://t.example/", cookie=bad)
        with pytest.raises(ValidationError):
            SqlmapRequest(
                target="http://t.example/", method="POST", data=bad,
            )


@pytest.mark.asyncio
async def test_healthz():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
