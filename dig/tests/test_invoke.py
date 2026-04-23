"""Unit tests for the dig tool service. Mocks subprocess — CI has no DNS."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from httpx import ASGITransport
from pydantic import ValidationError

from src.main import DigRequest, app


class _FakeProc:
    def __init__(self, stdout: bytes = b"", returncode: int = 0):
        self._stdout = stdout
        self.returncode = returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, b""

    async def wait(self) -> int:
        return self.returncode

    def kill(self) -> None:
        pass


def _install_subprocess_fake(monkeypatch, responses: dict[str, tuple[bytes, int]]):
    """responses maps record_type → (stdout_bytes, returncode)."""
    captured: list[list[str]] = []

    async def fake_exec(*cmd, stdout=None, stderr=None):
        captured.append(list(cmd))
        # cmd is `dig +short <target> <record_type>`
        rtype = cmd[-1]
        stdout_bytes, rc = responses.get(rtype, (b"", 0))
        return _FakeProc(stdout=stdout_bytes, returncode=rc)

    monkeypatch.setattr("src.main.asyncio.create_subprocess_exec", fake_exec)
    return captured


@pytest.mark.asyncio
async def test_invoke_multiple_record_types(monkeypatch):
    captured = _install_subprocess_fake(
        monkeypatch,
        {
            "A": (b"93.184.216.34\n", 0),
            "AAAA": (b"2606:2800:220:1:248:1893:25c8:1946\n", 0),
            "MX": (b"10 mail.example.com.\n", 0),
            "NS": (b"a.iana-servers.net.\nb.iana-servers.net.\n", 0),
            "TXT": (b'"v=spf1 -all"\n', 0),
        },
    )

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post(
            "/invoke",
            json={
                "target": "example.com",
                "record_types": ["A", "AAAA", "MX", "NS", "TXT"],
            },
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["target"] == "example.com"
    assert body["success"] is True
    recs = {r["record_type"]: r["values"] for r in body["records"]}
    assert recs["A"] == ["93.184.216.34"]
    # Trailing '.' in dig output is stripped.
    assert recs["MX"] == ["10 mail.example.com"]
    assert recs["NS"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert recs["TXT"] == ['"v=spf1 -all"']

    # All 5 record-type subprocesses spawned.
    assert len(captured) == 5
    for cmd in captured:
        assert cmd[0:3] == ["dig", "+short", "example.com"]


@pytest.mark.asyncio
async def test_invoke_default_record_types(monkeypatch):
    """Request without explicit record_types uses the default set."""
    captured = _install_subprocess_fake(monkeypatch, {})
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "example.com"})
    assert resp.status_code == 200
    # Default is A/AAAA/MX/NS/TXT = 5 types.
    requested_types = {cmd[-1] for cmd in captured}
    assert requested_types == {"A", "AAAA", "MX", "NS", "TXT"}


@pytest.mark.asyncio
async def test_invoke_empty_values_still_succeeds(monkeypatch):
    """NXDOMAIN-like: dig returns rc=0 with empty stdout. Should not fail."""
    _install_subprocess_fake(monkeypatch, {"A": (b"", 0), "MX": (b"", 0)})
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post(
            "/invoke",
            json={"target": "nonexistent.example", "record_types": ["A", "MX"]},
        )
    body = resp.json()
    assert body["success"] is True
    assert all(r["values"] == [] for r in body["records"])


@pytest.mark.asyncio
async def test_invoke_all_failures_reports_unsuccess(monkeypatch):
    """If every subprocess fails (rc!=0), success=false."""
    _install_subprocess_fake(
        monkeypatch,
        {"A": (b"", 2), "MX": (b"", 2)},
    )
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post(
            "/invoke",
            json={"target": "example.com", "record_types": ["A", "MX"]},
        )
    body = resp.json()
    assert body["success"] is False


@pytest.mark.asyncio
async def test_invoke_subprocess_timeout(monkeypatch):
    """dig hangs → kill + rc=124."""
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
        resp = await ac.post("/invoke", json={"target": "example.com", "record_types": ["A"]})
    body = resp.json()
    # All record types timed out → no rc=0, success=false.
    assert body["success"] is False
    assert killed["flag"] is True


@pytest.mark.asyncio
async def test_invoke_missing_binary(monkeypatch):
    async def boom(*cmd, stdout=None, stderr=None):
        raise FileNotFoundError("dig")

    monkeypatch.setattr("src.main.asyncio.create_subprocess_exec", boom)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "example.com", "record_types": ["A"]})
    body = resp.json()
    assert body["success"] is False


@pytest.mark.asyncio
async def test_invoke_rejects_argv_injection():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"target": "-t AXFR @evil"})
    assert resp.status_code == 422


def test_request_model_validation():
    # Valid forms
    for ok in ["example.com", "sub.example.com", "a-b.example.co.uk", "target"]:
        DigRequest(target=ok)
    # Invalid forms (leading hyphen, spaces, shell metachars)
    for bad in ["-q something", "target.com;ls", "a`b`", "", "  "]:
        with pytest.raises(ValidationError):
            DigRequest(target=bad)


@pytest.mark.asyncio
async def test_healthz():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
