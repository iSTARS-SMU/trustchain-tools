"""Tests for the whois wrapper. Uses monkeypatched subprocess — we don't
actually hit the whois registry in unit tests."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from whois.main import (
    WhoisRequest,
    WhoisResponse,
    _extract_first,
    _extract_name_servers,
    app,
    _FIELD_ALIASES,
)

client = TestClient(app)


SAMPLE_WHOIS_OUTPUT = """\
Domain Name: EXAMPLE.COM
Registrar: Example Registrar, LLC
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2026-08-13T04:00:00Z
Registrant Organization: Example Inc
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
"""


def _mock_proc(stdout: bytes, returncode: int = 0, stderr: bytes = b""):
    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.wait = AsyncMock()
    proc.returncode = returncode
    return proc


def test_healthz():
    assert client.get("/healthz").json() == {"status": "ok"}


def test_schema_shape():
    body = client.get("/schema").json()
    assert body["tool_id"] == "whois"
    assert body["version"] == "0.1.0"


# ---------- parsing helpers ----------


def test_extract_first_is_case_insensitive():
    text = "Registrar: Foo Corp\n"
    assert _extract_first(text, _FIELD_ALIASES["registrar"]) == "Foo Corp"
    text2 = "registrar: lowercase hit\n"
    assert _extract_first(text2, _FIELD_ALIASES["registrar"]) == "lowercase hit"


def test_extract_first_returns_empty_on_miss():
    assert _extract_first("no match here\n", _FIELD_ALIASES["registrar"]) == ""


def test_extract_name_servers_dedupes_and_lowercases():
    text = "Name Server: NS1.EXAMPLE.COM\nName Server: NS2.EXAMPLE.COM\nName Server: ns1.example.com\n"
    assert _extract_name_servers(text) == ["ns1.example.com", "ns2.example.com"]


# ---------- /invoke happy path ----------


@pytest.mark.asyncio
async def test_invoke_parses_structured_fields():
    with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=_mock_proc(SAMPLE_WHOIS_OUTPUT.encode(), 0))):
        r = client.post("/invoke", json={"target": "example.com"})

    body = WhoisResponse.model_validate(r.json())
    assert body.success is True
    assert body.registrar == "Example Registrar, LLC"
    assert body.creation_date == "1995-08-14T04:00:00Z"
    assert body.expiry_date == "2026-08-13T04:00:00Z"
    assert body.registrant_org == "Example Inc"
    assert body.name_servers == ["a.iana-servers.net", "b.iana-servers.net"]
    assert body.returncode == 0


@pytest.mark.asyncio
async def test_invoke_missing_binary_soft_fails():
    with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError()):
        r = client.post("/invoke", json={"target": "example.com"})
    body = WhoisResponse.model_validate(r.json())
    assert body.success is False
    assert "not installed" in body.error


@pytest.mark.asyncio
async def test_invoke_timeout_kills_process():
    proc = AsyncMock()
    proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
    proc.kill = lambda: None
    proc.wait = AsyncMock()
    proc.returncode = -9
    with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)):
        r = client.post("/invoke", json={"target": "example.com", "timeout_sec": 0.5})
    body = WhoisResponse.model_validate(r.json())
    assert body.success is False
    assert body.error == "timeout"


@pytest.mark.asyncio
async def test_invoke_nonzero_returncode_surfaces_stderr():
    with patch(
        "asyncio.create_subprocess_exec",
        new=AsyncMock(return_value=_mock_proc(b"", returncode=1, stderr=b"no whois server for tld\n")),
    ):
        r = client.post("/invoke", json={"target": "bogus.invalid"})
    body = WhoisResponse.model_validate(r.json())
    assert body.success is False
    assert "no whois server" in body.error
