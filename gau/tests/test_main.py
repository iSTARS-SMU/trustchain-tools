"""Tests for the gau wrapper. subprocess is mocked — we don't actually
hit Archive.org in unit tests."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from gau.main import GauResponse, app

client = TestClient(app)


def _mock_proc(stdout: bytes, returncode: int = 0, stderr: bytes = b""):
    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.wait = AsyncMock()
    proc.returncode = returncode
    return proc


SAMPLE_URLS = b"""\
https://example.com/
https://example.com/login
https://example.com/admin
https://example.com/api/v1/users
https://example.com/old-path
"""


def test_healthz():
    assert client.get("/healthz").json() == {"status": "ok"}


def test_schema_tool_id():
    assert client.get("/schema").json()["tool_id"] == "gau"


@pytest.mark.asyncio
async def test_invoke_happy_path_parses_urls():
    with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=_mock_proc(SAMPLE_URLS, 0))):
        r = client.post("/invoke", json={"target": "example.com"})

    body = GauResponse.model_validate(r.json())
    assert body.success is True
    assert len(body.urls) == 5
    assert body.total_found == 5
    assert body.truncated is False
    assert "https://example.com/admin" in body.urls


@pytest.mark.asyncio
async def test_invoke_max_urls_truncation():
    urls = b"\n".join(f"https://example.com/{i}".encode() for i in range(20))
    with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=_mock_proc(urls, 0))):
        r = client.post("/invoke", json={"target": "example.com", "max_urls": 5})

    body = GauResponse.model_validate(r.json())
    assert len(body.urls) == 5
    assert body.total_found == 20
    assert body.truncated is True


@pytest.mark.asyncio
async def test_invoke_missing_binary_soft_fails():
    with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError()):
        r = client.post("/invoke", json={"target": "example.com"})
    body = GauResponse.model_validate(r.json())
    assert body.success is False
    assert "not installed" in body.error


@pytest.mark.asyncio
async def test_invoke_timeout():
    proc = AsyncMock()
    proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
    proc.kill = lambda: None
    proc.wait = AsyncMock()
    proc.returncode = -9
    with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)):
        r = client.post("/invoke", json={"target": "example.com", "timeout_sec": 0.5})
    body = GauResponse.model_validate(r.json())
    assert body.success is False
    assert body.error == "timeout"


@pytest.mark.asyncio
async def test_invoke_skips_blank_lines():
    stdout = b"https://example.com/a\n\n\nhttps://example.com/b\n   \n"
    with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=_mock_proc(stdout, 0))):
        r = client.post("/invoke", json={"target": "example.com"})
    body = GauResponse.model_validate(r.json())
    assert body.urls == ["https://example.com/a", "https://example.com/b"]
