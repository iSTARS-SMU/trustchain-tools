"""Tests for the waybackurls wrapper. subprocess mocked."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from waybackurls.main import WaybackurlsResponse, app

client = TestClient(app)


def _mock_proc(stdout: bytes, returncode: int = 0, stderr: bytes = b""):
    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.wait = AsyncMock()
    proc.returncode = returncode
    return proc


def test_healthz():
    assert client.get("/healthz").json() == {"status": "ok"}


def test_schema_tool_id():
    assert client.get("/schema").json()["tool_id"] == "waybackurls"


@pytest.mark.asyncio
async def test_invoke_happy_path():
    stdout = b"https://example.com/\nhttps://example.com/robots.txt\nhttps://example.com/archive/2019/foo\n"
    with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=_mock_proc(stdout, 0))):
        r = client.post("/invoke", json={"target": "example.com"})

    body = WaybackurlsResponse.model_validate(r.json())
    assert body.success is True
    assert body.total_found == 3
    assert "https://example.com/archive/2019/foo" in body.urls


@pytest.mark.asyncio
async def test_invoke_truncation():
    urls = b"\n".join(f"https://example.com/{i}".encode() for i in range(100))
    with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=_mock_proc(urls, 0))):
        r = client.post("/invoke", json={"target": "example.com", "max_urls": 10})

    body = WaybackurlsResponse.model_validate(r.json())
    assert len(body.urls) == 10
    assert body.total_found == 100
    assert body.truncated is True


@pytest.mark.asyncio
async def test_invoke_missing_binary_soft_fails():
    with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError()):
        r = client.post("/invoke", json={"target": "example.com"})
    body = WaybackurlsResponse.model_validate(r.json())
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
    body = WaybackurlsResponse.model_validate(r.json())
    assert body.error == "timeout"
    assert body.success is False
