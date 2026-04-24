"""Tests for the linkfinder wrapper. subprocess mocked."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from linkfinder.main import LinkfinderResponse, app

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
    assert client.get("/schema").json()["tool_id"] == "linkfinder"


@pytest.mark.asyncio
async def test_invoke_parses_endpoints_filtering_noise():
    # LinkFinder's cli output is usually just URLs, but sometimes has banner
    # text. Our filter keeps lines with "/" or http prefix.
    stdout = (
        b"Running LinkFinder v1.0\n"
        b"/api/v1/users\n"
        b"/admin/login\n"
        b"\n"
        b"banner line without slash\n"
        b"https://assets.example/main.js\n"
    )
    with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=_mock_proc(stdout, 0))):
        r = client.post("/invoke", json={"target": "https://target.example/main.js"})

    body = LinkfinderResponse.model_validate(r.json())
    assert body.success is True
    assert "/api/v1/users" in body.endpoints
    assert "/admin/login" in body.endpoints
    assert "https://assets.example/main.js" in body.endpoints
    assert "banner line without slash" not in body.endpoints
    assert "Running LinkFinder v1.0" not in body.endpoints


@pytest.mark.asyncio
async def test_invoke_truncation():
    stdout = b"\n".join(f"/path/{i}".encode() for i in range(500))
    with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=_mock_proc(stdout, 0))):
        r = client.post("/invoke", json={"target": "https://target.example/main.js", "max_endpoints": 50})
    body = LinkfinderResponse.model_validate(r.json())
    assert len(body.endpoints) == 50
    assert body.total_found == 500
    assert body.truncated is True


@pytest.mark.asyncio
async def test_invoke_missing_linkfinder_soft_fails():
    with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError()):
        r = client.post("/invoke", json={"target": "https://target.example/main.js"})
    body = LinkfinderResponse.model_validate(r.json())
    assert body.success is False
    assert "LINKFINDER_PATH" in body.error or "not found" in body.error


@pytest.mark.asyncio
async def test_invoke_timeout():
    proc = AsyncMock()
    proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
    proc.kill = lambda: None
    proc.wait = AsyncMock()
    proc.returncode = -9
    with patch("asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)):
        r = client.post("/invoke", json={"target": "https://target.example/main.js", "timeout_sec": 0.5})
    body = LinkfinderResponse.model_validate(r.json())
    assert body.success is False
    assert body.error == "timeout"
