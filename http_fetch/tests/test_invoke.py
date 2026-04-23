"""Unit tests for the http_fetch tool service.

Uses httpx.MockTransport to substitute the upstream target — no real network.
"""

from __future__ import annotations

import httpx
import pytest
from httpx import ASGITransport
from trustchain_contracts import HttpFetchResult

from src.main import app


def _install_mock_target(handler):
    """Replace the lifespan-built httpx client with a mock-target one."""
    app.state.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_invoke_returns_structured_result():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/login"
        assert request.method == "GET"
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="<html>hi</html>",
        )

    _install_mock_target(handler)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://tool") as ac:
        resp = await ac.post(
            "/invoke",
            json={"url": "https://target.example/login"},
        )
    assert resp.status_code == 200
    body = resp.json()
    result = HttpFetchResult.model_validate(body)
    assert result.status_code == 200
    assert result.body_preview == "<html>hi</html>"
    assert result.headers["content-type"] == "text/html"
    assert result.truncated is False
    assert result.final_url == "https://target.example/login"


@pytest.mark.asyncio
async def test_invoke_truncates_oversized_body():
    """Streamed read with size cap: never buffers more than max+chunk in
    memory, even if the upstream serves a huge body. (Codex P2.)"""
    huge = "X" * (200 * 1024)  # 200 KB

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=huge)

    _install_mock_target(handler)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://tool") as ac:
        resp = await ac.post(
            "/invoke",
            json={
                "url": "https://target.example/big",
                "max_response_bytes": 64 * 1024,  # 64 KB cap
            },
        )
    body = resp.json()
    assert body["truncated"] is True
    # Preview is the inline 4 KB cap, not the full 64 KB allowance.
    assert len(body["body_preview"]) == 4 * 1024


class _CountingByteStream(httpx.AsyncByteStream):
    """Async byte stream that counts how many chunks were pulled. Used to
    prove the http_fetch service stops reading early when the size cap is
    hit, rather than reading the whole body and trimming. (Codex P2.)"""

    def __init__(self, chunks: list[bytes], counter: dict[str, int]):
        self._chunks = chunks
        self._counter = counter

    async def __aiter__(self):
        for c in self._chunks:
            self._counter["n"] += 1
            yield c

    async def aclose(self):
        return None


@pytest.mark.asyncio
async def test_invoke_streamed_read_stops_early_on_cap():
    counter = {"n": 0}
    chunk = b"X" * (16 * 1024)  # 16 KB per yield
    total_chunks = 100           # would be 1.6 MB if fully read
    body_chunks = [chunk] * total_chunks

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/octet-stream"},
            stream=_CountingByteStream(body_chunks, counter),
        )

    _install_mock_target(handler)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://tool") as ac:
        resp = await ac.post(
            "/invoke",
            json={
                "url": "https://target.example/stream",
                "max_response_bytes": 64 * 1024,  # 64 KB cap
            },
        )
    body = resp.json()
    assert body["truncated"] is True
    # MUST NOT have read all 100 chunks — the streaming cap is the whole
    # point of the fix. Allow some slack for httpx internal buffering.
    assert counter["n"] < total_chunks, (
        f"streamed read should stop early; pulled all {counter['n']} chunks"
    )


@pytest.mark.asyncio
async def test_invoke_target_unreachable_returns_502():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host", request=request)

    _install_mock_target(handler)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://tool") as ac:
        resp = await ac.post(
            "/invoke",
            json={"url": "https://unreachable.example/"},
        )
    assert resp.status_code == 502
    assert resp.json()["error"] == "TARGET_UNREACHABLE"


@pytest.mark.asyncio
async def test_healthz():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://tool") as ac:
        resp = await ac.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
