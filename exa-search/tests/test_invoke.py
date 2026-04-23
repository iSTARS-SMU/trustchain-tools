"""Unit tests for the exa-search tool.

Mocks the upstream Exa API via httpx.MockTransport — no real network.
"""

from __future__ import annotations

import httpx
import pytest
from httpx import ASGITransport
from pydantic import ValidationError

from src.main import EXA_ENV_KEY, ExaSearchRequest, app


def _install_mock_exa(handler):
    """Swap the lifespan-built httpx.AsyncClient for one that hits a
    MockTransport-backed fake Exa. Also sets a fake EXA_API_KEY on app.state."""
    app.state.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app.state.exa_key = "fake-exa-key"


# ---------- happy path ----------


@pytest.mark.asyncio
async def test_invoke_returns_results_on_success():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["method"] = request.method
        captured["auth"] = request.headers.get("authorization", "")
        import json
        captured["body"] = json.loads(request.content.decode() or "{}")
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "title": "CVE-2024-X — Django path traversal",
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-X",
                        "text": "A path traversal in Django 4.2 allows ...",
                        "score": 0.94,
                        "publishedDate": "2024-07-15T00:00:00Z",
                    },
                    {"title": "Stack Overflow discussion", "url": "https://stackoverflow.com/q/12345"},
                ]
            },
        )

    _install_mock_exa(handler)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post(
            "/invoke",
            json={"query": "Django 4.2 CVE", "num_results": 5, "search_type": "auto"},
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["success"] is True
    assert body["query"] == "Django 4.2 CVE"
    assert body["num_results_returned"] == 2
    assert body["results"][0]["url"].startswith("https://nvd.nist.gov/")

    # Verify the outbound Exa request shape.
    assert captured["method"] == "POST"
    assert captured["url"] == "https://api.exa.ai/search"
    assert captured["auth"] == "Bearer fake-exa-key"
    assert captured["body"]["query"] == "Django 4.2 CVE"
    assert captured["body"]["numResults"] == 5
    assert captured["body"]["type"] == "auto"


@pytest.mark.asyncio
async def test_invoke_passes_domain_filters():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json
        captured["body"] = json.loads(request.content.decode())
        return httpx.Response(200, json={"results": []})

    _install_mock_exa(handler)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post(
            "/invoke",
            json={
                "query": "CVE Django",
                "include_domains": ["nvd.nist.gov", "cve.mitre.org"],
                "exclude_domains": ["reddit.com"],
            },
        )

    assert resp.status_code == 200
    assert captured["body"]["includeDomains"] == ["nvd.nist.gov", "cve.mitre.org"]
    assert captured["body"]["excludeDomains"] == ["reddit.com"]


# ---------- failure paths (all soft-fail as success=false) ----------


@pytest.mark.asyncio
async def test_invoke_rate_limit_soft_fails():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="Too Many Requests")

    _install_mock_exa(handler)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"query": "anything"})

    assert resp.status_code == 200  # tool returns a structured result, not a 4xx
    body = resp.json()
    assert body["success"] is False
    assert "rate limit" in body["error"].lower()
    assert body["results"] == []


@pytest.mark.asyncio
async def test_invoke_auth_failure_soft_fails():
    """401 / 403 from Exa → structured soft-fail so engine's call_tool
    loop sees success=false + error, not a 500."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text='{"error":"invalid api key"}')

    _install_mock_exa(handler)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"query": "anything"})

    body = resp.json()
    assert body["success"] is False
    assert "auth failed" in body["error"]
    assert "EXA_API_KEY" in body["error"]


@pytest.mark.asyncio
async def test_invoke_timeout_soft_fails():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("too slow", request=request)

    _install_mock_exa(handler)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"query": "q", "timeout_s": 10})

    body = resp.json()
    assert body["success"] is False
    assert "timeout" in body["error"].lower()


@pytest.mark.asyncio
async def test_invoke_transport_error_soft_fails():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    _install_mock_exa(handler)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"query": "q"})

    body = resp.json()
    assert body["success"] is False
    assert "transport" in body["error"].lower()


@pytest.mark.asyncio
async def test_invoke_non_json_response_soft_fails():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>server error</html>")

    _install_mock_exa(handler)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"query": "q"})

    body = resp.json()
    assert body["success"] is False
    assert "non-JSON" in body["error"] or "non-json" in body["error"].lower()


@pytest.mark.asyncio
async def test_invoke_without_api_key_configured():
    """No EXA_API_KEY in env → /invoke returns success=false immediately,
    never touches the network. Lets operators bring up the stack before
    filling the key."""
    app.state.client = httpx.AsyncClient()  # not used
    app.state.exa_key = ""  # explicitly empty

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"query": "anything"})

    body = resp.json()
    assert body["success"] is False
    assert body["error"] == f"{EXA_ENV_KEY} not configured on exa-search-svc container"
    assert body["duration_ms"] == 0  # no network round-trip


# ---------- request validation ----------


def test_request_model_rejects_empty_query():
    with pytest.raises(ValidationError):
        ExaSearchRequest(query="")


def test_request_model_rejects_overlong_query():
    with pytest.raises(ValidationError):
        ExaSearchRequest(query="X" * 2001)


def test_request_model_rejects_out_of_range_num_results():
    with pytest.raises(ValidationError):
        ExaSearchRequest(query="q", num_results=0)
    with pytest.raises(ValidationError):
        ExaSearchRequest(query="q", num_results=51)


def test_request_model_rejects_bad_search_type():
    with pytest.raises(ValidationError):
        ExaSearchRequest(query="q", search_type="invalid")


def test_request_model_rejects_extra_fields():
    # extra='forbid' on the model catches stray fields (protect against
    # engines passing typos that would silently no-op at Exa).
    with pytest.raises(ValidationError):
        ExaSearchRequest(query="q", numResults=10)  # wrong casing


# ---------- healthz ----------


@pytest.mark.asyncio
async def test_healthz_reports_key_configured():
    app.state.exa_key = "some-key"
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["exa_key_configured"] is True


@pytest.mark.asyncio
async def test_healthz_reports_key_missing(monkeypatch):
    """With neither app.state.exa_key NOR EXA_API_KEY in env, key_configured=False."""
    app.state.exa_key = ""
    monkeypatch.delenv(EXA_ENV_KEY, raising=False)
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.get("/healthz")
    body = resp.json()
    assert body["status"] == "ok"  # service healthy even without key
    assert body["exa_key_configured"] is False
