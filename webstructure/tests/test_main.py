"""Tests for webstructure tool. Uses respx to mock httpx outbound calls —
no real network. Covers link discovery, form extraction, api-doc hints,
same-origin filter, depth/page caps, and a few soft-fail edge cases."""

from __future__ import annotations

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from webstructure.main import (
    WebstructureRequest,
    WebstructureResponse,
    _Crawler,
    app,
)

client = TestClient(app)


# ==============================================================
# Fixtures
# ==============================================================

INDEX_HTML = """
<!DOCTYPE html>
<html><head><title>Home</title></head>
<body>
    <a href="/login">Login</a>
    <a href="/about">About</a>
    <a href="https://external.example/other">External</a>
    <a href="mailto:admin@example.com">Mail</a>
    <form action="/search" method="GET">
        <input name="q" type="text" required>
    </form>
    <link rel="prefetch" href="/openapi.json">
</body></html>
"""

LOGIN_HTML = """
<html><head><title>Login</title></head>
<body>
    <form action="/login" method="POST">
        <input name="username" type="text" required>
        <input name="password" type="password" required>
        <input type="submit" value="Go">
    </form>
</body></html>
"""

ABOUT_HTML = "<html><head><title>About</title></head><body>About page</body></html>"


# ==============================================================
# Endpoint: /healthz + /schema
# ==============================================================


def test_healthz():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_schema_shape():
    r = client.get("/schema")
    assert r.status_code == 200
    body = r.json()
    assert body["tool_id"] == "webstructure"
    assert body["version"] == "0.1.1"
    assert "request_schema" in body
    assert "response_schema" in body


# ==============================================================
# /invoke — happy path
# ==============================================================


@pytest.mark.asyncio
@respx.mock
async def test_invoke_basic_crawl_finds_pages_and_forms():
    respx.get("https://target.example/").mock(
        return_value=httpx.Response(200, text=INDEX_HTML, headers={"content-type": "text/html"})
    )
    respx.get("https://target.example/login").mock(
        return_value=httpx.Response(200, text=LOGIN_HTML, headers={"content-type": "text/html"})
    )
    respx.get("https://target.example/about").mock(
        return_value=httpx.Response(200, text=ABOUT_HTML, headers={"content-type": "text/html"})
    )
    respx.get("https://target.example/search").mock(
        return_value=httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
    )
    respx.get("https://target.example/openapi.json").mock(
        return_value=httpx.Response(200, json={"openapi": "3.0"}, headers={"content-type": "application/json"})
    )

    r = client.post(
        "/invoke",
        json={"target_url": "https://target.example/", "max_depth": 2, "max_pages": 20, "use_playwright": False},
    )
    assert r.status_code == 200
    body = WebstructureResponse.model_validate(r.json())

    assert body.success is True
    paths = {p.path for p in body.web_pages}
    # Seed + 3 crawled links + 1 form action
    assert "/" in paths
    assert "/login" in paths
    assert "/about" in paths
    # External + mailto were filtered out
    assert not any(p.startswith("https://") for p in paths)

    # Forms: GET /search (from index) + POST /login (from login page)
    methods = sorted(f"{f.method} {f.page_path}" for f in body.forms)
    assert "GET /" in methods           # form on "/" with action=/search
    assert "POST /login" in methods     # form on /login with action=/login

    # Login form should have username + password
    login_form = next(f for f in body.forms if f.page_path == "/login")
    field_names = sorted(fld.name for fld in login_form.fields)
    assert field_names == ["password", "username"]

    # API-doc hint
    assert "/openapi.json" in body.api_hints


# ==============================================================
# same_origin_only
# ==============================================================


@pytest.mark.asyncio
@respx.mock
async def test_same_origin_only_blocks_external_fetch():
    respx.get("https://target.example/").mock(
        return_value=httpx.Response(
            200,
            text='<html><a href="https://external.example/ext">ext</a></html>',
            headers={"content-type": "text/html"},
        )
    )

    r = client.post(
        "/invoke",
        json={"target_url": "https://target.example/", "max_depth": 2, "same_origin_only": True, "use_playwright": False},
    )
    assert r.status_code == 200
    body = WebstructureResponse.model_validate(r.json())
    # Only the seed was fetched; the external link was filtered out.
    assert len(body.web_pages) == 1
    assert body.web_pages[0].path == "/"


# ==============================================================
# max_depth + max_pages caps
# ==============================================================


@pytest.mark.asyncio
@respx.mock
async def test_max_depth_zero_only_fetches_seed():
    respx.get("https://target.example/").mock(
        return_value=httpx.Response(
            200,
            text='<html><a href="/a">a</a><a href="/b">b</a></html>',
            headers={"content-type": "text/html"},
        )
    )
    r = client.post("/invoke", json={"target_url": "https://target.example/", "max_depth": 0, "use_playwright": False})
    body = WebstructureResponse.model_validate(r.json())
    assert body.pages_crawled == 1
    assert body.web_pages[0].path == "/"


@pytest.mark.asyncio
@respx.mock
async def test_max_pages_hard_cap():
    respx.get("https://target.example/").mock(
        return_value=httpx.Response(
            200,
            text='<html>'
            + "".join(f'<a href="/p{i}">p{i}</a>' for i in range(20))
            + '</html>',
            headers={"content-type": "text/html"},
        )
    )
    for i in range(20):
        respx.get(f"https://target.example/p{i}").mock(
            return_value=httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        )

    r = client.post(
        "/invoke",
        json={"target_url": "https://target.example/", "max_depth": 2, "max_pages": 5, "use_playwright": False},
    )
    body = WebstructureResponse.model_validate(r.json())
    assert body.pages_crawled == 5


# ==============================================================
# Soft-fail edge cases
# ==============================================================


def test_invoke_rejects_missing_scheme():
    r = client.post("/invoke", json={"target_url": "target.example"})
    assert r.status_code == 200  # tool returns structured error, not HTTP 4xx
    body = WebstructureResponse.model_validate(r.json())
    assert body.success is False
    assert "bad_request" in body.error


@pytest.mark.asyncio
@respx.mock
async def test_invoke_network_error_soft_fails_the_page_but_continues():
    # Seed fails; tool still returns success=true with the failed page recorded
    respx.get("https://target.example/").mock(side_effect=httpx.ConnectError("boom"))

    r = client.post("/invoke", json={"target_url": "https://target.example/", "use_playwright": False})
    body = WebstructureResponse.model_validate(r.json())
    assert body.success is True
    assert body.pages_crawled == 1
    assert body.web_pages[0].status_code == 0  # marker for failed fetch


# ==============================================================
# Link resolution unit tests
# ==============================================================


def test_resolve_to_path_strips_fragment():
    crawler = _Crawler(WebstructureRequest(target_url="https://target.example/"))
    assert crawler._resolve_to_path("/a#frag", "/") == "/a"


def test_resolve_to_path_preserves_query():
    crawler = _Crawler(WebstructureRequest(target_url="https://target.example/"))
    assert crawler._resolve_to_path("/search?q=hi", "/") == "/search?q=hi"


def test_resolve_to_path_rejects_non_fetchable():
    crawler = _Crawler(WebstructureRequest(target_url="https://target.example/"))
    for href in ("mailto:a@b", "tel:123", "javascript:void(0)", "#hash", "data:text/plain,x"):
        assert crawler._resolve_to_path(href, "/") is None


def test_resolve_to_path_handles_relative():
    crawler = _Crawler(WebstructureRequest(target_url="https://target.example/app/"))
    # from /app/, "nested" resolves to /app/nested
    assert crawler._resolve_to_path("nested", "/app/") == "/app/nested"


# ==============================================================
# Playwright fallback (browser launch fails in test env, must
# soft-fail to httpx and still return real data)
# ==============================================================


@pytest.mark.asyncio
@respx.mock
async def test_use_playwright_default_falls_back_to_httpx_when_browser_missing():
    """v0.1.1: use_playwright defaults to True. In a test env without
    Chromium installed, the browser launch raises and run() must reset
    state + retry via httpx so the caller still gets a real result.
    """
    respx.get("https://target.example/").mock(
        return_value=httpx.Response(
            200,
            text='<html><a href="/p1">p1</a></html>',
            headers={"content-type": "text/html"},
        )
    )
    respx.get("https://target.example/p1").mock(
        return_value=httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
    )

    # No use_playwright override → defaults to True. CI / local dev
    # without `playwright install chromium` triggers fallback.
    r = client.post("/invoke", json={"target_url": "https://target.example/"})
    body = WebstructureResponse.model_validate(r.json())

    # Fallback should produce a non-empty crawl, not bail out.
    assert body.success is True
    paths = {p.path for p in body.web_pages}
    assert "/" in paths
    assert "/p1" in paths


def test_request_schema_exposes_playwright_knobs():
    """The new use_playwright / wait_until / extra_wait_ms fields must
    appear in /schema so callers (like recon-targetinfo) can discover
    them programmatically."""
    schema_resp = client.get("/schema").json()
    props = schema_resp["request_schema"]["properties"]
    assert "use_playwright" in props
    assert props["use_playwright"]["default"] is True  # matches LLMAppSec
    assert "playwright_wait_until" in props
    assert "playwright_extra_wait_ms" in props
