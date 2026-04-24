"""Unit tests for nvd-search. Mocks NVD via httpx.MockTransport — no real network."""

from __future__ import annotations

import httpx
import pytest
from httpx import ASGITransport
from pydantic import ValidationError

from nvd_search.main import NVD_ENV_KEY, NVDSearchRequest, app


def _install_mock_nvd(handler):
    """Swap the lifespan-built httpx.AsyncClient with a MockTransport-backed
    one. Also sets a fake NVD_API_KEY so the auth branch runs."""
    app.state.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    app.state.nvd_key = "fake-nvd-key"


# ---------- happy paths ----------


@pytest.mark.asyncio
async def test_invoke_returns_results_for_cpe_lookup():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["method"] = request.method
        captured["key"] = request.headers.get("apikey", "")
        return httpx.Response(
            200,
            json={
                "totalResults": 2,
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-12345",
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "cvssData": {
                                            "baseScore": 7.5,
                                            "baseSeverity": "HIGH",
                                        }
                                    }
                                ]
                            },
                        }
                    },
                    {"cve": {"id": "CVE-2024-12346"}},
                ],
            },
        )

    _install_mock_nvd(handler)
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post(
            "/invoke",
            json={
                "cpe_name": "cpe:2.3:a:django:django:4.2.0:*:*:*:*:*:*:*",
                "cvss_v3_severity": "HIGH",
                "results_per_page": 20,
            },
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["success"] is True
    assert body["total_results"] == 2
    assert len(body["vulnerabilities"]) == 2
    assert body["vulnerabilities"][0]["cve"]["id"] == "CVE-2024-12345"

    # Verify outbound shape.
    assert captured["method"] == "GET"
    assert "services.nvd.nist.gov/rest/json/cves/2.0" in captured["url"]
    assert "cpeName=cpe" in captured["url"]
    assert "cvssV3Severity=HIGH" in captured["url"]
    assert captured["key"] == "fake-nvd-key"


@pytest.mark.asyncio
async def test_invoke_keyword_search():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})

    _install_mock_nvd(handler)
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post(
            "/invoke", json={"keyword_search": "log4j jndi lookup"}
        )

    assert resp.status_code == 200
    assert "keywordSearch=log4j" in captured["url"]


@pytest.mark.asyncio
async def test_invoke_date_filters():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})

    _install_mock_nvd(handler)
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post(
            "/invoke",
            json={
                "keyword_search": "xss",
                "pub_start_date": "2024-01-01T00:00:00.000",
                "pub_end_date": "2024-12-31T23:59:59.999",
            },
        )

    assert resp.status_code == 200
    assert "pubStartDate=2024-01-01" in captured["url"]
    assert "pubEndDate=2024-12-31" in captured["url"]


@pytest.mark.asyncio
async def test_invoke_cve_id_exact_lookup():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "totalResults": 1,
                "vulnerabilities": [{"cve": {"id": "CVE-2024-99999"}}],
            },
        )

    _install_mock_nvd(handler)
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"cve_id": "CVE-2024-99999"})
    body = resp.json()
    assert body["success"] is True
    assert body["vulnerabilities"][0]["cve"]["id"] == "CVE-2024-99999"


# ---------- special status: 404 on unknown cveId = empty (not error) ----------


@pytest.mark.asyncio
async def test_invoke_unknown_cve_returns_empty_success():
    """NVD returns 404 when a specific cveId is unknown. The tool treats
    this as an empty result (success=True, vulnerabilities=[]), not a
    failure — engines iterating a list of CVE IDs shouldn't get spammed
    with errors for unknowns."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="Not found")

    _install_mock_nvd(handler)
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"cve_id": "CVE-9999-00001"})
    body = resp.json()
    assert body["success"] is True
    assert body["vulnerabilities"] == []
    assert body["total_results"] == 0


# ---------- soft-fail paths ----------


@pytest.mark.asyncio
async def test_invoke_rate_limit_soft_fails_with_hint():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="Too Many Requests")

    _install_mock_nvd(handler)
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"keyword_search": "anything"})
    body = resp.json()
    assert body["success"] is False
    assert "rate limit" in body["error"].lower()


@pytest.mark.asyncio
async def test_invoke_rate_limit_no_key_suggests_setting_one():
    """Different hint when NVD_API_KEY is not configured — tells operator
    to set one to 10× the cap."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="Too Many Requests")

    _install_mock_nvd(handler)
    app.state.nvd_key = ""   # simulate no key

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"keyword_search": "anything"})
    body = resp.json()
    assert body["success"] is False
    assert "NVD_API_KEY" in body["error"]


@pytest.mark.asyncio
async def test_invoke_auth_failure_soft_fails():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="bad api key")

    _install_mock_nvd(handler)
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"keyword_search": "x"})
    body = resp.json()
    assert body["success"] is False
    assert "auth failed" in body["error"]
    assert NVD_ENV_KEY in body["error"]


@pytest.mark.asyncio
async def test_invoke_timeout_soft_fails():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("slow", request=request)

    _install_mock_nvd(handler)
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"keyword_search": "x", "timeout_s": 5})
    body = resp.json()
    assert body["success"] is False
    assert "timeout" in body["error"].lower()


@pytest.mark.asyncio
async def test_invoke_transport_error_soft_fails():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    _install_mock_nvd(handler)
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"keyword_search": "x"})
    body = resp.json()
    assert body["success"] is False
    assert "transport" in body["error"].lower()


@pytest.mark.asyncio
async def test_invoke_non_json_response_soft_fails():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>NVD server error</html>")

    _install_mock_nvd(handler)
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"keyword_search": "x"})
    body = resp.json()
    assert body["success"] is False
    assert "non-JSON" in body["error"] or "non-json" in body["error"].lower()


@pytest.mark.asyncio
async def test_invoke_server_error_soft_fails():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="upstream down")

    _install_mock_nvd(handler)
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"keyword_search": "x"})
    body = resp.json()
    assert body["success"] is False
    assert "server error" in body["error"].lower()


# ---------- no filter rejection ----------


@pytest.mark.asyncio
async def test_invoke_refuses_unfiltered_query():
    """NVD refuses unfiltered queries (would return millions of CVEs);
    we reject before even making the call so engines don't accidentally
    trigger it with an empty-payload bug."""
    _install_mock_nvd(lambda r: httpx.Response(200, json={"totalResults": 99999999}))
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.post("/invoke", json={"results_per_page": 20})
    body = resp.json()
    assert body["success"] is False
    assert "cpe_name" in body["error"]
    assert "keyword_search" in body["error"]
    assert "cve_id" in body["error"]


# ---------- request validation ----------


def test_request_rejects_invalid_cve_id():
    with pytest.raises(ValidationError):
        NVDSearchRequest(cve_id="not-a-cve")


def test_request_rejects_invalid_severity():
    with pytest.raises(ValidationError):
        NVDSearchRequest(cpe_name="x", cvss_v3_severity="OOPS")


def test_request_rejects_results_per_page_out_of_range():
    with pytest.raises(ValidationError):
        NVDSearchRequest(cpe_name="x", results_per_page=0)
    with pytest.raises(ValidationError):
        NVDSearchRequest(cpe_name="x", results_per_page=2001)


def test_request_rejects_extra_fields():
    with pytest.raises(ValidationError):
        NVDSearchRequest(cpe_name="x", cpeName="typo-camelcase")


# ---------- healthz ----------


@pytest.mark.asyncio
async def test_healthz_reports_key_configured():
    app.state.nvd_key = "some-key"
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.get("/healthz")
    body = resp.json()
    assert body["status"] == "ok"
    assert body["nvd_api_key_configured"] is True


@pytest.mark.asyncio
async def test_healthz_reports_key_missing(monkeypatch):
    app.state.nvd_key = ""
    monkeypatch.delenv(NVD_ENV_KEY, raising=False)
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        resp = await ac.get("/healthz")
    body = resp.json()
    assert body["status"] == "ok"
    assert body["nvd_api_key_configured"] is False
