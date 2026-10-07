"""Unit tests for the gadget tool service.

The high-value test actually DESERIALIZES the built pickle gadget
against a throwaway local HTTP listener and asserts the callback fires
— proving the gadget does what we claim (HTTP GET on deserialize),
not just that bytes come back.
"""
from __future__ import annotations

import base64
import http.server
import pickle
import threading
import urllib.request

import httpx
import pytest
from httpx import ASGITransport
from pydantic import ValidationError

from src.main import GadgetRequest, app, build_gadget


# ──────────────────────────────────────────────────────────────────
# Request validation
# ──────────────────────────────────────────────────────────────────

def test_bad_callback_url_rejected():
    with pytest.raises(ValidationError):
        GadgetRequest(callback_url="not a url")


def test_framework_normalized_lowercase():
    assert GadgetRequest(callback_url="http://x.local/cb", framework="PYTHON").framework == "python"


# ──────────────────────────────────────────────────────────────────
# build_gadget contract
# ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("fw", ["auto", "python", "pickle", "flask", "django"])
def test_pickle_frameworks_build_a_gadget(fw):
    r = build_gadget(GadgetRequest(callback_url="http://host.docker.internal:9290/cb", framework=fw))
    assert r.supported is True
    assert r.variant == "python-pickle"
    assert r.gadget_b64
    # round-trips as valid base64
    base64.b64decode(r.gadget_b64)


@pytest.mark.parametrize("fw", ["java", "php", "ruby", "dotnet", "node"])
def test_unsupported_frameworks_return_reason(fw):
    r = build_gadget(GadgetRequest(callback_url="http://x.local/cb", framework=fw))
    assert r.supported is False
    assert r.gadget_b64 is None
    assert r.reason


# ──────────────────────────────────────────────────────────────────
# The gadget actually beacons on deserialize
# ──────────────────────────────────────────────────────────────────

def test_pickle_gadget_beacons_on_deserialize():
    hits: list[str] = []

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            hits.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):  # silence
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.handle_request, daemon=True)
    t.start()
    try:
        callback = f"http://127.0.0.1:{port}/oob/cid-test"
        r = build_gadget(GadgetRequest(callback_url=callback, framework="python"))
        gadget = pickle.loads(base64.b64decode(r.gadget_b64))  # noqa: S301 — the whole point
        # urlopen returns a response object; drain it
        try:
            gadget.read()
        except Exception:
            pass
    finally:
        t.join(timeout=3)
        srv.server_close()

    assert hits == ["/oob/cid-test"], f"expected 1 beacon to the callback path, got {hits}"


# ──────────────────────────────────────────────────────────────────
# HTTP endpoints
# ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_invoke_endpoint_builds_pickle():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        resp = await c.post("/invoke", json={
            "framework": "auto",
            "callback_url": "http://host.docker.internal:9290/cb",
            "callback_type": "http",
        })
    assert resp.status_code == 200
    body = resp.json()
    assert body["supported"] is True and body["variant"] == "python-pickle"
    assert body["gadget_b64"]


@pytest.mark.asyncio
async def test_invoke_endpoint_unsupported_callback_type_rejected():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        resp = await c.post("/invoke", json={
            "framework": "auto",
            "callback_url": "http://x.local/cb",
            "callback_type": "dns",
        })
    # callback_type is a Literal["http"] → 422 at validation
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_healthz():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        resp = await c.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
