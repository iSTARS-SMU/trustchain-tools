"""Smoke tests for the garak service — request validation + task lifecycle.

Don't actually run garak (heavy dep); just exercise the FastAPI surface
and the input validators. End-to-end live tests run against a real
container in pentest-engine's integration suite.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.main import GarakScanRequest, app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


class TestHealthz:
    def test_healthz(self, client):
        r = client.get("/healthz")
        assert r.status_code == 200
        body = r.json()
        assert body["service"] == "garak"
        assert body["status"] in ("healthy", "degraded")
        assert "garak_importable" in body


class TestRequestValidation:
    def test_target_url_must_be_http(self):
        with pytest.raises(ValueError, match="http"):
            GarakScanRequest(target_url="ftp://example.com")

    def test_target_url_must_have_host(self):
        with pytest.raises(ValueError, match="host"):
            GarakScanRequest(target_url="http:///path-no-host")

    def test_model_name_rejects_leading_dash(self):
        with pytest.raises(ValueError, match="disallowed"):
            GarakScanRequest(
                target_url="https://example.com",
                model_name="-evil",
            )

    def test_probes_rejects_leading_dash(self):
        with pytest.raises(ValueError, match="disallowed"):
            GarakScanRequest(
                target_url="https://example.com",
                probes=["-rm-rf"],
            )

    def test_model_name_accepts_ollama_name_tag(self):
        # ollama model ids carry a ':' (name:tag) — must be accepted.
        req = GarakScanRequest(
            target_url="http://localhost:11434",
            framework="ollama",
            model_name="qwen3.6:latest",
        )
        assert req.model_name == "qwen3.6:latest"

    def test_probes_must_be_non_empty(self):
        with pytest.raises(ValueError, match="empty"):
            GarakScanRequest(
                target_url="https://example.com",
                probes=[],
            )

    def test_extra_field_forbidden(self):
        with pytest.raises(ValueError):
            GarakScanRequest(
                target_url="https://example.com",
                wat="hi",  # type: ignore[call-arg]
            )

    def test_default_probes_is_all(self):
        req = GarakScanRequest(target_url="https://example.com")
        assert req.probes == ["all"]

    def test_default_framework(self):
        req = GarakScanRequest(target_url="https://example.com")
        assert req.framework == "openai-compat"


class TestTaskLifecycle:
    def test_unknown_task_404(self, client):
        r = client.get("/api/v1/tasks/nonexistent-uuid")
        assert r.status_code == 404


class TestArgvBuilder:
    def test_argv_openai_compat_default_probes(self, tmp_path):
        from src.main import _build_garak_argv
        req = GarakScanRequest(
            target_url="https://api.example.com",
            framework="openai-compat",
            model_name="my/model",
        )
        argv = _build_garak_argv(req, tmp_path)
        assert argv[0:3] == ["python", "-m", "garak"]
        assert "--model_type" in argv
        assert "openai.OpenAICompatible" in argv
        assert "my/model" in argv
        # 'all' default → no --probes flag
        assert "--probes" not in argv

    def test_argv_specific_probes_joined(self, tmp_path):
        from src.main import _build_garak_argv
        req = GarakScanRequest(
            target_url="https://api.example.com",
            framework="openai-compat",
            probes=["dan.Dan_11_0", "promptinject.HijackHateHumansFull"],
        )
        argv = _build_garak_argv(req, tmp_path)
        assert "--probes" in argv
        idx = argv.index("--probes")
        assert argv[idx + 1] == (
            "dan.Dan_11_0,promptinject.HijackHateHumansFull"
        )

    def test_argv_ollama_framework(self, tmp_path):
        from src.main import _build_garak_argv
        req = GarakScanRequest(
            target_url="http://localhost:8012",
            framework="ollama",
            model_name="llama2",
        )
        argv = _build_garak_argv(req, tmp_path)
        assert "ollama" in argv          # garak 0.15.x generator (not rest.OllamaGenerator)
        assert "llama2" in argv
