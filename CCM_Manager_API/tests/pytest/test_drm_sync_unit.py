import pytest

from services import certification_scheme_service as service


pytestmark = pytest.mark.unit


class FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body
        self.text = str(body)

    def json(self):
        return self._body


def _export_payload():
    return {
        "scheme": {
            "id": "local-scheme",
            "name": "Local Scheme",
            "description": "Local description",
            "scheme_admin_email": "admin@example.test",
        },
        "metrics": [
            {
                "id": "local-metric",
                "name": "Metric",
                "description": "Metric description",
            }
        ],
        "controls": [
            {
                "control_id": "local-control",
                "name": "Control",
                "description": "Control description",
            }
        ],
        "risks": [
            {
                "risk_id": "local-risk",
                "risk_name": "Risk",
                "risk_details": "Risk description",
            }
        ],
        "threats": [
            {
                "threat_id": "local-threat",
                "name": "Threat",
                "description": "Threat description",
            }
        ],
        "control_metric_mappings": [
            {
                "control_id": "local-control",
                "metric_id": "local-metric",
            }
        ],
        "risk_threat_control_mappings": [
            {
                "risk_id": "local-risk",
                "threat_id": "local-threat",
                "control_id": "local-control",
            }
        ],
    }


def test_drm_api_base_defaults_to_cobalt_prefix(monkeypatch):
    monkeypatch.setenv("DRM_API_PREFIX", "/eu/cobalt")

    assert service._drm_api_base("http://drm.example.test") == "http://drm.example.test/eu/cobalt"
    assert service._drm_api_base("http://drm.example.test/eu/cobalt") == "http://drm.example.test/eu/cobalt"


def test_sync_drm_uses_pdf_resource_endpoints(monkeypatch):
    calls = []
    response_ids = {
        "/schemes": "drm-scheme",
        "/metrics": "drm-metric",
        "/controls": "drm-control",
        "/risks": "drm-risk",
        "/threats": "drm-threat",
        "/links/cm": "drm-cm-link",
        "/links/rtc": "drm-rtc-link",
    }

    def fake_export(scheme_id):
        assert scheme_id == "local-scheme"
        return _export_payload(), 200

    def fake_authed_request(method, url, **kwargs):
        assert method == "POST"
        path = url.replace("http://drm.example.test/eu/cobalt", "")
        calls.append((path, kwargs["json"]))
        return FakeResponse(201, {"id": response_ids[path]})

    monkeypatch.setenv("DRM_BASE_URL", "http://drm.example.test")
    monkeypatch.setenv("DRM_CREATOR_EMAIL", "creator@example.test")
    monkeypatch.setattr(service, "export_scheme", fake_export)
    monkeypatch.setattr(service, "authed_request", fake_authed_request)

    payload, status = service.sync_drm("local-scheme")

    assert status == 200
    assert payload["created"] == {
        "schemes": 1,
        "metrics": 1,
        "controls": 1,
        "risks": 1,
        "threats": 1,
        "control_metric_links": 1,
        "risk_threat_control_links": 1,
    }
    assert [path for path, _ in calls] == [
        "/schemes",
        "/metrics",
        "/controls",
        "/risks",
        "/threats",
        "/links/cm",
        "/links/rtc",
    ]
    assert calls[3][1]["scheme_id"] == "drm-scheme"
    assert calls[5][1] == {
        "control_id": "drm-control",
        "metric_id": "drm-metric",
    }
    assert calls[6][1] == {
        "risk_id": "drm-risk",
        "threat_id": "drm-threat",
        "control_id": "drm-control",
        "creator_email": "creator@example.test",
    }
    assert payload["remote_ids"]["scheme"] == "drm-scheme"


def test_sync_drm_synthesizes_entities_referenced_only_by_mappings(monkeypatch):
    calls = []
    export_payload = _export_payload()
    export_payload["controls"] = []

    def fake_authed_request(method, url, **kwargs):
        path = url.replace("http://drm.example.test/eu/cobalt", "")
        calls.append((path, kwargs["json"]))
        return FakeResponse(201, {"id": f"remote-{len(calls)}"})

    monkeypatch.setenv("DRM_BASE_URL", "http://drm.example.test")
    monkeypatch.setattr(service, "export_scheme", lambda scheme_id: (export_payload, 200))
    monkeypatch.setattr(service, "authed_request", fake_authed_request)

    payload, status = service.sync_drm("local-scheme")

    assert status == 200
    assert payload["created"]["controls"] == 1
    assert payload["warnings"]
    control_call = next(body for path, body in calls if path == "/controls")
    assert control_call["name"] == "local-control"


def test_sync_drm_returns_502_with_failed_drm_path(monkeypatch):
    def fake_authed_request(method, url, **kwargs):
        path = url.replace("http://drm.example.test/eu/cobalt", "")
        if path == "/metrics":
            return FakeResponse(500, {"error": "DRM exploded"})
        return FakeResponse(201, {"id": "ok"})

    monkeypatch.setenv("DRM_BASE_URL", "http://drm.example.test")
    monkeypatch.setattr(service, "export_scheme", lambda scheme_id: (_export_payload(), 200))
    monkeypatch.setattr(service, "authed_request", fake_authed_request)

    payload, status = service.sync_drm("local-scheme")

    assert status == 502
    assert payload["path"] == "/metrics"
    assert payload["drm_status"] == 500
    assert payload["created_before_failure"]["schemes"] == 1


def test_sync_drm_requires_base_url(monkeypatch):
    monkeypatch.delenv("DRM_BASE_URL", raising=False)

    payload, status = service.sync_drm("local-scheme")

    assert status == 503
    assert "DRM_BASE_URL" in payload["error"]
