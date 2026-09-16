import json
from types import SimpleNamespace

import pytest
import requests
from flask import g

import app
from services import certification_scheme_service
from services import ledger
from services import mqtt_alert_service as alerts


pytestmark = pytest.mark.unit


class FakePublisher:
    def __init__(self, error=None):
        self.calls = []
        self.error = error

    def single(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error


class FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body
        self.text = str(body)

    def json(self):
        return self._body


def _enable_alerts(monkeypatch, publisher=None):
    publisher = publisher or FakePublisher()
    monkeypatch.setattr(alerts, "MQTT_ALERTS_ENABLED", True)
    monkeypatch.setattr(alerts, "MQTT_ALERT_TOPIC", "components/CCM-Manager/reports")
    monkeypatch.setattr(alerts, "MQTT_BROKER_HOST", "10.163.1.161")
    monkeypatch.setattr(alerts, "MQTT_BROKER_PORT", 1883)
    monkeypatch.setattr(alerts, "MQTT_QOS", 1)
    monkeypatch.setattr(alerts, "MQTT_RETAIN", False)
    monkeypatch.setattr(alerts, "MQTT_USERNAME", "")
    monkeypatch.setattr(alerts, "MQTT_TLS_ENABLED", False)
    monkeypatch.setattr(alerts, "publish", publisher)
    monkeypatch.setattr(alerts, "mqtt", SimpleNamespace(MQTTv311=4))
    return publisher


def test_publish_failure_uses_required_contract_and_redacts_details(monkeypatch):
    publisher = _enable_alerts(monkeypatch)

    with app.app.test_request_context(
        "/upload_certification_scheme", method="POST"
    ):
        g.request_id = "request-123"
        result = alerts.publish_failure(
            operation="Publish certification scheme to blockchain",
            message="Processor timeout",
            details={
                "service": "ledger",
                "scheme_id": "scheme-42",
                "attempt": 3,
                "access_token": "must-not-leak",
                "error": "request failed: password=hunter2",
            },
            event_id="failure-42",
        )

    assert result == {"status": "published", "event_id": "failure-42"}
    assert len(publisher.calls) == 1
    call = publisher.calls[0]
    assert call["topic"] == "components/CCM-Manager/reports"
    assert call["hostname"] == "10.163.1.161"
    assert call["port"] == 1883
    assert call["qos"] == 1
    assert call["retain"] is False
    assert call["protocol"] == 4

    payload = json.loads(call["payload"])
    assert payload["event_id"] == "failure-42"
    assert payload["state"] == "failed"
    assert payload["severity"] == "critical"
    assert payload["component"] == "ledger"
    assert payload["operation"] == "Publish certification scheme to blockchain"
    assert payload["message"] == "Processor timeout"
    assert payload["occurred_at"].endswith("+00:00")
    assert payload["details"] == {
        "request_id": "request-123",
        "method": "POST",
        "path": "/upload_certification_scheme",
        "service": "ledger",
        "scheme_id": "scheme-42",
        "attempt": 3,
        "access_token": "[REDACTED]",
        "error": "request failed: password=[REDACTED]",
    }


def test_disabled_alerts_do_not_contact_publisher(monkeypatch):
    publisher = FakePublisher()
    monkeypatch.setattr(alerts, "MQTT_ALERTS_ENABLED", False)
    monkeypatch.setattr(alerts, "publish", publisher)

    assert alerts.publish_failure("Test operation", "Test failure") == {
        "status": "disabled"
    }
    assert publisher.calls == []


def test_internal_failure_uses_ccm_manager_as_component(monkeypatch):
    monkeypatch.setattr(alerts, "MQTT_COMPONENT_ID", "CCM-Manager")

    payload = alerts.build_failure_payload(
        "Generate certificate PDF",
        "Failed to regenerate the certificate PDF",
        details={"certificate_id": "certificate-42"},
    )

    assert payload["component"] == "CCM-Manager"


def test_explicit_component_overrides_details_service(monkeypatch):
    monkeypatch.setattr(alerts, "MQTT_COMPONENT_ID", "CCM-Manager")

    payload = alerts.build_failure_payload(
        "Publish certification scheme",
        "Publication failed",
        details={"service": "ledger"},
        component="Blockchain-Ledger",
    )

    assert payload["component"] == "Blockchain-Ledger"


def test_broker_failure_never_raises_into_business_operation(monkeypatch):
    publisher = _enable_alerts(monkeypatch, FakePublisher(OSError("broker offline")))

    result = alerts.publish_failure("Test operation", "Original failure")

    assert result["status"] == "failed"
    assert result["error"] == "broker offline"
    assert len(publisher.calls) == 1


def test_oversized_response_is_removed_but_identifiers_are_retained(monkeypatch):
    monkeypatch.setattr(alerts, "MQTT_DETAILS_MAX_CHARS", 256)

    payload = alerts.build_failure_payload(
        "Synchronize certification scheme to DRM",
        "DRM rejected the request",
        details={
            "scheme_id": "scheme-42",
            "status_code": 500,
            "response": {"debug": "x" * 2000},
        },
    )

    assert payload["details"] == {
        "scheme_id": "scheme-42",
        "status_code": 500,
        "details_truncated": True,
    }


def test_background_failure_is_deduplicated_until_cleared(monkeypatch):
    publisher = _enable_alerts(monkeypatch)
    key = "toe-handoff:dedupe-test"
    alerts.clear_failure(key)

    first = alerts.publish_failure("Handoff ToE ID", "offline", dedupe_key=key)
    second = alerts.publish_failure("Handoff ToE ID", "offline", dedupe_key=key)
    alerts.clear_failure(key)
    third = alerts.publish_failure("Handoff ToE ID", "offline", dedupe_key=key)
    alerts.clear_failure(key)

    assert first["status"] == "published"
    assert second["status"] == "duplicate"
    assert third["status"] == "published"
    assert len(publisher.calls) == 2


def test_generic_http_alert_only_for_unhandled_5xx(monkeypatch):
    calls = []
    monkeypatch.setattr(app, "publish_failure", lambda *args, **kwargs: calls.append((args, kwargs)))

    with app.app.test_request_context("/test", method="GET"):
        g.request_id = "request-500"
        response = app.app.response_class(
            response=json.dumps({"error": "Database unavailable"}),
            status=500,
            mimetype="application/json",
        )
        app.log_http_response(response)

    assert len(calls) == 1
    assert calls[0][1]["operation"] == "GET /test"
    assert calls[0][1]["message"] == "Database unavailable"
    assert calls[0][1]["details"] == {"status_code": 500}


@pytest.mark.parametrize("status", [200, 400, 404, 409])
def test_generic_http_alert_excludes_success_and_client_errors(monkeypatch, status):
    calls = []
    monkeypatch.setattr(app, "publish_failure", lambda *args, **kwargs: calls.append((args, kwargs)))

    with app.app.test_request_context("/test", method="POST"):
        response = app.app.response_class(
            response=json.dumps({"error": "Invalid JSON"}),
            status=status,
            mimetype="application/json",
        )
        app.log_http_response(response)

    assert calls == []


def test_ledger_failure_emits_contextual_alert_and_preserves_exception(monkeypatch):
    calls = []
    original_error = requests.ConnectionError("ledger offline")
    monkeypatch.setattr(
        ledger,
        "authed_request",
        lambda *args, **kwargs: (_ for _ in ()).throw(original_error),
    )
    monkeypatch.setattr(
        ledger,
        "publish_failure",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    with pytest.raises(requests.ConnectionError) as raised:
        ledger.send_to_ledger(
            "/v1/certification-authority/certification-scheme",
            {"id": "scheme-42"},
            operation="Publish certification scheme to blockchain",
            details={"scheme_id": "scheme-42"},
        )

    assert raised.value is original_error
    assert len(calls) == 1
    assert calls[0][1]["operation"] == "Publish certification scheme to blockchain"
    assert calls[0][1]["details"]["scheme_id"] == "scheme-42"
    assert calls[0][1]["details"]["service"] == "ledger"


def test_scheme_import_rejection_emits_alert(monkeypatch):
    calls = []
    monkeypatch.setattr(
        certification_scheme_service,
        "SCHEME_IMPORT_URL",
        "http://scheme-import.test/scheme/import",
    )
    monkeypatch.setattr(
        certification_scheme_service,
        "authed_request",
        lambda *args, **kwargs: FakeResponse(500, {"error": "import failed"}),
    )
    monkeypatch.setattr(
        certification_scheme_service,
        "publish_failure",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    payload, status = certification_scheme_service.import_scheme_to_orchestrator(
        {"id": "scheme-42"},
        {"id": "scheme-42"},
        "scheme-42",
    )

    assert status == 500
    assert payload["scheme_import_status"] == "failed"
    assert len(calls) == 1
    assert calls[0][1]["operation"] == "Import certification scheme to orchestrator"
    assert calls[0][1]["details"]["status_code"] == 500


def test_ccm_mqtt_test_endpoint_is_disabled_by_default(monkeypatch):
    monkeypatch.setattr(app, "CCM_MQTT_TEST_ENDPOINT_ENABLED", False)

    response = app.app.test_client().get(
        "/internal/test/mqtt-alerts",
        headers={"X-CCM-MQTT-Test-Token": "test-token"},
    )

    assert response.status_code == 404


def test_ccm_mqtt_test_endpoint_requires_matching_token(monkeypatch):
    monkeypatch.setattr(app, "CCM_MQTT_TEST_ENDPOINT_ENABLED", True)
    monkeypatch.setattr(app, "CCM_MQTT_TEST_TOKEN", "expected-token")

    response = app.app.test_client().get(
        "/internal/test/mqtt-alerts",
        headers={"X-CCM-MQTT-Test-Token": "wrong-token"},
    )

    assert response.status_code == 403


def test_ccm_mqtt_test_endpoint_publishes_filtered_case_through_ccm(monkeypatch):
    calls = []
    monkeypatch.setattr(app, "CCM_MQTT_TEST_ENDPOINT_ENABLED", True)
    monkeypatch.setattr(app, "CCM_MQTT_TEST_TOKEN", "expected-token")

    def fake_publish_failure(*args, **kwargs):
        calls.append((args, kwargs))
        return {"status": "published", "event_id": kwargs["event_id"]}

    monkeypatch.setattr(app, "publish_failure", fake_publish_failure)

    response = app.app.test_client().post(
        "/internal/test/mqtt-alerts",
        headers={"X-CCM-MQTT-Test-Token": "expected-token"},
        json={
            "confirm": "PUBLISH_SYNTHETIC_FAILURE_ALERTS",
            "filter": "certificate-pdf",
            "delay": 0,
        },
    )

    assert response.status_code == 200
    assert response.json["requested"] == 1
    assert response.json["published"] == 1
    assert response.json["failed"] == 0
    assert len(calls) == 1
    assert calls[0][1]["operation"] == "Generate certificate PDF"
    assert calls[0][1]["details"]["synthetic_test"] is True
    assert calls[0][1]["details"]["test_case"] == "certificate-pdf"
