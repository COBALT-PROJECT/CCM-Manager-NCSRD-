import json

import pytest

from services import sdt_sender


pytestmark = pytest.mark.unit


class DummyResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no json payload")
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")


class FakeCollection:
    def __init__(self, record=None):
        self.record = record

    def find_one(self, query):
        if query in ({"hash": "hash-1"}, {"headers.hash": "hash-1"}):
            return self.record
        return None


def test_send_sdt_uses_sdtm_lifecycle_and_adapt_flow(tmp_path, monkeypatch):
    bom_path = tmp_path / "SBOM.json"
    bom_payload = {"bomFormat": "CycloneDX", "components": []}
    bom_path.write_text(json.dumps(bom_payload), encoding="utf-8")
    calls = []

    def fake_authed_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        if url.endswith("/digital-twin") and method == "POST":
            return DummyResponse(201, {
                "identifier": "dt-1",
                "ids_connector_id": "ids-1",
                "watchtower_id": "wt-1",
                "auth_status": "pending",
            })
        if url.endswith("/adapt") and method == "POST":
            return DummyResponse(200, {"adapted": True})
        if url.endswith("/deployments"):
            return DummyResponse(200, {"deployments": [{"identifier": "dt-1"}]})
        if "/auth/" in url:
            return DummyResponse(200, {"auth_status": "ready"})
        return DummyResponse(200, {"identifier": "dt-1", "pod_state": "Running"})

    monkeypatch.setattr(sdt_sender, "authed_request", fake_authed_request)
    monkeypatch.setattr(sdt_sender, "SDTM_DIGITAL_TWIN_URL", "http://sdtm.example.test/api/SDTM/digital-twin")
    monkeypatch.setattr(sdt_sender, "SDTM_DEPLOYMENTS_URL", "http://sdtm.example.test/api/SDTM/deployments")
    monkeypatch.setattr(sdt_sender, "SDTM_AUTH_STATUS_URL", "http://sdtm.example.test/api/SDTM/auth")
    monkeypatch.setattr(sdt_sender, "SDTM_ADAPT_URL", "http://sdtm.example.test/api/SDTM/adapt")
    monkeypatch.setattr(sdt_sender, "SDTM_DEFAULT_PAYLOAD_TYPE", "BOMS")
    monkeypatch.setattr(sdt_sender, "SDTM_DEFAULT_TOE_ID", "00000000-0000-0000-0000-000000000000")

    payload, status_code = sdt_sender.send_sdt(
        "hash-1",
        bom_path=str(bom_path),
        toe_id="toe-123",
        category="BOMS",
        deployment_payload={"metadata": {"owner": "ccm"}},
    )

    assert status_code == 200
    assert payload["status"] == "SDT instance deployed and SBOM adapted successfully"
    assert payload["twin_id"] == "dt-1"
    assert payload["ids_connector_id"] == "ids-1"
    assert payload["watchtower_id"] == "wt-1"
    assert payload["adapt_response"] == {"adapted": True}
    assert payload["sdts"] == ["dt-1"]
    assert payload["twin_status"] == {"identifier": "dt-1", "pod_state": "Running"}
    assert payload["auth_status_response"] == {"auth_status": "ready"}
    assert calls == [
        (
            "POST",
            "http://sdtm.example.test/api/SDTM/digital-twin",
            {
                "timeout": 30,
                "service": "sdt",
                "json": {"metadata": {"owner": "ccm"}},
            },
        ),
        (
            "POST",
            "http://sdtm.example.test/api/SDTM/adapt",
            {
                "params": {"payload_type": "BOMS", "toeid": "toe-123"},
                "json": bom_payload,
                "timeout": 30,
                "service": "sdt",
            },
        ),
        (
            "GET",
            "http://sdtm.example.test/api/SDTM/deployments",
            {"timeout": 10, "service": "sdt"},
        ),
        (
            "GET",
            "http://sdtm.example.test/api/SDTM/digital-twin/dt-1",
            {"timeout": 10, "service": "sdt"},
        ),
        (
            "GET",
            "http://sdtm.example.test/api/SDTM/auth/dt-1",
            {"timeout": 10, "service": "sdt"},
        ),
    ]


def test_send_sdt_can_deploy_without_body(tmp_path, monkeypatch):
    bom_path = tmp_path / "SBOM.json"
    bom_payload = {"bomFormat": "CycloneDX", "components": []}
    bom_path.write_text(json.dumps(bom_payload), encoding="utf-8")
    calls = []

    def fake_authed_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        if url.endswith("/adapt"):
            return DummyResponse(200, {"adapted": True})
        return DummyResponse(200, {"identifier": "dt-1"})

    monkeypatch.setattr(sdt_sender, "authed_request", fake_authed_request)
    monkeypatch.setattr(sdt_sender, "SDTM_DIGITAL_TWIN_URL", "http://sdtm.example.test/api/SDTM/digital-twin")
    monkeypatch.setattr(sdt_sender, "SDTM_DEPLOYMENTS_URL", "")
    monkeypatch.setattr(sdt_sender, "SDTM_AUTH_STATUS_URL", "")
    monkeypatch.setattr(sdt_sender, "SDTM_ADAPT_URL", "http://sdtm.example.test/api/SDTM/adapt")
    monkeypatch.setattr(sdt_sender, "SDTM_DEFAULT_PAYLOAD_TYPE", "BOMS")
    monkeypatch.setattr(sdt_sender, "SDTM_DEFAULT_TOE_ID", "00000000-0000-0000-0000-000000000000")

    payload, status_code = sdt_sender.send_sdt("hash-1", bom_path=str(bom_path))

    assert status_code == 200
    assert payload["twin_id"] == "dt-1"
    assert calls == [
        (
            "POST",
            "http://sdtm.example.test/api/SDTM/digital-twin",
            {"timeout": 30, "service": "sdt"},
        ),
        (
            "POST",
            "http://sdtm.example.test/api/SDTM/adapt",
            {
                "params": {
                    "payload_type": "BOMS",
                    "toeid": "00000000-0000-0000-0000-000000000000",
                },
                "json": bom_payload,
                "timeout": 30,
                "service": "sdt",
            },
        ),
        (
            "GET",
            "http://sdtm.example.test/api/SDTM/digital-twin/dt-1",
            {"timeout": 10, "service": "sdt"},
        ),
    ]


def test_send_sdt_can_resolve_bom_path_from_hash_record(tmp_path, monkeypatch):
    bom_path = tmp_path / "SBOM.json"
    bom_payload = {"bomFormat": "CycloneDX", "components": []}
    bom_path.write_text(json.dumps(bom_payload), encoding="utf-8")
    calls = []

    def fake_authed_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        if url.endswith("/adapt"):
            return DummyResponse(200, {"adapted": True})
        return DummyResponse(200, {"identifier": "dt-1"})

    monkeypatch.setattr(sdt_sender, "collection", FakeCollection({"path": str(bom_path)}))
    monkeypatch.setattr(sdt_sender, "authed_request", fake_authed_request)
    monkeypatch.setattr(sdt_sender, "SDTM_DIGITAL_TWIN_URL", "http://sdtm.example.test/api/SDTM/digital-twin")
    monkeypatch.setattr(sdt_sender, "SDTM_DEPLOYMENTS_URL", "")
    monkeypatch.setattr(sdt_sender, "SDTM_AUTH_STATUS_URL", "")
    monkeypatch.setattr(sdt_sender, "SDTM_ADAPT_URL", "http://sdtm.example.test/api/SDTM/adapt")
    monkeypatch.setattr(sdt_sender, "SDTM_DEFAULT_PAYLOAD_TYPE", "BOMS")
    monkeypatch.setattr(sdt_sender, "SDTM_DEFAULT_TOE_ID", "00000000-0000-0000-0000-000000000000")

    payload, status_code = sdt_sender.send_sdt("hash-1")

    assert status_code == 200
    assert payload["bom_path"] == str(bom_path)
    assert calls[1] == (
        "POST",
        "http://sdtm.example.test/api/SDTM/adapt",
        {
            "params": {
                "payload_type": "BOMS",
                "toeid": "00000000-0000-0000-0000-000000000000",
            },
            "json": bom_payload,
            "timeout": 30,
            "service": "sdt",
        },
    )


def test_get_sdt_fetches_instance_and_auth_status(monkeypatch):
    calls = []

    def fake_authed_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        if "/auth/" in url:
            return DummyResponse(200, {"auth_status": "ready"})
        return DummyResponse(200, {"identifier": "dt-1"})

    monkeypatch.setattr(sdt_sender, "authed_request", fake_authed_request)
    monkeypatch.setattr(sdt_sender, "SDTM_DIGITAL_TWIN_URL", "http://sdtm.example.test/api/SDTM/digital-twin")
    monkeypatch.setattr(sdt_sender, "SDTM_AUTH_STATUS_URL", "http://sdtm.example.test/api/SDTM/auth")

    payload, status_code = sdt_sender.get_sdt("dt-1")

    assert status_code == 200
    assert payload["sdt"] == {"identifier": "dt-1"}
    assert payload["auth_status"] == {"auth_status": "ready"}
    assert calls == [
        (
            "GET",
            "http://sdtm.example.test/api/SDTM/digital-twin/dt-1",
            {"timeout": 10, "service": "sdt"},
        ),
        (
            "GET",
            "http://sdtm.example.test/api/SDTM/auth/dt-1",
            {"timeout": 10, "service": "sdt"},
        ),
    ]


def test_trigger_delete_uses_sdtm_digital_twin_endpoint(monkeypatch):
    calls = []

    def fake_authed_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return DummyResponse(200, {"deleted": True})

    monkeypatch.setattr(sdt_sender, "authed_request", fake_authed_request)
    monkeypatch.setattr(sdt_sender, "SDTM_DIGITAL_TWIN_URL", "http://sdtm.example.test/api/SDTM/digital-twin")

    payload, status_code = sdt_sender.trigger_delete("dt-1")

    assert status_code == 200
    assert payload["delete_response_body"] == {"deleted": True}
    assert calls == [
        (
            "DELETE",
            "http://sdtm.example.test/api/SDTM/digital-twin/dt-1",
            {"service": "sdt"},
        )
    ]


def test_get_sdt_ids_lists_sdtm_deployments(monkeypatch):
    calls = []

    def fake_authed_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return DummyResponse(200, {"deployments": [{"identifier": "dt-1"}]})

    monkeypatch.setattr(sdt_sender, "authed_request", fake_authed_request)
    monkeypatch.setattr(sdt_sender, "SDTM_DEPLOYMENTS_URL", "http://sdtm.example.test/api/SDTM/deployments")

    payload, status_code = sdt_sender.get_sdt_ids()

    assert status_code == 200
    assert payload["sdts"] == ["dt-1"]
    assert payload["deployments"] == {"deployments": [{"identifier": "dt-1"}]}
    assert calls == [
        (
            "GET",
            "http://sdtm.example.test/api/SDTM/deployments",
            {"timeout": 10, "service": "sdt"},
        )
    ]
