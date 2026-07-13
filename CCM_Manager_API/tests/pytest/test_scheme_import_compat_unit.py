import copy

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


def _scheme_content():
    return {
        "id": "urn:uuid:scheme",
        "name": "Full CCM Scheme",
        "authority": {"name": "COBALT"},
        "risk_catalogue": [{"risk_id": "risk-1"}],
        "controls": [{"control_id": "control-1"}],
        "boundary_conditions": {"environment": "Quantum"},
        "certifiable_standards_mapping": [
            {
                "control_id": "quantum-2.QGT-01_req.1",
                "description": "one qubit",
                "metric_id": "OneQubitGateErrorRate_QPU_1.0",
                "standard": "COBALT-Q",
                "extra": "not-for-clouditor",
            },
            {
                "control_id": "eucs-7.AI-02_req.2",
                "description": "anomaly",
                "metric_id": "DataAnomalyIdentification_AIModelClassification_013",
                "standard": "COBALT",
            },
            {
                "control_id": "control-unknown",
                "description": "unknown",
                "metric_id": "UnknownMetric_QPU_1.0",
                "standard": "COBALT-Q",
            },
        ],
        "compliance_metrics": [
            {
                "id": "OneQubitGateErrorRate_QPU_1.0",
                "name": "One-qubit gate error rate",
                "description": "Metric description",
                "version": "V1.0",
                "information_need": "Need",
                "implementation_evidence": "JSON",
                "frequency": 1,
                "data_source_type": "QPU",
                "reporting_format": "Float",
                "target_values": {"target_value": "0.1"},
                "associated_control": {
                    "associated_control_requirement": "quantum-2.QGT-01_req.1",
                },
                "mapped_risks": ["risk-1"],
            },
            {
                "id": "DataAnomalyIdentification_AIModelClassification_013",
                "name": "Data Anomaly Identification",
                "description": "Metric description",
                "version": "V1.0",
            },
            {
                "id": "UnknownMetric_QPU_1.0",
                "name": "Unknown Metric",
                "description": "Metric description",
                "version": "V1.0",
            },
        ],
    }


def test_clouditor_payload_strips_unsupported_fields_maps_metric_uuids_and_omits_unknowns():
    scheme_content = _scheme_content()
    original = copy.deepcopy(scheme_content)

    payload, warnings = service._clouditor_scheme_import_payload(scheme_content)

    assert scheme_content == original
    assert set(payload) == {
        "boundary_conditions",
        "certifiable_standards_mapping",
        "compliance_metrics",
    }
    assert payload["compliance_metrics"][0]["id"] == "16c8ec2b-325e-492f-b2c3-fd9ef48ebd90"
    assert payload["compliance_metrics"][1]["id"] == "58d9a281-0f05-4a49-a1ef-df5013cc901e"
    assert len(payload["compliance_metrics"]) == 2
    assert payload["certifiable_standards_mapping"][0]["metric_id"] == "16c8ec2b-325e-492f-b2c3-fd9ef48ebd90"
    assert payload["certifiable_standards_mapping"][1]["metric_id"] == "58d9a281-0f05-4a49-a1ef-df5013cc901e"
    assert len(payload["certifiable_standards_mapping"]) == 2
    assert "mapped_risks" not in payload["compliance_metrics"][0]
    assert "extra" not in payload["certifiable_standards_mapping"][0]
    assert "UnknownMetric_QPU_1.0" not in {
        metric["id"] for metric in payload["compliance_metrics"]
    }
    assert any("omitting it" in warning and "UnknownMetric_QPU_1.0" in warning for warning in warnings)
    assert any("omitting the mapping" in warning and "UnknownMetric_QPU_1.0" in warning for warning in warnings)


def test_scheme_import_adds_default_target_of_evaluation_id(monkeypatch):
    calls = []

    def fake_authed_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return FakeResponse(200, {"status": "ok"})

    monkeypatch.setattr(service, "SCHEME_IMPORT_URL", "http://orchestrator.example.test/scheme/import")
    monkeypatch.setattr(
        service,
        "SCHEME_IMPORT_TARGET_OF_EVALUATION_ID",
        "00000000-0000-0000-0000-000000000000",
    )
    monkeypatch.setattr(service, "authed_request", fake_authed_request)

    payload, status = service.import_scheme_to_orchestrator(
        {"certificationScheme": _scheme_content()},
        _scheme_content(),
        "urn:uuid:scheme",
        payload_mode="clouditor",
    )

    assert status == 200
    assert payload["scheme_import_status"] == "imported"
    assert calls[0][2]["params"] == {
        "targetOfEvaluationId": "00000000-0000-0000-0000-000000000000"
    }
    assert set(calls[0][2]["json"]) == {
        "boundary_conditions",
        "certifiable_standards_mapping",
        "compliance_metrics",
    }
