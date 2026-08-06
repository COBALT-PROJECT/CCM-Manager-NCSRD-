import os
import uuid
from datetime import datetime, timezone

import pytest


def _valid_assessment_payload(toe_id):
    now = datetime.now(timezone.utc).isoformat()
    return {
        "id": str(uuid.uuid4()),
        "created_at": now,
        "metric_id": f"metric-{uuid.uuid4()}",
        "metric_configuration": {"sample": True},
        "compliant": False,
        "evidence_id": str(uuid.uuid4()),
        "resource_id": f"resource-{uuid.uuid4()}",
        "resource_types": ["service"],
        "compliance_comment": "Integration test assessment",
        "target_of_evaluation_id": toe_id,
        "tool_id": "pytest",
        "history_updated_at": now,
        "history": [
            {
                "evidence_id": str(uuid.uuid4()),
                "evidence_recorded_at": now,
            }
        ],
    }


def test_assessment_result_requires_body(http, base_url):
    response = http.post(f"{base_url}/assessment-result", json={})

    assert response.status_code == 400
    assert response.json().get("error") == "Bad Request"


def test_assessment_result_rejects_schema_errors(http, base_url):
    response = http.post(f"{base_url}/assessment-result", json={"id": "not-a-uuid"})

    assert response.status_code == 500
    assert "required property" in response.json().get("error", "")


def test_assessment_result_rejects_unregistered_toe(http, base_url):
    payload = _valid_assessment_payload(str(uuid.uuid4()))

    response = http.post(f"{base_url}/assessment-result", json=payload)

    assert response.status_code == 404
    assert "is not registered" in response.json().get("error", "")


@pytest.mark.external
@pytest.mark.skipif(
    not os.getenv("CCM_RUN_EXTERNAL_TESTS"),
    reason="Set CCM_RUN_EXTERNAL_TESTS=1 to exercise ledger-backed certificate issuance",
)
def test_assessment_result_stores_without_updating_certificate(http, base_url, assessment_payload):
    assessment_payload["compliant"] = True
    response = http.post(f"{base_url}/assessment-result", json=assessment_payload)

    assert response.status_code == 200
    payload = response.json()
    assert payload.get("status") == "success"
    assert payload.get("certificate_update_status") == "skipped"
    assert payload.get("certificate_update_endpoint") == "/certificate-evaluation-result"


def test_list_certificates(http, base_url):
    response = http.get(f"{base_url}/certificates")

    assert response.status_code == 200
    payload = response.json()
    assert "count" in payload
    assert "certificates" in payload


def test_get_certificate_not_found(http, base_url):
    cert_uuid = str(uuid.uuid4())

    response = http.get(f"{base_url}/certificates/{cert_uuid}")

    assert response.status_code == 404
    assert response.json().get("cert_uuid") == cert_uuid


def test_withdraw_certificate_not_found(http, base_url):
    response = http.put(f"{base_url}/certificates/{uuid.uuid4()}/withdraw")

    assert response.status_code == 404
    assert response.json().get("error") == "Certificate not found"
