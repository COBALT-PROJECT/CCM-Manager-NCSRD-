import os
import uuid
from datetime import datetime, timezone

import pytest
import requests


DEFAULT_TIMEOUT = int(os.getenv("CCM_TEST_TIMEOUT", "10"))


def _unique_id(prefix):
    return f"{prefix}-{uuid.uuid4()}"


@pytest.fixture(scope="session")
def base_url():
    return os.getenv("CCM_API_BASE_URL", "http://localhost:5001").rstrip("/")


@pytest.fixture(scope="session")
def http():
    session = requests.Session()
    session.headers.update({"Accept": "application/json"})
    yield session
    session.close()


@pytest.fixture(scope="session")
def api_ready(base_url, http):
    try:
        response = http.get(f"{base_url}/", timeout=DEFAULT_TIMEOUT)
        if response.status_code >= 500:
            pytest.skip(f"API returned {response.status_code} at {base_url}")
    except Exception as exc:
        pytest.skip(f"API not reachable at {base_url}: {exc}")


@pytest.fixture(autouse=True)
def _ensure_api(request):
    if request.node.get_closest_marker("unit"):
        return

    request.getfixturevalue("api_ready")


@pytest.fixture(scope="session")
def container_api_root():
    container_root = os.getenv("CCM_CONTAINER_ROOT", "/app")
    return os.path.join(container_root, "CCM_Manager_API")


@pytest.fixture(scope="session")
def scheme_context(http, base_url, api_ready):
    scheme_id = _unique_id("scheme")
    metric_id = _unique_id("metric")
    risk_id = _unique_id("risk")
    threat_id = _unique_id("threat")
    control_id = _unique_id("control")

    payload = {
        "certificationScheme": {
            "id": scheme_id,
            "compliance_metrics": [
                {
                    "id": metric_id,
                    "name": "Metric",
                    "description": "Test metric",
                    "version": "1.0",
                    "information_need": "test",
                    "implementation_evidence": "manual",
                    "frequency": 1,
                    "data_source_type": "manual",
                    "reporting_format": "json",
                    "target_values": {
                        "target_value_scale": "binary",
                        "target_value": "true",
                    },
                    "associated_control": {
                        "associated_control_framework": "NIST",
                        "associated_control_category": "AC",
                        "associated_control_requirement": control_id,
                    },
                }
            ],
            "certifiable_standards_mapping": [],
            "boundary_conditions": {},
            "risk_catalogue": [
                {
                    "risk_id": risk_id,
                    "risk_name": "Risk",
                    "risk_details": "Test risk",
                    "risk_category": "test",
                    "associated_framework": "NIST",
                    "mapped_threats": [
                        {
                            "threat_id": threat_id,
                            "name": "Threat",
                        }
                    ],
                    "mapped_metrics": [
                        {
                            "metric_id": metric_id,
                            "impact": "high",
                        }
                    ],
                }
            ],
            "productProfile": {},
            "controls": [
                {"oscal_id": control_id, "metric_id": metric_id}
            ],
        }
    }

    response = http.post(
        f"{base_url}/upload_certification_scheme?sync_drm=false&sync_scheme_import=false",
        json=payload,
        timeout=DEFAULT_TIMEOUT,
    )
    if response.status_code != 200:
        pytest.skip(
            f"Scheme setup failed ({response.status_code}): {response.text}"
        )

    return {
        "scheme_id": scheme_id,
        "metric_id": metric_id,
        "risk_id": risk_id,
        "threat_id": threat_id,
        "control_id": control_id,
        "payload": payload,
    }


@pytest.fixture(scope="session")
def toe_context(http, base_url, scheme_context, api_ready):
    toe_id = str(uuid.uuid4())
    payload = {
        "component": {
            "component-definition": {
                "components": [
                    {
                        "uuid": toe_id,
                        "title": "Test ToE",
                    }
                ]
            }
        }
    }

    response = http.post(
        f"{base_url}/upload_toe_descriptor",
        params={"scheme_id": scheme_context["scheme_id"]},
        json=payload,
        timeout=DEFAULT_TIMEOUT,
    )
    if response.status_code != 200:
        pytest.skip(
            f"ToE setup failed ({response.status_code}): {response.text}"
        )

    return {
        "toe_id": toe_id,
        "payload": payload,
    }


@pytest.fixture
def assessment_payload(toe_context):
    now = datetime.now(timezone.utc).isoformat()
    return {
        "id": str(uuid.uuid4()),
        "created_at": now,
        "metric_id": _unique_id("metric"),
        "metric_configuration": {"sample": True},
        "compliant": True,
        "evidence_id": str(uuid.uuid4()),
        "resource_id": _unique_id("resource"),
        "resource_types": ["service"],
        "compliance_comment": "Test assessment",
        "target_of_evaluation_id": toe_context["toe_id"],
        "tool_id": "tool-1",
        "history_updated_at": now,
        "history": [
            {
                "evidence_id": str(uuid.uuid4()),
                "evidence_recorded_at": now,
            }
        ],
    }
