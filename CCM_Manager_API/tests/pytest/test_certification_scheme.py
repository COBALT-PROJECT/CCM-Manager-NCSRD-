import os
import uuid


def _scheme_payload(scheme_id):
    metric_id = f"metric-{uuid.uuid4()}"
    risk_id = f"risk-{uuid.uuid4()}"
    threat_id = f"threat-{uuid.uuid4()}"
    control_id = f"control-{uuid.uuid4()}"

    return {
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


def test_upload_certification_scheme_requires_json(http, base_url):
    response = http.post(f"{base_url}/upload_certification_scheme", data="")
    assert response.status_code == 400


def test_get_certification_scheme(http, base_url, scheme_context):
    scheme_id = scheme_context["scheme_id"]
    response = http.get(f"{base_url}/certification_scheme/{scheme_id}")
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("uuid") == scheme_id


def test_list_certification_schemes(http, base_url):
    response = http.get(f"{base_url}/certification_schemes")
    assert response.status_code == 200
    payload = response.json()
    assert "count" in payload


def test_rtc_mappings_roundtrip(http, base_url, scheme_context):
    scheme_id = scheme_context["scheme_id"]

    response = http.post(
        f"{base_url}/schemes/{scheme_id}/mappings/rtc",
        json={"invalid": True},
    )
    assert response.status_code == 400

    payload = [
        {
            "risk_id": scheme_context["risk_id"],
            "threat_id": scheme_context["threat_id"],
            "control_id": scheme_context["control_id"],
        }
    ]
    response = http.post(
        f"{base_url}/schemes/{scheme_id}/mappings/rtc",
        json=payload,
    )
    assert response.status_code == 201

    response = http.get(f"{base_url}/schemes/{scheme_id}/mappings/rtc")
    assert response.status_code == 200
    payload = response.json()
    assert "mappings" in payload


def test_cm_mappings_roundtrip(http, base_url, scheme_context):
    scheme_id = scheme_context["scheme_id"]

    response = http.post(
        f"{base_url}/schemes/{scheme_id}/mappings/cm",
        json={"invalid": True},
    )
    assert response.status_code == 400

    payload = [
        {
            "control_id": scheme_context["control_id"],
            "metric_id": scheme_context["metric_id"],
        }
    ]
    response = http.post(
        f"{base_url}/schemes/{scheme_id}/mappings/cm",
        json=payload,
    )
    assert response.status_code == 201

    response = http.get(f"{base_url}/schemes/{scheme_id}/mappings/cm")
    assert response.status_code == 200
    payload = response.json()
    assert "mappings" in payload


def test_export_scheme(http, base_url, scheme_context):
    scheme_id = scheme_context["scheme_id"]
    response = http.get(f"{base_url}/schemes/{scheme_id}/export")
    assert response.status_code == 200
    payload = response.json()
    assert "scheme" in payload
    assert "counts" in payload


def test_export_scheme_not_found(http, base_url):
    response = http.get(f"{base_url}/schemes/scheme-{uuid.uuid4()}/export")

    assert response.status_code == 404
    assert "not found" in response.json().get("error", "")


def test_sync_drm(http, base_url, scheme_context):
    scheme_id = scheme_context["scheme_id"]
    response = http.post(f"{base_url}/schemes/{scheme_id}/sync-drm")
    if os.getenv("DRM_BASE_URL"):
        assert response.status_code in (200, 502)
    else:
        assert response.status_code == 503


def test_delete_certification_scheme(http, base_url):
    scheme_id = f"scheme-{uuid.uuid4()}"
    payload = _scheme_payload(scheme_id)

    response = http.post(
        f"{base_url}/upload_certification_scheme",
        json=payload,
    )
    assert response.status_code == 200

    response = http.delete(f"{base_url}/certification_scheme/{scheme_id}")
    assert response.status_code == 200

    response = http.get(f"{base_url}/certification_scheme/{scheme_id}")
    assert response.status_code == 404


def test_delete_certification_scheme_not_found(http, base_url):
    response = http.delete(f"{base_url}/certification_scheme/scheme-{uuid.uuid4()}")

    assert response.status_code == 404
    assert response.json().get("error") == "Certification Scheme not found"
