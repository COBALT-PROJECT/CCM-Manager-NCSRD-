import io
import json
import uuid


def _cbom_payload():
    return {
        "ciphers": {
            "tls": {
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": {
                    "TLS_version": "1.2",
                    "encryption_algorithm": "AESGCM(256)",
                    "oid": "2.16.840.1.101.3.4.1.46",
                }
            }
        },
        "certificate": {
            "subjectName": "CN=test.example.com",
            "issuerName": "CN=Test CA",
            "notValidBefore": "Jan 01 00:00:00 2024 GMT",
            "notValidAfter": "Jan 01 00:00:00 2026 GMT",
            "rsaPublicKey": "test-public-key",
            "signatureAlgorithm": "sha256WithRSAEncryption",
            "oid": "1.2.840.113549.1.1.11",
            "publicKeyAlgorithm": "rsaEncryption",
        },
    }


def _json_upload(payload, filename="input.json"):
    return {
        "file": (
            filename,
            io.BytesIO(json.dumps(payload).encode("utf-8")),
            "application/json",
        )
    }


def _saasbom_payload():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "Test SaaS",
                "version": "1.0.0",
            }
        },
        "services": [
            {
                "name": "test-service",
                "data": {"classification": "internal"},
                "x-trust-boundary": True,
            }
        ],
    }


def test_generate_sbom_requires_folder(http, base_url):
    response = http.post(f"{base_url}/generate_sbom", data={})

    assert response.status_code == 400
    assert "error" in response.json()


def test_generate_sbom_rejects_missing_folder(http, base_url):
    response = http.post(
        f"{base_url}/generate_sbom",
        data={"folder": f"/missing/ccm-test-{uuid.uuid4()}"},
    )

    assert response.status_code == 400
    assert "does not exist" in response.json().get("error", "")


def test_generate_sbom_rejects_folder_without_dependency_file(http, base_url, container_api_root):
    response = http.post(
        f"{base_url}/generate_sbom",
        data={"folder": f"{container_api_root}/data"},
    )

    assert response.status_code == 400
    assert "error" in response.json()


def test_generate_cbom_requires_file(http, base_url):
    response = http.post(f"{base_url}/generate_cbom", data={"hashed_ip": "test"})

    assert response.status_code == 400
    assert response.json().get("error") == "No file part in the request."


def test_generate_cbom_rejects_invalid_json(http, base_url):
    files = {"file": ("bad.json", io.BytesIO(b"{bad json"), "application/json")}

    response = http.post(f"{base_url}/generate_cbom", files=files, data={"hashed_ip": "test"})

    assert response.status_code == 400
    assert response.json().get("error") == "Invalid JSON file."


def test_generate_cbom_rejects_payload_without_crypto_data(http, base_url):
    response = http.post(
        f"{base_url}/generate_cbom",
        files=_json_upload({"hello": "world"}),
        data={"hashed_ip": "test"},
    )

    assert response.status_code == 400
    assert "ciphers" in response.json().get("error", "")


def test_generate_cbom_success(http, base_url):
    response = http.post(
        f"{base_url}/generate_cbom",
        files=_json_upload(_cbom_payload()),
        data={"hashed_ip": f"hash-{uuid.uuid4()}"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload.get("message") == "SBOMs generated successfully"
    assert payload.get("algorithm_sbom", "").endswith(".json")
    assert payload.get("certificate_sbom", "").endswith(".json")
    assert payload.get("protocol_sbom", "").endswith(".json")


def test_receive_output_requires_file_or_json(http, base_url):
    response = http.post(f"{base_url}/receive_output", data="")

    assert response.status_code == 400
    assert response.json().get("error") == "No valid input provided."


def test_receive_output_rejects_non_json_file(http, base_url):
    files = {"file": ("input.txt", io.BytesIO(b"{}"), "text/plain")}

    response = http.post(f"{base_url}/receive_output", files=files)

    assert response.status_code == 400
    assert "Only .json files" in response.json().get("error", "")


def test_receive_output_rejects_empty_json(http, base_url):
    response = http.post(f"{base_url}/receive_output", json={})

    assert response.status_code == 400
    assert response.json().get("error") == "Invalid JSON data."


def test_receive_output_accepts_json_cbom_input(http, base_url):
    response = http.post(f"{base_url}/receive_output", json=_cbom_payload())

    assert response.status_code == 200
    assert response.json().get("message") == "SBOMs generated successfully"


def test_upload_saasbom_requires_json(http, base_url):
    response = http.post(f"{base_url}/upload_saasbom", data="")

    assert response.status_code == 400
    assert response.json().get("error") == "No JSON data provided."


def test_upload_saasbom_rejects_invalid_bom_format(http, base_url):
    payload = _saasbom_payload()
    payload["bomFormat"] = "SPDX"

    response = http.post(f"{base_url}/upload_saasbom", json=payload)

    assert response.status_code == 400
    assert "bomFormat" in response.json().get("error", "")


def test_upload_saasbom_rejects_invalid_spec_version(http, base_url):
    payload = _saasbom_payload()
    payload["specVersion"] = "1.5"

    response = http.post(f"{base_url}/upload_saasbom", json=payload)

    assert response.status_code == 400
    assert "specVersion" in response.json().get("error", "")


def test_upload_saasbom_rejects_invalid_serial_number(http, base_url):
    payload = _saasbom_payload()
    payload["serialNumber"] = "not-a-urn"

    response = http.post(f"{base_url}/upload_saasbom", json=payload)

    assert response.status_code == 400
    assert "serialNumber" in response.json().get("error", "")


def test_upload_saasbom_requires_integer_version(http, base_url):
    payload = _saasbom_payload()
    payload["version"] = "1"

    response = http.post(f"{base_url}/upload_saasbom", json=payload)

    assert response.status_code == 400
    assert "version" in response.json().get("error", "")


def test_upload_saasbom_requires_metadata_component(http, base_url):
    payload = _saasbom_payload()
    payload["metadata"] = {}

    response = http.post(f"{base_url}/upload_saasbom", json=payload)

    assert response.status_code == 400
    assert "metadata" in response.json().get("error", "")


def test_upload_saasbom_requires_services(http, base_url):
    payload = _saasbom_payload()
    payload["services"] = []

    response = http.post(f"{base_url}/upload_saasbom", json=payload)

    assert response.status_code == 400
    assert "services" in response.json().get("error", "")


def test_upload_saasbom_requires_saas_service_indicators(http, base_url):
    payload = _saasbom_payload()
    payload["services"] = [{"name": "plain-service"}]

    response = http.post(f"{base_url}/upload_saasbom", json=payload)

    assert response.status_code == 400
    assert "Service entries" in response.json().get("error", "")


def test_upload_saasbom_success(http, base_url):
    response = http.post(f"{base_url}/upload_saasbom", json=_saasbom_payload())

    assert response.status_code == 200
    payload = response.json()
    assert payload.get("message") == "SaaSBOM saved successfully."
    assert payload.get("serialNumber", "").startswith("urn:uuid:")
