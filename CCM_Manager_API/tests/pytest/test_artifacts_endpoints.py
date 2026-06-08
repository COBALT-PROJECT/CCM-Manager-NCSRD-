import uuid


def test_insert_data(http, base_url):
    response = http.post(f"{base_url}/data", json={"hello": "world"})
    assert response.status_code == 201
    payload = response.json()
    assert payload.get("status") == "success"


def test_show_vulnerabilities(http, base_url):
    response = http.get(f"{base_url}/show_vulnerabilities")
    assert response.status_code in (200, 404)


def test_oscal_ids_not_found(http, base_url):
    response = http.get(f"{base_url}/oscal_ids/{uuid.uuid4()}")
    assert response.status_code == 404


def test_store_ledger_missing_component(http, base_url):
    response = http.post(f"{base_url}/store-ledger", json={})
    assert response.status_code == 400


def test_store_and_update_ledger(http, base_url):
    payload = {"component-definition": {"uuid": str(uuid.uuid4()), "components": []}}
    response = http.post(f"{base_url}/store-ledger", json=payload)
    assert response.status_code == 201
    ledger_uuid = response.json().get("uuid")
    assert ledger_uuid

    update_payload = {
        "component-definition": {
            "uuid": str(uuid.uuid4()),
            "components": [],
        }
    }
    response = http.put(f"{base_url}/update-ledger/{ledger_uuid}", json=update_payload)
    assert response.status_code == 200


def test_update_ledger_not_found(http, base_url):
    response = http.put(
        f"{base_url}/update-ledger/{uuid.uuid4()}",
        json={"component-definition": {"components": []}},
    )

    assert response.status_code == 404
    assert response.json().get("error") == "Entry not found"


def test_send_records_requires_json(http, base_url):
    response = http.post(f"{base_url}/send_records", data="")
    assert response.status_code == 400


def test_send_records_success(http, base_url):
    response = http.post(f"{base_url}/send_records", json={"record": True})
    assert response.status_code == 200


def test_upload_evidence_validation(http, base_url):
    response = http.post(f"{base_url}/evidence", json={"id": "only"})
    assert response.status_code == 400


def test_upload_evidence_success(http, base_url):
    payload = {
        "timestamp": "2026-01-01T00:00:00Z",
        "toolId": "tool-1",
        "raw": {"data": True},
        "resource": "resource-1",
        "id": f"evidence-{uuid.uuid4()}",
    }
    response = http.post(f"{base_url}/evidence", json=payload)
    assert response.status_code == 201
