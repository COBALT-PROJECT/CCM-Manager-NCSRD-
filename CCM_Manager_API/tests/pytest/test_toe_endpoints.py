import uuid


def test_upload_toe_descriptor_requires_component(http, base_url):
    response = http.post(f"{base_url}/upload_toe_descriptor", json={})
    assert response.status_code == 400


def test_upload_toe_descriptor_requires_components(http, base_url):
    payload = {"component": {"component-definition": {"components": []}}}

    response = http.post(f"{base_url}/upload_toe_descriptor", json=payload)

    assert response.status_code == 400
    assert "No components" in response.json().get("error", "")


def test_upload_toe_descriptor_requires_toe_uuid(http, base_url):
    payload = {
        "component": {
            "component-definition": {
                "components": [
                    {
                        "title": "Missing UUID",
                    }
                ]
            }
        }
    }

    response = http.post(f"{base_url}/upload_toe_descriptor", json=payload)

    assert response.status_code == 400
    assert "Missing ToE UUID" in response.json().get("error", "")


def test_upload_toe_descriptor_rejects_missing_scheme(http, base_url):
    payload = {
        "component": {
            "component-definition": {
                "components": [
                    {
                        "uuid": str(uuid.uuid4()),
                        "title": "ToE",
                    }
                ]
            }
        }
    }

    response = http.post(
        f"{base_url}/upload_toe_descriptor",
        params={"scheme_id": f"scheme-{uuid.uuid4()}"},
        json=payload,
    )

    assert response.status_code == 404
    assert "not found" in response.json().get("error", "")


def test_upload_toe_descriptor_with_scheme(http, base_url, scheme_context):
    toe_id = str(uuid.uuid4())
    payload = {
        "component": {
            "component-definition": {
                "components": [
                    {
                        "uuid": toe_id,
                        "title": "ToE",
                    }
                ]
            }
        }
    }
    response = http.post(
        f"{base_url}/upload_toe_descriptor",
        params={"scheme_id": scheme_context["scheme_id"]},
        json=payload,
    )
    assert response.status_code == 200
    assert response.json().get("toe_uuid") == toe_id
    assert "outbound_auth" in response.json()


def test_upload_toe_descriptor_accepts_scheme_from_body(http, base_url, scheme_context):
    toe_id = str(uuid.uuid4())
    payload = {
        "certification_scheme_id": scheme_context["scheme_id"],
        "component": {
            "component-definition": {
                "components": [
                    {
                        "uuid": toe_id,
                        "title": "ToE",
                    }
                ]
            }
        },
    }

    response = http.post(f"{base_url}/upload_toe_descriptor", json=payload)

    assert response.status_code == 200
    assert response.json().get("toe_uuid") == toe_id


def test_retrieve_toe_not_found(http, base_url):
    response = http.get(f"{base_url}/retrieve_toe/{uuid.uuid4()}")
    assert response.status_code == 404


def test_retrieve_toe(http, base_url, toe_context):
    response = http.get(f"{base_url}/retrieve_toe/{toe_context['toe_id']}")
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("toe_id") == toe_context["toe_id"]


def test_search_toe_requires_id(http, base_url):
    response = http.get(f"{base_url}/toes/search")

    assert response.status_code == 400
    assert response.json().get("error") == "Missing ToE ID"


def test_search_toe_by_query_id(http, base_url, toe_context):
    response = http.get(
        f"{base_url}/toes/search",
        params={"toe_id": toe_context["toe_id"]},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload.get("query", {}).get("toe_id") == toe_context["toe_id"]
    assert payload.get("match", {}).get("toe_id") == toe_context["toe_id"]


def test_search_toe_by_path_id(http, base_url, toe_context):
    response = http.get(f"{base_url}/toes/{toe_context['toe_id']}")

    assert response.status_code == 200
    payload = response.json()
    assert payload.get("query", {}).get("toe_id") == toe_context["toe_id"]
    assert payload.get("match", {}).get("toe_id") == toe_context["toe_id"]


def test_retrieve_toes(http, base_url):
    response = http.get(f"{base_url}/retrieve_toes")
    assert response.status_code == 200
    payload = response.json()
    assert "count" in payload
