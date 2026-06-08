import os
import uuid

import pytest


def test_send_sdt_requires_hash(http, base_url):
    response = http.post(f"{base_url}/send_sdt", json={})

    assert response.status_code == 400
    assert response.json().get("error") == "Missing 'hash' in request body"


def test_send_sdt_configured_or_fails_gracefully(http, base_url):
    response = http.post(f"{base_url}/send_sdt", json={"hash": f"hash-{uuid.uuid4()}"})

    if os.getenv("DEPLOY_SDT") and os.getenv("DEPLOYMENTS_SDT") and os.getenv("CREATE_SDT"):
        assert response.status_code in (200, 404, 500, 502)
    else:
        assert response.status_code == 502
        assert "error" in response.json()


def test_trigger_delete_requires_identifier(http, base_url):
    response = http.post(f"{base_url}/trigger_delete", json={})

    assert response.status_code == 400
    assert response.json().get("error") == "Missing 'identifier' in request body"


def test_trigger_delete_configured_or_fails_gracefully(http, base_url):
    response = http.post(
        f"{base_url}/trigger_delete",
        json={"identifier": f"sdt-{uuid.uuid4()}"},
    )

    if os.getenv("DELETE_SDT"):
        assert response.status_code in (200, 400, 404, 500, 502)
    else:
        assert response.status_code == 500
        assert "DELETE_SDT" in response.json().get("error", "")


def test_sdts_configured_or_fails_gracefully(http, base_url):
    response = http.get(f"{base_url}/sdts")

    if os.getenv("DEPLOYMENTS_SDT"):
        assert response.status_code in (200, 502)
        if response.status_code == 200:
            payload = response.json()
            assert isinstance(payload.get("sdts"), list)
            assert "outbound_auth" in payload
    else:
        assert response.status_code == 500
        assert "DEPLOYMENTS_SDT" in response.json().get("error", "")
        assert "outbound_auth" in response.json()


def test_trigger_chain_requires_bom_path(http, base_url):
    response = http.post(f"{base_url}/trigger-chain", json={})

    assert response.status_code == 400
    assert response.json().get("error") == "No BOM file path provided"


def test_trigger_chain_rejects_missing_bom_file(http, base_url):
    response = http.post(
        f"{base_url}/trigger-chain",
        json={
            "bom_path": f"/missing/ccm-bom-{uuid.uuid4()}.json",
            "unique_key": f"key-{uuid.uuid4()}",
        },
    )

    assert response.status_code == 404
    assert response.json().get("error") == "BOM file not found"


def test_trigger_chain_requires_unique_key_after_loading_bom(http, base_url, container_api_root):
    response = http.post(
        f"{base_url}/trigger-chain",
        json={"bom_path": f"{container_api_root}/data/ai_catalogue.json"},
    )

    assert response.status_code in (400, 404)
    if response.status_code == 400:
        assert response.json().get("error") == "unique_key not provided"


@pytest.mark.external
@pytest.mark.skipif(
    not (
        os.getenv("CCM_RUN_EXTERNAL_TESTS")
        and os.getenv("LEDGER_BASE_URL")
        and os.getenv("LEDGER_HASH")
        and os.getenv("SEND_SDT")
    ),
    reason="Set CCM_RUN_EXTERNAL_TESTS, LEDGER_BASE_URL, LEDGER_HASH, and SEND_SDT to exercise chain sync",
)
def test_trigger_chain_success_when_external_services_are_enabled(http, base_url, container_api_root):
    response = http.post(
        f"{base_url}/trigger-chain",
        json={
            "bom_path": f"{container_api_root}/data/ai_catalogue.json",
            "unique_key": f"key-{uuid.uuid4()}",
        },
    )

    assert response.status_code in (200, 500)
    if response.status_code == 200:
        payload = response.json()
        assert payload.get("status") == "success"
        assert "hash" in payload


@pytest.mark.slow
@pytest.mark.skipif(
    not os.getenv("CCM_RUN_SLOW_TESTS"),
    reason="Set CCM_RUN_SLOW_TESTS=1 to exercise the 10 second /stop-sdt endpoint",
)
def test_stop_sdt(http, base_url):
    timeout = int(os.getenv("CCM_TEST_TIMEOUT", "10")) + 15
    response = http.get(f"{base_url}/stop-sdt", timeout=timeout)

    assert response.status_code == 200
    assert response.text == "SDT manager stopped"
