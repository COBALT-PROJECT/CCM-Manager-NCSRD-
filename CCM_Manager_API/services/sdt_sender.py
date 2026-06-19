import json
import os
import time
import requests
from urllib.parse import quote
from pymongo.collection import Collection

from auth import auth_context, authed_request
from config import (
    SDTM_ADAPT_URL,
    SDTM_AUTH_STATUS_URL,
    SDTM_DEFAULT_PAYLOAD_TYPE,
    SDTM_DEFAULT_TOE_ID,
    SDTM_DEPLOYMENTS_URL,
    SDTM_DIGITAL_TWIN_URL,
)
from db import collection
from utils import mongo_safe_document


IDENTIFIER_KEYS = (
    "id",
    "identifier",
    "digital_twin_id",
    "digitalTwinId",
    "toe_id",
    "toeId",
    "twinId",
    "twin_id",
    "thingId",
    "thing_id",
    "uuid",
)


def _json_or_text(response):
    try:
        return response.json()
    except ValueError:
        return response.text


def _unique_strings(items):
    seen = set()
    result = []
    for item in items:
        text = str(item)
        if text not in seen:
            seen.add(text)
            result.append(text)
    return result


def _extract_identifiers(payload):
    values = []

    if isinstance(payload, dict):
        for key, value in payload.items():
            if key in IDENTIFIER_KEYS and isinstance(value, (str, int)):
                values.append(value)
            else:
                values.extend(_extract_identifiers(value))
    elif isinstance(payload, list):
        for item in payload:
            values.extend(_extract_identifiers(item))

    return _unique_strings(values)


def _normalize_endpoint(url):
    return url.rstrip("/") if url else ""


def _candidate_bom_paths(record):
    for key in ("path", "sbom_filepath", "bom_path"):
        path = record.get(key)
        if isinstance(path, str) and path:
            yield path

    filename = record.get("filename")
    if isinstance(filename, str) and filename:
        yield filename


def _resolve_bom_path(hash_value=None, bom_path=None):
    if bom_path and os.path.exists(bom_path):
        return bom_path

    if not hash_value:
        return None

    for query in ({"hash": hash_value}, {"headers.hash": hash_value}):
        record = collection.find_one(query)
        if not record:
            continue
        for candidate_path in _candidate_bom_paths(record):
            if os.path.exists(candidate_path):
                return candidate_path

    return None


def _resolve_toe_id(toe_id=None):
    return toe_id or SDTM_DEFAULT_TOE_ID


def _resolve_payload_type(category=None):
    return category or SDTM_DEFAULT_PAYLOAD_TYPE


def _digital_twin_url(twin_id=None):
    base_url = _normalize_endpoint(SDTM_DIGITAL_TWIN_URL)
    if not base_url:
        return ""
    if not twin_id:
        return base_url
    return f"{base_url}/{quote(str(twin_id), safe='')}"


def _auth_status_url(twin_id):
    base_url = _normalize_endpoint(SDTM_AUTH_STATUS_URL)
    if not base_url:
        return ""
    return f"{base_url}/{quote(str(twin_id), safe='')}"


def _adapt_url():
    return _normalize_endpoint(SDTM_ADAPT_URL)


def _deploy_payload(hash_value=None, bom_path=None, toe_id=None, category=None, extra_payload=None):
    if isinstance(extra_payload, dict):
        return extra_payload
    return None


def _deployment_summary(payload):
    if not isinstance(payload, dict):
        return {}
    return {
        "twin_id": (
            payload.get("identifier")
            or payload.get("twinId")
            or payload.get("twin_id")
            or payload.get("id")
        ),
        "ids_connector_id": payload.get("ids_connector_id"),
        "watchtower_id": payload.get("watchtower_id"),
        "auth_status": payload.get("auth_status"),
    }


def _get_deployments():
    deployments_url = _normalize_endpoint(SDTM_DEPLOYMENTS_URL)
    if not deployments_url:
        return None
    response = authed_request("GET", deployments_url, timeout=10, service="sdt")
    response.raise_for_status()
    return response


def _save_adapt_fallback(file_path, hash_value, toe_id, payload_type, content, exc, source_label=None):
    filename = os.path.basename(file_path) if file_path else f"{source_label or 'inline'}-bom.json"
    fallback_data = {
        "filename": filename,
        "path": file_path,
        "hash": hash_value,
        "toe_id": toe_id,
        "payload_type": payload_type,
        "content": mongo_safe_document(content),
        "timestamp": time.time(),
        "note": "Saved due to SDTM adapt failure",
    }
    collection.insert_one(fallback_data)
    return {
        "status": "Fallback save to MongoDB",
        "error": str(exc),
        "saved_file": fallback_data["filename"],
        "toe_id": toe_id,
        "payload_type": payload_type,
        "outbound_auth": [auth_context("sdt")],
    }, 500


def _load_bom_content(file_path=None, bom_content=None):
    if bom_content is not None:
        return bom_content

    with open(file_path, "r") as bom_file:
        return json.load(bom_file)


def _adapt_bom(file_path, hash_value, toe_id, payload_type, bom_content=None, source_label=None):
    adapt_url = _adapt_url()
    if not adapt_url:
        return None, {
            "error": "SDTM adapt endpoint is not configured",
            "outbound_auth": [auth_context("sdt")],
        }, 500

    content = _load_bom_content(file_path=file_path, bom_content=bom_content)

    try:
        response = authed_request(
            "POST",
            adapt_url,
            params={"payload_type": payload_type, "toeid": toe_id},
            json=content,
            timeout=30,
            service="sdt",
        )
        response.raise_for_status()
        return response, None, None
    except requests.RequestException as exc:
        _, fallback_payload, fallback_status = _save_adapt_fallback(
            file_path,
            hash_value,
            toe_id,
            payload_type,
            content,
            exc,
            source_label=source_label,
        )
        return None, fallback_payload, fallback_status


def get_sdt(identifier):
    status_url = _digital_twin_url(identifier)
    if not status_url:
        return {
            "error": "SDTM digital twin endpoint is not configured",
            "outbound_auth": [auth_context("sdt")],
        }, 500

    status_resp = authed_request("GET", status_url, timeout=10, service="sdt")
    status_resp.raise_for_status()

    auth_resp = None
    auth_error = None
    auth_url = _auth_status_url(identifier)
    if auth_url:
        try:
            auth_resp = authed_request("GET", auth_url, timeout=10, service="sdt")
            auth_resp.raise_for_status()
        except requests.RequestException as exc:
            auth_error = str(exc)

    return {
        "sdt": _json_or_text(status_resp),
        "status_code": status_resp.status_code,
        "auth_status": _json_or_text(auth_resp) if auth_resp is not None else None,
        "auth_status_code": auth_resp.status_code if auth_resp is not None else None,
        "auth_error": auth_error,
        "outbound_auth": [auth_context("sdt")],
    }, 200


def send_sdt(
    hash_value=None,
    bom_path=None,
    toe_id=None,
    category=None,
    deployment_payload=None,
    bom_content=None,
    bom_source=None,
):
    print("\nStarting SDTM digital twin and SBOM adapt workflow...\n")
    print(f"Received hash: {hash_value}")

    deploy_url = _digital_twin_url()
    if not deploy_url:
        return {
            "error": "SDTM digital twin endpoint is not configured",
            "outbound_auth": [auth_context("sdt")],
        }, 500
    if not _adapt_url():
        return {
            "error": "SDTM adapt endpoint is not configured",
            "outbound_auth": [auth_context("sdt")],
        }, 500

    resolved_bom_path = None
    if bom_content is None:
        resolved_bom_path = _resolve_bom_path(hash_value=hash_value, bom_path=bom_path)

    if bom_content is None and not resolved_bom_path:
        return {
            "error": "No SBOM file found for SDTM adapt",
            "hash": hash_value,
            "outbound_auth": [auth_context("sdt")],
        }, 404

    resolved_toe_id = _resolve_toe_id(toe_id)
    payload_type = _resolve_payload_type(category)

    try:
        payload = _deploy_payload(
            hash_value=hash_value,
            bom_path=resolved_bom_path,
            toe_id=resolved_toe_id,
            category=payload_type,
            extra_payload=deployment_payload,
        )
        request_kwargs = {"timeout": 30, "service": "sdt"}
        if payload is not None:
            request_kwargs["json"] = payload

        deploy_resp = authed_request(
            "POST",
            deploy_url,
            **request_kwargs,
        )
        print(f"SDTM deploy completed (status {deploy_resp.status_code})")
        deploy_resp.raise_for_status()
    except requests.RequestException as exc:
        return {
            "error": "Failed to deploy SDT instance",
            "details": str(exc),
            "hash": hash_value,
            "outbound_auth": [auth_context("sdt")],
        }, 502

    deploy_payload = _json_or_text(deploy_resp)
    summary = _deployment_summary(deploy_payload)
    twin_id = summary.get("twin_id")

    adapt_resp, adapt_error, adapt_status = _adapt_bom(
        resolved_bom_path,
        hash_value,
        resolved_toe_id,
        payload_type,
        bom_content=bom_content,
        source_label=bom_source,
    )
    if adapt_error is not None:
        adapt_error.update({
            "deploy_status": deploy_resp.status_code,
            "deploy_response": deploy_payload,
            "twin_id": twin_id,
        })
        return adapt_error, adapt_status

    adapt_payload = _json_or_text(adapt_resp)

    deployments_resp = None
    deployments_payload = None
    deployments_error = None
    try:
        deployments_resp = _get_deployments()
        deployments_payload = _json_or_text(deployments_resp) if deployments_resp is not None else None
    except requests.RequestException as exc:
        deployments_error = str(exc)

    status_payload = None
    status_code = None
    status_error = None
    auth_payload = None
    auth_status_code = None
    auth_error = None
    if twin_id:
        try:
            status_result, status_result_code = get_sdt(twin_id)
            status_payload = status_result.get("sdt")
            status_code = status_result.get("status_code") or status_result_code
            auth_payload = status_result.get("auth_status")
            auth_status_code = status_result.get("auth_status_code")
            auth_error = status_result.get("auth_error")
        except requests.RequestException as exc:
            status_error = str(exc)

    sdt_ids = _extract_identifiers(deployments_payload if deployments_payload is not None else deploy_payload)

    print("\nSDTM lifecycle and adapt workflow completed successfully!")

    return {
        "status": "SDT instance deployed and SBOM adapted successfully",
        "hash": hash_value,
        "toe_id": resolved_toe_id,
        "payload_type": payload_type,
        "category": payload_type,
        "bom_path": resolved_bom_path,
        "bom_source": bom_source or ("file" if resolved_bom_path else "inline"),
        "twin_id": twin_id,
        "ids_connector_id": summary.get("ids_connector_id"),
        "watchtower_id": summary.get("watchtower_id"),
        "auth_status": summary.get("auth_status"),
        "deploy_status": deploy_resp.status_code,
        "adapt_status": adapt_resp.status_code,
        "deployments_status": deployments_resp.status_code if deployments_resp is not None else None,
        "twin_status_code": status_code,
        "auth_status_code": auth_status_code,
        "sdts": sdt_ids,
        "deploy_response": deploy_payload,
        "adapt_response": adapt_payload,
        "deployments_response": deployments_payload,
        "twin_status": status_payload,
        "auth_status_response": auth_payload,
        "deployments_error": deployments_error,
        "twin_status_error": status_error,
        "auth_error": auth_error,
        "outbound_auth": [auth_context("sdt")],
    }, 200


def trigger_delete(identifier):
    delete_url = _digital_twin_url(identifier)
    if not delete_url:
        return {
            "error": "SDTM digital twin endpoint is not configured",
            "outbound_auth": [auth_context("sdt")],
        }, 500

    response = authed_request("DELETE", delete_url, service="sdt")

    return {
        "message": "Triggered delete request",
        "twin_id": identifier,
        "delete_response_status": response.status_code,
        "delete_response_body": _json_or_text(response),
        "outbound_auth": [auth_context("sdt")],
    }, response.status_code


def get_sdt_ids():
    deployments_url = _normalize_endpoint(SDTM_DEPLOYMENTS_URL)
    if not deployments_url:
        return {
            "error": "SDTM deployments endpoint is not configured",
            "outbound_auth": [auth_context("sdt")],
        }, 500

    response = authed_request("GET", deployments_url, timeout=10, service="sdt")
    response.raise_for_status()
    data = _json_or_text(response)
    sdt_ids = _extract_identifiers(data)

    return {
        "sdts": [str(item) for item in sdt_ids if item is not None],
        "deployments": data,
        "outbound_auth": [auth_context("sdt")],
    }, 200


class SdtSenderService:
    def __init__(self, collection: Collection, file_path: str, deploy_host: str, auth_client=None):
        self.collection = collection
        self.file_path = file_path
        self.deploy_host = deploy_host.rstrip("/")
        self.auth_client = auth_client

    def _request(self, method, url, **kwargs):
        """Route through ComponentAuthClient when available, raw requests otherwise."""
        if self.auth_client is not None:
            return self.auth_client.authenticated_request(method, url, **kwargs)
        return requests.request(method, url, **kwargs)

    def send(self, hash_value):
        if not os.path.exists(self.file_path):
            return {"error": f"{self.file_path} not found"}, 404

        deploy_resp = self._request("POST", f"{self.deploy_host}/api/SDTM/digital-twin")
        deploy_resp.raise_for_status()

        with open(self.file_path, "r") as bom_file:
            content = json.load(bom_file)

        adapt_resp = self._request(
            "POST",
            f"{self.deploy_host}/api/SDTM/adapt",
            params={
                "payload_type": SDTM_DEFAULT_PAYLOAD_TYPE,
                "toeid": SDTM_DEFAULT_TOE_ID,
            },
            json=content,
        )
        adapt_resp.raise_for_status()

        deployments_resp = self._request("GET", f"{self.deploy_host}/api/SDTM/deployments")
        deployments_resp.raise_for_status()

        return {
            "status": "SDT instance deployed and SBOM adapted successfully",
            "hash": hash_value,
            "deploy_status": deploy_resp.status_code,
            "adapt_status": adapt_resp.status_code,
            "deployments_status": deployments_resp.status_code,
            "deploy_response": _json_or_text(deploy_resp),
            "adapt_response": _json_or_text(adapt_resp),
            "deployments_response": _json_or_text(deployments_resp),
        }, 200
