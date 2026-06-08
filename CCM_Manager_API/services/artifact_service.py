import logging
from datetime import datetime
from uuid import uuid4

import requests

from auth import auth_context, authed_request
from config import ENDPOINTS
from db import collection, db
from utils import generate_json_hash, is_valid_urn_uuid


def insert_data(data):
    result = db.collection.insert_one(data)
    return {"status": "success", "id": str(result.inserted_id)}, 201


def list_vulnerabilities():
    vulnerabilities = list(collection.find({}, {"_id": 0}))
    if vulnerabilities:
        return vulnerabilities, 200

    return {"message": "No vulnerabilities found"}, 404


def get_oscal_control_ids(doc_uuid):
    doc = collection.find_one({"uuid": doc_uuid})
    if not doc or "content" not in doc or "profile" not in doc["content"]:
        return {"error": "Profile not found"}, 404

    control_ids = []
    imports = doc["content"]["profile"].get("imports", [])
    for imported_profile in imports:
        for control in imported_profile.get("include-controls", []):
            control_ids.extend(control.get("with-ids", []))

    return {"control_ids": list(set(control_ids))}, 200


def upload_saasbom(saasbom_json):
    if saasbom_json.get("bomFormat") != "CycloneDX":
        return {"error": "'bomFormat' must be 'CycloneDX'."}, 400

    if saasbom_json.get("specVersion") != "1.4":
        return {"error": "'specVersion' must be '1.4'."}, 400

    if "serialNumber" not in saasbom_json:
        saasbom_json["serialNumber"] = f"urn:uuid:{str(uuid4())}"
    elif not is_valid_urn_uuid(saasbom_json["serialNumber"]):
        return {"error": "'serialNumber' must be a valid 'urn:uuid'."}, 400

    if not isinstance(saasbom_json.get("version"), int):
        return {"error": "'version' must be an integer."}, 400

    metadata = saasbom_json.get("metadata", {})
    if "component" not in metadata:
        return {"error": "Missing 'component' in 'metadata'."}, 400

    services = saasbom_json.get("services")
    if not isinstance(services, list) or not services:
        return {"error": "Missing or invalid 'services' field — not a SaaSBOM."}, 400

    has_saasbom_indicators = any(
        isinstance(service, dict) and "data" in service and "x-trust-boundary" in service
        for service in services
    )
    if not has_saasbom_indicators:
        return {
            "error": "Service entries must contain 'data' and 'x-trust-boundary' — likely not a SaaSBOM."
        }, 400

    try:
        result = collection.insert_one(saasbom_json)
        logging.info("Document inserted with ID: %s", result.inserted_id)
    except Exception as exc:
        return {"error": f"Error inserting into database: {exc}"}, 500

    return {
        "message": "SaaSBOM saved successfully.",
        "serialNumber": saasbom_json["serialNumber"],
    }, 200


def store_ledger_entry(oscal_json):
    component_def = oscal_json.get("component-definition")
    if not component_def:
        return {"error": "Missing 'component-definition' section."}, 400

    wrapper_uuid = str(uuid4())
    content_hash = generate_json_hash(oscal_json)

    wrapped_doc = {
        "type": "ccm_ledger",
        "headers": {
            "uuid": wrapper_uuid,
            "hash": content_hash,
            "timestamp": datetime.utcnow().isoformat(),
        },
        "oscal_component": {
            "ref": wrapper_uuid,
            "component-definition": component_def,
        },
    }

    collection.insert_one(wrapped_doc)
    return {"message": "Stored", "uuid": wrapper_uuid, "hash": content_hash}, 201


def update_ledger_entry(entry_uuid, oscal_json):
    new_hash = generate_json_hash(oscal_json)

    result = collection.update_one(
        {"headers.uuid": entry_uuid, "type": "ccm_ledger"},
        {
            "$set": {
                "oscal_component.component-definition": oscal_json.get("component-definition"),
                "headers.hash": new_hash,
                "headers.timestamp": datetime.utcnow().isoformat(),
            }
        },
    )

    if result.matched_count == 0:
        return {"error": "Entry not found"}, 404

    return {"message": "Ledger updated", "uuid": entry_uuid, "hash": new_hash}, 200


def receive_and_forward(incoming_data):
    if not incoming_data:
        return {"error": "Invalid or missing JSON"}, 400

    wrapped_doc = {
        "channel": "artifact",
        "smartContract": "artifactsc",
        "key": "test",
        "data": incoming_data,
    }

    collection.insert_one(wrapped_doc.copy())

    headers = {"Content-Type": "application/json"}
    forward_results = []
    for url in ENDPOINTS:
        forward_result = {
            "url": url,
            "auth": auth_context("artifact_forwarder"),
        }
        try:
            response = authed_request(
                "POST",
                url,
                json=wrapped_doc,
                headers=headers,
                timeout=5,
                service="artifact_forwarder",
            )
            forward_result["status"] = "sent"
            forward_result["response_status"] = response.status_code
        except requests.RequestException as exc:
            print(f"Failed to forward to {url}: {exc}")
            forward_result["status"] = "failed"
            forward_result["error"] = str(exc)
        forward_results.append(forward_result)

    return {"status": "Success", "forwarded_to": forward_results}, 200


def upload_evidence(evidence):
    required_fields = ["timestamp", "toolId", "raw", "resource", "id"]
    if not all(field in evidence for field in required_fields):
        return {"error": "Missing required fields in evidence"}, 400

    db.collection.insert_one({"type": "evidence", "data": evidence})
    return {"message": "Evidence stored", "id": evidence["id"]}, 201
