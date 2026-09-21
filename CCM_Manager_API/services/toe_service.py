import logging
from datetime import datetime

import requests

from auth import auth_context, authed_request
from config import FORWARD_URL, SBOM_LEDGER_URL
from db import certificates_col, collection, schemes_col, toes_col
from services import sdt_sender, toe_workflow_service
from services.ledger import ledger_auth_context, send_to_ledger
from services.mqtt_alert_service import publish_failure
from utils import mongo_safe_document


def _clean_link_ref(href):
    return href.split("/")[-1].replace(".json", "").replace("urn:uuid:", "")


def _find_linked_bom(clean_ref):
    return collection.find_one(
        {
            "$or": [
                {"uuid": clean_ref},
                {"serialNumber": {"$regex": clean_ref}},
                {"filename": {"$regex": clean_ref}},
                {"_id": clean_ref},
            ]
        },
        {"_id": 0},
    )


def _collect_attached_boms(components):
    attached_boms = {}

    for component in components:
        for link in component.get("links", []):
            href = link.get("href", "")
            bom_type = link.get("text", "unknown-bom")
            bom_doc = _find_linked_bom(_clean_link_ref(href))

            if not bom_doc:
                continue

            attached_boms.setdefault(bom_type, []).append({
                "source_component_uuid": component.get("uuid"),
                "link_ref": href,
                "content": bom_doc,
            })

    return attached_boms


def _flag_enabled(value, default=True):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in {"0", "false", "no", "off", "skip"}
    return bool(value)


def _extract_inline_bom(data, preferred_type=None):
    bills_of_material = data.get("bills-of-material")
    if not isinstance(bills_of_material, dict):
        return None, None

    preferred_keys = []
    if isinstance(preferred_type, str) and preferred_type:
        preferred_keys.append(preferred_type.lower())
    preferred_keys.extend(["sbom", "bom", "saasbom", "cbom", "vex"])

    for key in preferred_keys:
        value = bills_of_material.get(key)
        if isinstance(value, (dict, list)):
            return value, f"bills-of-material.{key}"

    for key, value in bills_of_material.items():
        if isinstance(value, (dict, list)):
            return value, f"bills-of-material.{key}"

    return None, None


def _extract_attached_bom(data, preferred_type=None):
    attached_boms = data.get("attached_boms")
    if not isinstance(attached_boms, dict):
        return None, None

    preferred_terms = []
    if isinstance(preferred_type, str) and preferred_type:
        preferred_terms.append(preferred_type.lower())
    preferred_terms.extend(["sbom", "bom", "cbom", "saasbom"])

    for term in preferred_terms:
        for bom_type, entries in attached_boms.items():
            if term not in str(bom_type).lower() or not isinstance(entries, list):
                continue
            for entry in entries:
                content = entry.get("content") if isinstance(entry, dict) else None
                if isinstance(content, (dict, list)):
                    return content, f"attached_boms.{bom_type}"

    for bom_type, entries in attached_boms.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            content = entry.get("content") if isinstance(entry, dict) else None
            if isinstance(content, (dict, list)):
                return content, f"attached_boms.{bom_type}"

    return None, None


def _extract_sbom(data):
    """Return only the software BOM intended for the manufacturer DLT API."""
    bills_of_material = data.get("bills-of-material")
    if isinstance(bills_of_material, dict):
        sbom = bills_of_material.get("sbom")
        if isinstance(sbom, (dict, list)):
            return sbom, "bills-of-material.sbom"

    attached_boms = data.get("attached_boms")
    if not isinstance(attached_boms, dict):
        return None, None

    for bom_type, entries in attached_boms.items():
        normalized_type = str(bom_type).strip().lower().replace("_", "-")
        if normalized_type not in {"sbom", "sbom-file", "software-bom"}:
            continue
        if not isinstance(entries, list):
            continue
        for entry in entries:
            content = entry.get("content") if isinstance(entry, dict) else None
            if isinstance(content, (dict, list)):
                return content, f"attached_boms.{bom_type}"

    return None, None


def _publish_sbom_to_ledger(data, toe_uuid):
    sbom, sbom_source = _extract_sbom(data)
    if sbom is None:
        return {
            "ledger_hash": None,
            "sbom_ledger_status": "skipped",
            "sbom_ledger_reason": "No SBOM was available in the ToE payload.",
            "sbom_source": None,
            "attempted": False,
        }

    try:
        ledger_hash = send_to_ledger(
            SBOM_LEDGER_URL,
            sbom,
            operation="Publish SBOM to blockchain",
            details={"toe_id": toe_uuid, "sbom_source": sbom_source},
            raw_body=True,
            auth_service="manufacturer",
        )
        if not ledger_hash:
            publish_failure(
                operation="Publish SBOM to blockchain",
                message="Blockchain response did not include an SBOM hash",
                details={
                    "service": "ledger",
                    "endpoint": SBOM_LEDGER_URL,
                    "toe_id": toe_uuid,
                    "sbom_source": sbom_source,
                },
            )
            return {
                "ledger_hash": None,
                "sbom_ledger_status": "failed",
                "sbom_ledger_error": "DLT response did not contain a hash",
                "sbom_source": sbom_source,
                "attempted": True,
            }

        return {
            "ledger_hash": ledger_hash,
            "sbom_ledger_status": "published",
            "sbom_source": sbom_source,
            "attempted": True,
        }
    except Exception as exc:
        logging.warning("Failed to publish ToE SBOM to the ledger: %s", exc)
        if not isinstance(exc, requests.RequestException):
            publish_failure(
                operation="Publish SBOM to blockchain",
                message="Failed to process the blockchain SBOM response",
                details={
                    "service": "ledger",
                    "endpoint": SBOM_LEDGER_URL,
                    "toe_id": toe_uuid,
                    "sbom_source": sbom_source,
                    "exception_type": type(exc).__name__,
                    "error": str(exc),
                },
            )
        return {
            "ledger_hash": None,
            "sbom_ledger_status": "failed",
            "sbom_ledger_error": str(exc),
            "sbom_source": sbom_source,
            "attempted": True,
        }


def _sdt_payload(toe_uuid, toe_name, scheme_id=None):
    metadata = {
        "toe_id": toe_uuid,
        "toe_name": toe_name,
        "source": "ccm",
    }
    if scheme_id:
        metadata["certification_scheme_id"] = scheme_id
    return {"metadata": metadata}


def _sync_to_sdtm(
    data,
    toe_uuid,
    toe_name,
    scheme_id=None,
    bom_path=None,
    payload_type=None,
    ledger_hash=None,
):
    inline_bom, bom_source = _extract_inline_bom(data, payload_type)
    if inline_bom is None:
        inline_bom, bom_source = _extract_attached_bom(data, payload_type)

    if not bom_path and inline_bom is None:
        return {
            "sdtm_status": "skipped",
            "sdtm_attempted": False,
            "sdtm_reason": "No BOM content or BOM path was available for SDTM adapt.",
        }, 200

    sdt_payload, sdt_status = sdt_sender.send_sdt(
        hash_value=ledger_hash,
        bom_path=bom_path,
        toe_id=toe_uuid,
        category=payload_type or "BOMS",
        deployment_payload=_sdt_payload(toe_uuid, toe_name, scheme_id),
        bom_content=inline_bom if not bom_path else None,
        bom_source=bom_source,
    )

    return {
        "sdtm_status": "deployed" if sdt_status == 200 else "failed",
        "sdtm_attempted": True,
        "sdtm_status_code": sdt_status,
        "sdtm_response": sdt_payload,
    }, sdt_status


def upload_toe_descriptor(
    data,
    scheme_id=None,
    deploy_sdt=True,
    sdt_bom_path=None,
    sdt_payload_type=None,
):
    if not data or "component" not in data:
        return {"error": "Missing 'component' in payload"}, 400

    try:
        comp_def = data["component"].get("component-definition", {})
        components = comp_def.get("components", [])

        if not components:
            return {"error": "No components found in component-definition"}, 400

        attached_boms = _collect_attached_boms(components)
        if attached_boms:
            data["attached_boms"] = attached_boms

        toe_uuid = components[0].get("uuid")
        toe_name = components[0].get("title")

        if not toe_uuid:
            return {"error": "Missing ToE UUID"}, 400

        if scheme_id and not schemes_col.find_one({"uuid": scheme_id}):
            return {"error": f"Scheme {scheme_id} not found."}, 404

        sbom_ledger = _publish_sbom_to_ledger(data, toe_uuid)
        ledger_hash = sbom_ledger["ledger_hash"]

        toe_entry = {
            "type": "target_of_evaluation",
            "uuid": toe_uuid,
            "name": toe_name,
            "content": mongo_safe_document(data),
            "linked_scheme_id": scheme_id,
            "ledger_hash": ledger_hash,
            "sbom_ledger_status": sbom_ledger["sbom_ledger_status"],
            "timestamp": datetime.utcnow().isoformat(),
        }

        toes_col.update_one({"uuid": toe_uuid}, {"$set": toe_entry}, upsert=True)

        outbound_auth = []
        if sbom_ledger["attempted"]:
            outbound_auth.append(ledger_auth_context("manufacturer"))
        forward_status = "not_configured"
        try:
            if FORWARD_URL:
                forward_response = authed_request(
                    "POST",
                    FORWARD_URL,
                    json=data,
                    timeout=5,
                    service="orchestrator",
                )
                outbound_auth.append(auth_context("orchestrator"))
                if 200 <= forward_response.status_code < 300:
                    forward_status = "sent"
                else:
                    forward_status = "failed"
                    publish_failure(
                        operation="Forward ToE to orchestrator",
                        message="Orchestrator rejected the ToE descriptor",
                        details={
                            "service": "orchestrator",
                            "toe_id": toe_uuid,
                            "scheme_id": scheme_id,
                            "status_code": forward_response.status_code,
                        },
                    )
        except Exception as exc:
            logging.warning("Failed to forward enriched ToE: %s", exc)
            outbound_auth.append(auth_context("orchestrator"))
            forward_status = "failed"
            publish_failure(
                operation="Forward ToE to orchestrator",
                message="Failed to forward the ToE descriptor",
                details={
                    "service": "orchestrator",
                    "toe_id": toe_uuid,
                    "scheme_id": scheme_id,
                    "exception_type": type(exc).__name__,
                    "error": str(exc),
                },
            )

        response = {
            "message": "ToE registered and BOM files grouped successfully",
            "toe_uuid": toe_uuid,
            "ledger_hash": ledger_hash,
            "sbom_ledger_status": sbom_ledger["sbom_ledger_status"],
            "sbom_source": sbom_ledger["sbom_source"],
            "forward_status": forward_status,
            "outbound_auth": outbound_auth,
        }
        if sbom_ledger.get("sbom_ledger_reason"):
            response["sbom_ledger_reason"] = sbom_ledger["sbom_ledger_reason"]
        if sbom_ledger.get("sbom_ledger_error"):
            response["sbom_ledger_error"] = sbom_ledger["sbom_ledger_error"]

        sdtm_attempted = False
        if _flag_enabled(deploy_sdt, default=True):
            try:
                sdtm_payload, _ = _sync_to_sdtm(
                    data,
                    toe_uuid,
                    toe_name,
                    scheme_id=scheme_id,
                    bom_path=sdt_bom_path,
                    payload_type=sdt_payload_type,
                    ledger_hash=ledger_hash,
                )
                response.update(sdtm_payload)
                sdtm_attempted = bool(sdtm_payload.get("sdtm_attempted"))
                sdt_auth = sdtm_payload.get("sdtm_response", {}).get("outbound_auth")
                if sdt_auth:
                    response["outbound_auth"].extend(sdt_auth)
            except Exception as exc:
                sdtm_attempted = True
                logging.warning("Failed to sync ToE %s to SDTM: %s", toe_uuid, exc)
                publish_failure(
                    operation="Synchronize ToE to SDTM",
                    message="Unexpected failure while synchronizing the ToE to SDTM",
                    details={
                        "service": "sdt",
                        "toe_id": toe_uuid,
                        "scheme_id": scheme_id,
                        "exception_type": type(exc).__name__,
                        "error": str(exc),
                    },
                )
                response.update({
                    "sdtm_status": "failed",
                    "sdtm_attempted": True,
                    "sdtm_error": str(exc),
                })
                response["outbound_auth"].append(auth_context("sdt"))
        else:
            response["sdtm_status"] = "skipped"
            response["sdtm_attempted"] = False
            response["sdtm_reason"] = "SDTM sync disabled for this request."

        if sdtm_attempted:
            try:
                handoff_result = toe_workflow_service.schedule_toe_workflow(
                    toe_uuid,
                    sdt_attempt_status=response.get("sdtm_status"),
                    sdt_attempt_status_code=response.get("sdtm_status_code"),
                )
                response["toe_id_handoff"] = handoff_result
            except Exception as exc:
                logging.warning(
                    "Failed to schedule ToE ID handoff for %s: %s",
                    toe_uuid,
                    exc,
                )
                publish_failure(
                    operation="Schedule ToE ID handoff",
                    message="Failed to schedule the ToE ID handoff workflow",
                    details={
                        "service": "toe_connector",
                        "toe_id": toe_uuid,
                        "exception_type": type(exc).__name__,
                        "error": str(exc),
                    },
                )
                response["toe_id_handoff"] = {
                    "status": "scheduling_failed",
                    "error": str(exc),
                }

        return response, 200

    except Exception as exc:
        logging.error("Error in upload_toe_descriptor: %s", exc)
        return {"error": str(exc)}, 500


def extract_linked_ids(document, root_toe_id):
    linked_ids = set()

    def clean_id(value):
        if isinstance(value, str) and value.startswith("urn:uuid:"):
            return value.replace("urn:uuid:", "")
        return value

    def traverse(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ["uuid", "party-uuids", "role-id", "id"]:
                    if isinstance(value, list):
                        for item in value:
                            linked_ids.add(clean_id(item))
                    else:
                        linked_ids.add(clean_id(value))

                if key == "href" and isinstance(value, str) and "urn:uuid:" in value:
                    linked_ids.add(clean_id(value))

                traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)

    traverse(document)

    if root_toe_id in linked_ids:
        linked_ids.remove(root_toe_id)

    return list(linked_ids)


def retrieve_toe_data(toe_id):
    root_doc = toes_col.find_one({"uuid": toe_id}, {"_id": 0})

    if not root_doc:
        primary_query = {
            "$or": [
                {"content.component-definition.uuid": toe_id},
                {"content.component-definition.components.uuid": toe_id},
                {"component-definition.uuid": toe_id},
                {"uuid": toe_id},
            ]
        }
        root_doc = collection.find_one(primary_query, {"_id": 0})

    if not root_doc:
        return {
            "message": "No root document found for the provided ToE ID",
            "toe_id": toe_id,
        }, 404

    linked_uuids = extract_linked_ids(root_doc, toe_id)
    artifact_query = {
        "$or": [
            {"uuid": {"$in": linked_uuids}},
            {"serialNumber": {"$in": [f"urn:uuid:{uid}" for uid in linked_uuids]}},
            {"target_of_evaluation_id": toe_id},
            {"certification.target_of_evaluation.toe_uuid": toe_id},
        ]
    }

    linked_artifacts = list(collection.find(artifact_query, {"_id": 0}))
    certificates = list(
        certificates_col.find(
            {"certification.target_of_evaluation.toe_uuid": toe_id},
            {"_id": 0},
        )
    )

    return {
        "toe_id": toe_id,
        "root_document": root_doc,
        "linked_files_count": len(linked_artifacts) + len(certificates),
        "linked_ids_detected": linked_uuids,
        "linked_documents": linked_artifacts + certificates,
    }, 200


def search_toe_by_id(toe_id):
    if not toe_id:
        return {"error": "Missing ToE ID"}, 400

    payload, status_code = retrieve_toe_data(toe_id)
    if status_code == 200:
        payload = {
            "query": {"toe_id": toe_id},
            "match": payload,
        }

    return payload, status_code


def retrieve_all_toes():
    dedicated_toes = list(toes_col.find({}, {"_id": 0}))
    fallback_query = {
        "$or": [
            {"content.component-definition": {"$exists": True}},
            {"component-definition": {"$exists": True}},
        ]
    }
    fallback_toes = list(collection.find(fallback_query, {"_id": 0}))

    unique_toes = {}
    for toe in dedicated_toes + fallback_toes:
        toe_uuid = toe.get("uuid")

        if not toe_uuid:
            if "component-definition" in toe:
                toe_uuid = toe["component-definition"].get("uuid")
            elif "content" in toe and "component-definition" in toe["content"]:
                toe_uuid = toe["content"]["component-definition"].get("uuid")

        if toe_uuid:
            unique_toes[toe_uuid] = toe
        else:
            unique_toes[str(id(toe))] = toe

    final_toes_list = list(unique_toes.values())
    return {"count": len(final_toes_list), "toes": final_toes_list}, 200
