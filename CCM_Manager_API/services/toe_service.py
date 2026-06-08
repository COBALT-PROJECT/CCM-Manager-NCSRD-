import logging
from datetime import datetime

from auth import auth_context, authed_request
from config import FORWARD_URL
from db import certificates_col, collection, schemes_col, toes_col


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


def upload_toe_descriptor(data, scheme_id=None):
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

        toe_entry = {
            "type": "target_of_evaluation",
            "uuid": toe_uuid,
            "name": toe_name,
            "content": data,
            "linked_scheme_id": scheme_id,
            "timestamp": datetime.utcnow().isoformat(),
        }

        toes_col.update_one({"uuid": toe_uuid}, {"$set": toe_entry}, upsert=True)

        outbound_auth = []
        forward_status = "not_configured"
        try:
            if FORWARD_URL:
                authed_request("POST", FORWARD_URL, json=data, timeout=5, service="orchestrator")
                outbound_auth.append(auth_context("orchestrator"))
                forward_status = "sent"
        except Exception as exc:
            logging.warning("Failed to forward enriched ToE: %s", exc)
            outbound_auth.append(auth_context("orchestrator"))
            forward_status = "failed"

        return {
            "message": "ToE registered and BOM files grouped successfully",
            "toe_uuid": toe_uuid,
            "forward_status": forward_status,
            "outbound_auth": outbound_auth,
        }, 200

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
