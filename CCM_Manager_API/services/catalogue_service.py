import json
import logging
import os
from datetime import datetime

from db import controls_col, metrics_col, risks_col, threats_col


def list_documents(collection):
    return list(collection.find({}, {"_id": 0})), 200


def get_document(collection, field, value, label):
    document = collection.find_one({field: value}, {"_id": 0})
    if document:
        return document, 200
    return {"error": f"{label} not found"}, 404


def upsert_documents(collection, data, key_getter, missing_message, saved_label, response_key):
    if isinstance(data, list):
        saved = 0
        for item in data:
            key = key_getter(item)
            if key:
                item["timestamp"] = datetime.utcnow().isoformat()
                collection.update_one({response_key: key}, {"$set": item}, upsert=True)
                saved += 1
        return {"message": f"{saved} {saved_label} saved successfully."}, 201

    key = key_getter(data)
    if not key:
        return {"error": missing_message}, 400

    data["timestamp"] = datetime.utcnow().isoformat()
    collection.update_one({response_key: key}, {"$set": data}, upsert=True)
    return {"message": f"{saved_label[:-1].capitalize()} saved successfully.", response_key: key}, 201


def metric_key(item):
    return item.get("id")


def risk_key(item):
    return item.get("risk_id")


def threat_key(item):
    return item.get("threat_id")


def control_key(item):
    return item.get("control_id") or item.get("associated_control_requirement") or item.get("id")


def _control_statement(control):
    for part in control.get("parts", []) or []:
        if part.get("name") == "statement" and part.get("prose"):
            return part["prose"]
    for part in control.get("parts", []) or []:
        if part.get("prose"):
            return part["prose"]
    return ""


def _flatten_oscal_controls(catalogue):
    catalog = catalogue.get("catalog", catalogue)
    controls = []

    def walk(node, parent_groups=None):
        parent_groups = parent_groups or []

        for control in node.get("controls", []) or []:
            control_id = control.get("id")
            if not control_id:
                continue

            statement = _control_statement(control)
            controls.append({
                "control_id": control_id,
                "oscal_id": control_id,
                "title": control.get("title", ""),
                "class": control.get("class", ""),
                "description": statement,
                "prose": statement,
                "parts": control.get("parts", []),
                "groups": parent_groups,
            })

        for group in node.get("groups", []) or []:
            group_ref = {
                "id": group.get("id", ""),
                "title": group.get("title", ""),
                "class": group.get("class", ""),
            }
            walk(group, parent_groups + [group_ref])

    walk(catalog)
    return controls


def _load_oscal_controls(controls_catalogue_path):
    if not controls_catalogue_path or not os.path.exists(controls_catalogue_path):
        return []

    with open(controls_catalogue_path, "r") as controls_catalogue_file:
        controls_catalogue = json.load(controls_catalogue_file)

    return _flatten_oscal_controls(controls_catalogue)


def _save_documents(collection, docs, key_getter, force_upsert=False, query_builder=None):
    if not docs:
        return 0

    if force_upsert:
        saved = 0
        for doc in docs:
            key = key_getter(doc)
            if not key:
                continue

            query = query_builder(doc, key) if query_builder else {key_getter.__name__: key}
            collection.update_one(query, {"$set": doc}, upsert=True)
            saved += 1
        return saved

    collection.insert_many(docs)
    return len(docs)


def initialize_ai_catalogue(catalogue_path, controls_catalogue_path=None, force_upsert=False):
    if not os.path.exists(catalogue_path):
        return {"initialized": False, "reason": "catalogue file not found"}

    with open(catalogue_path, "r") as catalogue_file:
        cat_data = json.load(catalogue_file)
    cat_data = cat_data.get("certificationScheme", cat_data)

    initialized = {
        "metrics": 0,
        "controls": 0,
        "risks": 0,
        "threats": 0,
    }

    if force_upsert or metrics_col.count_documents({}) == 0:
        metrics_list = cat_data.get("compliance_metrics", [])
        if metrics_list:
            initialized["metrics"] = _save_documents(
                metrics_col,
                metrics_list,
                metric_key,
                force_upsert,
                lambda _doc, key: {"id": key},
            )
            logging.info("Initialized %s AI compliance metrics into MongoDB.", len(metrics_list))

    if force_upsert or controls_col.count_documents({}) == 0:
        controls_list = _load_oscal_controls(controls_catalogue_path)
        if not controls_list:
            controls_list = cat_data.get("certifiable_standards_mapping", [])
        if controls_list:
            initialized["controls"] = _save_documents(
                controls_col,
                controls_list,
                control_key,
                force_upsert,
                lambda _doc, key: {"control_id": key},
            )
            logging.info("Initialized %s AI controls into MongoDB.", len(controls_list))

    if force_upsert or (risks_col.count_documents({}) == 0 and threats_col.count_documents({}) == 0):
        risks_list = cat_data.get("risk_catalogue", [])
        threats_list = []

        for risk in risks_list:
            mapped_threats = risk.get("mapped_threats", []) or []
            for threat in mapped_threats:
                threat_doc = {**threat, "associated_risk_id": risk.get("risk_id")}
                threats_list.append(threat_doc)

        if risks_list:
            initialized["risks"] = _save_documents(
                risks_col,
                risks_list,
                risk_key,
                force_upsert,
                lambda _doc, key: {"risk_id": key},
            )
            logging.info("Initialized %s AI risks into MongoDB.", len(risks_list))

        if threats_list:
            initialized["threats"] = _save_documents(
                threats_col,
                threats_list,
                threat_key,
                force_upsert,
                lambda doc, key: {
                    "threat_id": key,
                    "associated_risk_id": doc.get("associated_risk_id"),
                },
            )
            logging.info("Initialized %s AI threats into MongoDB.", len(threats_list))

    return {"initialized": True, "counts": initialized}
