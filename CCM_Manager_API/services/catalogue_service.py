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


def initialize_ai_catalogue(catalogue_path):
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

    if metrics_col.count_documents({}) == 0:
        metrics_list = cat_data.get("compliance_metrics", [])
        if metrics_list:
            metrics_col.insert_many(metrics_list)
            initialized["metrics"] = len(metrics_list)
            logging.info("Initialized %s AI compliance metrics into MongoDB.", len(metrics_list))

    if controls_col.count_documents({}) == 0:
        controls_list = cat_data.get("certifiable_standards_mapping", [])
        if controls_list:
            controls_col.insert_many(controls_list)
            initialized["controls"] = len(controls_list)
            logging.info("Initialized %s AI controls into MongoDB.", len(controls_list))

    if risks_col.count_documents({}) == 0 and threats_col.count_documents({}) == 0:
        risks_list = cat_data.get("risk_catalogue", [])
        threats_list = []

        for risk in risks_list:
            mapped_threats = risk.get("mapped_threats", []) or []
            for threat in mapped_threats:
                threat_doc = {**threat, "associated_risk_id": risk.get("risk_id")}
                threats_list.append(threat_doc)

        if risks_list:
            risks_col.insert_many(risks_list)
            initialized["risks"] = len(risks_list)
            logging.info("Initialized %s AI risks into MongoDB.", len(risks_list))

        if threats_list:
            threats_col.insert_many(threats_list)
            initialized["threats"] = len(threats_list)
            logging.info("Initialized %s AI threats into MongoDB.", len(threats_list))

    return {"initialized": True, "counts": initialized}
