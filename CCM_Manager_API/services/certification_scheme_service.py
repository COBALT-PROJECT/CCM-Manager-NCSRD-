import logging
import os
from datetime import datetime
from uuid import uuid4

from auth import auth_context, authed_request
from db import cm_col, controls_col, metrics_col, risks_col, rtc_col, schemes_col, threats_col
from services.ledger import ledger_auth_context, send_to_ledger


def _scheme_sections(data):
    if "certificationScheme" in data:
        scheme_meta = data["certificationScheme"]
        scheme_id = scheme_meta.get("id") or str(uuid4())
    else:
        scheme_meta = {}
        scheme_id = data.get("id") or str(uuid4())

    compliance_metrics = data.get("compliance_metrics", []) or scheme_meta.get("compliance_metrics", [])
    certifiable_standards = data.get("certifiable_standards_mapping", []) or scheme_meta.get("certifiable_standards_mapping", [])
    boundary_conditions = data.get("boundary_conditions", {}) or scheme_meta.get("boundary_conditions", {})
    risk_catalogue = data.get("risk_catalogue", []) or scheme_meta.get("risk_catalogue", [])
    product_profile = data.get("productProfile", {}) or scheme_meta.get("productProfile", {})
    controls_list = data.get("controls", []) or scheme_meta.get("controls", [])
    profile = data.get("profile", {}) or scheme_meta.get("profile", {})
    catalog = data.get("catalog", {}) or scheme_meta.get("catalog", {})

    scheme_content = {**scheme_meta}
    scheme_content["id"] = scheme_id
    scheme_content["compliance_metrics"] = compliance_metrics
    scheme_content["certifiable_standards_mapping"] = certifiable_standards
    scheme_content["boundary_conditions"] = boundary_conditions
    scheme_content["risk_catalogue"] = risk_catalogue
    scheme_content["productProfile"] = product_profile
    scheme_content["controls"] = controls_list
    scheme_content["profile"] = profile
    scheme_content["catalog"] = catalog

    return {
        "scheme_id": scheme_id,
        "scheme_meta": scheme_meta,
        "scheme_content": scheme_content,
        "compliance_metrics": compliance_metrics,
        "risk_catalogue": risk_catalogue,
        "controls_list": controls_list,
    }


def upload_certification_scheme(data):
    if not data:
        return {"error": "No JSON data provided"}, 400

    sections = _scheme_sections(data)
    scheme_id = sections["scheme_id"]
    scheme_meta = sections["scheme_meta"]
    scheme_content = sections["scheme_content"]
    compliance_metrics = sections["compliance_metrics"]
    risk_catalogue = sections["risk_catalogue"]
    controls_list = sections["controls_list"]

    try:
        ledger_hash = send_to_ledger("/v1/certification-authority/certification-scheme", scheme_content)
    except Exception as exc:
        logging.warning("Ledger unavailable, using placeholder hash: %s", exc)
        ledger_hash = "TempHashDueToHotFix"

    try:
        ts = datetime.utcnow().isoformat()
        counts = {
            "metrics": 0,
            "risks": 0,
            "threats": 0,
            "controls": 0,
            "control_metric_mappings": 0,
            "risk_threat_control_mappings": 0,
        }

        for metric in compliance_metrics:
            metric_id = metric.get("id")
            if metric_id:
                metric_doc = {**metric, "scheme_id": scheme_id, "timestamp": ts}
                metrics_col.update_one({"id": metric_id}, {"$set": metric_doc}, upsert=True)
                counts["metrics"] += 1

        seen_threats = set()
        for risk in risk_catalogue:
            risk_id = risk.get("risk_id")
            if not risk_id:
                continue

            risk_doc = {**risk, "scheme_id": scheme_id, "timestamp": ts}
            risks_col.update_one({"risk_id": risk_id}, {"$set": risk_doc}, upsert=True)
            counts["risks"] += 1

            for threat in risk.get("mapped_threats", []):
                threat_id = threat.get("threat_id")
                if threat_id and threat_id not in seen_threats:
                    seen_threats.add(threat_id)
                    threat_doc = {
                        "threat_id": threat_id,
                        "name": threat.get("name", ""),
                        "associated_risk_id": threat.get("associated_risk_id", risk_id),
                        "scheme_id": scheme_id,
                        "timestamp": ts,
                    }
                    threats_col.update_one({"threat_id": threat_id}, {"$set": threat_doc}, upsert=True)
                    counts["threats"] += 1

        for control in controls_list:
            oscal_id = control.get("oscal_id")
            metric_id = control.get("metric_id")
            if oscal_id and metric_id:
                control_doc = {**control, "scheme_id": scheme_id, "timestamp": ts}
                controls_col.update_one(
                    {"oscal_id": oscal_id, "metric_id": metric_id},
                    {"$set": control_doc},
                    upsert=True,
                )
                counts["controls"] += 1

        metric_to_control = {}
        for metric in compliance_metrics:
            metric_id = metric.get("id")
            associated_control = metric.get("associated_control", {})
            control_requirement = associated_control.get("associated_control_requirement")
            if metric_id and control_requirement:
                metric_to_control[metric_id] = control_requirement

        explicit_cm = data.get("control_metric_mappings", []) or scheme_meta.get("control_metric_mappings", [])
        cm_mappings = explicit_cm or [
            {"control_id": control_id, "metric_id": metric_id}
            for metric_id, control_id in metric_to_control.items()
        ]

        cm_col.delete_many({"scheme_id": scheme_id})
        if cm_mappings:
            cm_docs = [{**mapping, "scheme_id": scheme_id, "timestamp": ts} for mapping in cm_mappings]
            cm_col.insert_many(cm_docs)
            counts["control_metric_mappings"] = len(cm_docs)

        risk_to_controls = {}
        for risk in risk_catalogue:
            risk_id = risk.get("risk_id")
            if not risk_id:
                continue

            controls = set()
            for mapped_metric in risk.get("mapped_metrics", []):
                metric_id = mapped_metric.get("metric_id")
                if metric_id and metric_id in metric_to_control:
                    controls.add(metric_to_control[metric_id])

            for metric in compliance_metrics:
                if risk_id in (metric.get("mapped_risks") or []):
                    control = metric_to_control.get(metric.get("id"))
                    if control:
                        controls.add(control)

            risk_to_controls[risk_id] = controls

        explicit_rtc = data.get("risk_threat_control_mappings", []) or scheme_meta.get("risk_threat_control_mappings", [])
        if explicit_rtc:
            rtc_mappings = explicit_rtc
        else:
            rtc_mappings = []
            for risk in risk_catalogue:
                risk_id = risk.get("risk_id")
                if not risk_id:
                    continue

                for threat in risk.get("mapped_threats", []):
                    threat_id = threat.get("threat_id")
                    if not threat_id:
                        continue

                    for control_id in risk_to_controls.get(risk_id, set()):
                        rtc_mappings.append({
                            "risk_id": risk_id,
                            "threat_id": threat_id,
                            "control_id": control_id,
                        })

        rtc_col.delete_many({"scheme_id": scheme_id})
        if rtc_mappings:
            rtc_docs = [{**mapping, "scheme_id": scheme_id, "timestamp": ts} for mapping in rtc_mappings]
            rtc_col.insert_many(rtc_docs)
            counts["risk_threat_control_mappings"] = len(rtc_docs)

        db_entry = {
            "type": "certification_scheme",
            "uuid": scheme_id,
            "content": scheme_content,
            "ledger_hash": ledger_hash,
            "timestamp": ts,
        }
        schemes_col.update_one({"uuid": scheme_id}, {"$set": db_entry}, upsert=True)

        logging.info(
            "Scheme %s uploaded: %s metrics, %s risks, %s threats, %s controls, %s C-M, %s R-T-C",
            scheme_id,
            counts["metrics"],
            counts["risks"],
            counts["threats"],
            counts["controls"],
            counts["control_metric_mappings"],
            counts["risk_threat_control_mappings"],
        )

        return {
            "message": "Certification Scheme uploaded and all entities populated",
            "uuid": scheme_id,
            "ledger_hash": ledger_hash,
            "populated": counts,
            "outbound_auth": [ledger_auth_context()],
        }, 200

    except Exception as exc:
        logging.error("Error in upload_certification_scheme: %s", exc)
        return {"error": str(exc)}, 500


def get_mappings(collection, scheme_id):
    mappings = list(collection.find({"scheme_id": scheme_id}, {"_id": 0}))
    return {"scheme_id": scheme_id, "count": len(mappings), "mappings": mappings}, 200


def replace_mappings(collection, scheme_id, data, label, schema_label):
    if not data or not isinstance(data, list):
        return {"error": f"Payload must be a JSON array of {schema_label} objects."}, 400

    timestamp = datetime.utcnow().isoformat()
    collection.delete_many({"scheme_id": scheme_id})

    docs = [{**item, "scheme_id": scheme_id, "timestamp": timestamp} for item in data]
    if docs:
        collection.insert_many(docs)

    return {"message": f"{len(docs)} {label} mappings saved for scheme {scheme_id}."}, 201


def export_scheme(scheme_id):
    scheme_doc = schemes_col.find_one({"uuid": scheme_id}, {"_id": 0})
    if not scheme_doc:
        return {"error": f"Scheme '{scheme_id}' not found."}, 404

    risks = list(risks_col.find({"scheme_id": scheme_id}, {"_id": 0}))
    threats = list(threats_col.find({"scheme_id": scheme_id}, {"_id": 0}))
    metrics = list(metrics_col.find({"scheme_id": scheme_id}, {"_id": 0}))
    controls = list(controls_col.find({"scheme_id": scheme_id}, {"_id": 0}))
    rtc_mappings = list(rtc_col.find({"scheme_id": scheme_id}, {"_id": 0}))
    cm_mappings = list(cm_col.find({"scheme_id": scheme_id}, {"_id": 0}))

    return {
        "scheme": scheme_doc.get("content", {}),
        "risks": risks,
        "threats": threats,
        "metrics": metrics,
        "controls": controls,
        "risk_threat_control_mappings": rtc_mappings,
        "control_metric_mappings": cm_mappings,
        "counts": {
            "risks": len(risks),
            "threats": len(threats),
            "metrics": len(metrics),
            "controls": len(controls),
            "rtc_mappings": len(rtc_mappings),
            "cm_mappings": len(cm_mappings),
        },
    }, 200


class DrmSyncError(Exception):
    def __init__(self, path, status_code, body):
        super().__init__(f"DRM {path} returned {status_code}")
        self.path = path
        self.status_code = status_code
        self.body = body


def _first_non_empty(*values):
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _drm_api_base(drm_base):
    base = drm_base.rstrip("/")
    prefix = os.getenv("DRM_API_PREFIX", "/eu/cobalt").strip()
    if not prefix or prefix == "/":
        return base

    prefix = f"/{prefix.strip('/')}"
    if base.endswith(prefix):
        return base
    return f"{base}{prefix}"


def _response_body(response):
    try:
        return response.json()
    except ValueError:
        return response.text


def _response_object(body, entity_name):
    if not isinstance(body, dict):
        return {}

    for key in (entity_name, "object", "data", "result"):
        value = body.get(key)
        if isinstance(value, dict):
            return value

    return body


def _remote_id(body, entity_name, fallback=None):
    remote_object = _response_object(body, entity_name)
    for key in ("id", "uuid", "_id"):
        value = remote_object.get(key)
        if value is not None:
            return str(value)
    return str(fallback) if fallback is not None else None


def _drm_post(api_base, path, payload, entity_name, fallback_id=None):
    response = authed_request(
        "POST",
        f"{api_base}{path}",
        json=payload,
        timeout=30,
        service="drm",
    )
    body = _response_body(response)

    if response.status_code >= 400:
        raise DrmSyncError(path, response.status_code, body)

    return {
        "status": response.status_code,
        "id": _remote_id(body, entity_name, fallback_id),
        "body": body,
    }


def _metric_ref(metric):
    return _first_non_empty(metric.get("external_metric_id"), metric.get("id"))


def _control_ref(control):
    return _first_non_empty(
        control.get("control_id"),
        control.get("associated_control_requirement"),
        control.get("oscal_id"),
        control.get("id"),
    )


def _risk_ref(risk):
    return _first_non_empty(risk.get("risk_id"), risk.get("id"))


def _threat_ref(threat):
    return _first_non_empty(threat.get("threat_id"), threat.get("id"))


def _dedupe_by_ref(items, ref_getter):
    deduped = {}
    for item in items or []:
        ref = ref_getter(item)
        if ref and ref not in deduped:
            deduped[ref] = item
    return deduped


def _unique_pairs(mappings):
    unique = []
    seen = set()
    for mapping in mappings or []:
        key = (
            _first_non_empty(mapping.get("control_id")),
            _first_non_empty(mapping.get("metric_id")),
        )
        if not all(key) or key in seen:
            continue
        seen.add(key)
        unique.append(key)
    return unique


def _unique_triplets(mappings):
    unique = []
    seen = set()
    for mapping in mappings or []:
        key = (
            _first_non_empty(mapping.get("risk_id")),
            _first_non_empty(mapping.get("threat_id")),
            _first_non_empty(mapping.get("control_id")),
        )
        if not all(key) or key in seen:
            continue
        seen.add(key)
        unique.append(key)
    return unique


def _prepare_drm_entities(export_payload):
    metrics = _dedupe_by_ref(export_payload.get("metrics", []), _metric_ref)
    controls = _dedupe_by_ref(export_payload.get("controls", []), _control_ref)
    risks = _dedupe_by_ref(export_payload.get("risks", []), _risk_ref)
    threats = _dedupe_by_ref(export_payload.get("threats", []), _threat_ref)
    warnings = []

    for control_id, metric_id in _unique_pairs(export_payload.get("control_metric_mappings", [])):
        if control_id not in controls:
            controls[control_id] = {
                "control_id": control_id,
                "name": control_id,
                "description": "Created from CCM control-metric mapping.",
            }
            warnings.append(f"Control '{control_id}' was missing from export controls and was synthesized.")
        if metric_id not in metrics:
            metrics[metric_id] = {
                "id": metric_id,
                "name": metric_id,
                "description": "Created from CCM control-metric mapping.",
            }
            warnings.append(f"Metric '{metric_id}' was missing from export metrics and was synthesized.")

    for risk_id, threat_id, control_id in _unique_triplets(export_payload.get("risk_threat_control_mappings", [])):
        if risk_id not in risks:
            risks[risk_id] = {
                "risk_id": risk_id,
                "risk_name": risk_id,
                "risk_details": "Created from CCM risk-threat-control mapping.",
            }
            warnings.append(f"Risk '{risk_id}' was missing from export risks and was synthesized.")
        if threat_id not in threats:
            threats[threat_id] = {
                "threat_id": threat_id,
                "name": threat_id,
                "description": "Created from CCM risk-threat-control mapping.",
            }
            warnings.append(f"Threat '{threat_id}' was missing from export threats and was synthesized.")
        if control_id not in controls:
            controls[control_id] = {
                "control_id": control_id,
                "name": control_id,
                "description": "Created from CCM risk-threat-control mapping.",
            }
            warnings.append(f"Control '{control_id}' was missing from export controls and was synthesized.")

    return {
        "metrics": metrics,
        "controls": controls,
        "risks": risks,
        "threats": threats,
        "warnings": warnings,
    }


def sync_drm(scheme_id):
    drm_base = os.getenv("DRM_BASE_URL", "")
    if not drm_base:
        return {"error": "DRM_BASE_URL is not configured in .env"}, 503

    payload, status = export_scheme(scheme_id)
    if status != 200:
        return payload, status

    api_base = _drm_api_base(drm_base)
    scheme = payload.get("scheme", {})
    entities = _prepare_drm_entities(payload)

    admin_email = _first_non_empty(
        scheme.get("scheme_admin_email"),
        os.getenv("DRM_SCHEME_ADMIN_EMAIL"),
        os.getenv("DRM_CREATOR_EMAIL"),
        "ccm-manager@cobalt.local",
    )
    creator_email = _first_non_empty(
        os.getenv("DRM_CREATOR_EMAIL"),
        admin_email,
    )

    created = {
        "schemes": 0,
        "metrics": 0,
        "controls": 0,
        "risks": 0,
        "threats": 0,
        "control_metric_links": 0,
        "risk_threat_control_links": 0,
    }
    remote_ids = {
        "scheme": None,
        "metrics": {},
        "controls": {},
        "risks": {},
        "threats": {},
    }

    try:
        scheme_payload = {
            "name": _first_non_empty(scheme.get("name"), scheme.get("title"), scheme_id),
            "description": _first_non_empty(
                scheme.get("description"),
                scheme.get("summary"),
                f"Imported from CCM Manager scheme {scheme_id}",
            ),
            "scheme_admin_email": admin_email,
        }
        scheme_result = _drm_post(api_base, "/schemes", scheme_payload, "scheme", scheme_id)
        drm_scheme_id = scheme_result["id"] or scheme_id
        remote_ids["scheme"] = drm_scheme_id
        created["schemes"] = 1

        for local_id, metric in entities["metrics"].items():
            metric_payload = {
                "name": _first_non_empty(metric.get("name"), local_id),
                "description": _first_non_empty(metric.get("description"), metric.get("information_need")),
                "external_metric_id": _first_non_empty(metric.get("external_metric_id"), metric.get("id"), local_id),
            }
            result = _drm_post(api_base, "/metrics", metric_payload, "metric", local_id)
            remote_ids["metrics"][local_id] = result["id"] or local_id
            created["metrics"] += 1

        for local_id, control in entities["controls"].items():
            control_payload = {
                "name": _first_non_empty(control.get("name"), control.get("title"), local_id),
                "description": _first_non_empty(control.get("description"), control.get("details")),
            }
            result = _drm_post(api_base, "/controls", control_payload, "control", local_id)
            remote_ids["controls"][local_id] = result["id"] or local_id
            created["controls"] += 1

        for local_id, risk in entities["risks"].items():
            risk_payload = {
                "scheme_id": drm_scheme_id,
                "name": _first_non_empty(risk.get("name"), risk.get("risk_name"), local_id),
                "description": _first_non_empty(risk.get("description"), risk.get("risk_details")),
                "creator_email": _first_non_empty(risk.get("creator_email"), creator_email),
            }
            result = _drm_post(api_base, "/risks", risk_payload, "risk", local_id)
            remote_ids["risks"][local_id] = result["id"] or local_id
            created["risks"] += 1

        for local_id, threat in entities["threats"].items():
            threat_payload = {
                "name": _first_non_empty(threat.get("name"), threat.get("threat_name"), local_id),
                "description": _first_non_empty(threat.get("description"), threat.get("details")),
                "creator_email": _first_non_empty(threat.get("creator_email"), creator_email),
            }
            result = _drm_post(api_base, "/threats", threat_payload, "threat", local_id)
            remote_ids["threats"][local_id] = result["id"] or local_id
            created["threats"] += 1

        for control_id, metric_id in _unique_pairs(payload.get("control_metric_mappings", [])):
            link_payload = {
                "control_id": remote_ids["controls"][control_id],
                "metric_id": remote_ids["metrics"][metric_id],
            }
            _drm_post(api_base, "/links/cm", link_payload, "control_metric")
            created["control_metric_links"] += 1

        for risk_id, threat_id, control_id in _unique_triplets(payload.get("risk_threat_control_mappings", [])):
            link_payload = {
                "risk_id": remote_ids["risks"][risk_id],
                "threat_id": remote_ids["threats"][threat_id],
                "control_id": remote_ids["controls"][control_id],
                "creator_email": creator_email,
            }
            _drm_post(api_base, "/links/rtc", link_payload, "risk_threat_control")
            created["risk_threat_control_links"] += 1

        return {
            "message": "Scheme synchronized to DRM using the COBALT DRM API.",
            "drm_api_base": api_base,
            "created": created,
            "remote_ids": remote_ids,
            "outbound_auth": [auth_context("drm")],
            "warnings": entities["warnings"],
        }, 200
    except DrmSyncError as exc:
        return {
            "error": "DRM sync failed",
            "path": exc.path,
            "drm_status": exc.status_code,
            "drm_response": exc.body,
            "created_before_failure": created,
            "outbound_auth": [auth_context("drm")],
        }, 502
    except Exception as exc:
        logging.error("DRM sync failed for scheme %s: %s", scheme_id, exc)
        return {"error": f"DRM sync failed: {str(exc)}"}, 502
