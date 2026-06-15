import logging
import os
from datetime import datetime
from uuid import uuid4

from auth import auth_context, authed_request
from db import cm_col, controls_col, metrics_col, risks_col, rtc_col, schemes_col, threats_col
from services.ledger import ledger_auth_context, send_to_ledger


INVALID_REFERENCE_VALUES = {"", "N/A", "NA", "NONE", "NULL"}


def _is_real_reference(value):
    if value is None:
        return False
    return str(value).strip().upper() not in INVALID_REFERENCE_VALUES


def _unwrap_oscal_section(value, key):
    if isinstance(value, dict) and isinstance(value.get(key), dict):
        return value[key]
    if isinstance(value, dict):
        return value
    return {}


def _ordered_unique(values):
    unique = []
    seen = set()

    for value in values:
        if not _is_real_reference(value):
            continue

        normalized = str(value).strip()
        if normalized not in seen:
            unique.append(normalized)
            seen.add(normalized)

    return unique


def _control_key(control):
    return (
        control.get("control_id")
        or control.get("oscal_id")
        or control.get("associated_control_requirement")
        or control.get("id")
    )


def _catalog_control_index(catalog):
    index = {}
    catalog = _unwrap_oscal_section(catalog, "catalog")

    def walk(node):
        for control in node.get("controls", []) or []:
            control_id = control.get("id")
            if _is_real_reference(control_id):
                index[str(control_id).strip()] = control

        for group in node.get("groups", []) or []:
            walk(group)

    walk(catalog)
    return index


def _control_statement(control):
    for part in control.get("parts", []) or []:
        if part.get("name") == "statement" and part.get("prose"):
            return part["prose"]

    for part in control.get("parts", []) or []:
        if part.get("prose"):
            return part["prose"]

    return ""


def _referenced_control_ids(certifiable_standards, risk_catalogue, controls_list):
    references = []

    for mapping in certifiable_standards:
        references.append(mapping.get("control_id"))

    for risk in risk_catalogue:
        references.extend(risk.get("mapped_controls") or [])

    for control in controls_list:
        references.append(_control_key(control))

    return _ordered_unique(references)


def _normalized_control_doc(control_id, scheme_id, timestamp, catalog_index, source_docs):
    catalog_control = catalog_index.get(control_id, {})
    source = source_docs.get(control_id, {})
    statement = _control_statement(catalog_control)

    doc = {
        **source,
        "scheme_id": scheme_id,
        "control_id": control_id,
        "oscal_id": control_id,
        "timestamp": timestamp,
    }

    if catalog_control.get("title"):
        doc["title"] = catalog_control["title"]
    if catalog_control.get("class"):
        doc["class"] = catalog_control["class"]
    if statement:
        doc["prose"] = statement
        doc.setdefault("description", statement)

    return doc


def _dedupe_mappings(mappings, fields):
    deduped = []
    seen = set()

    for mapping in mappings:
        key = tuple(str(mapping.get(field, "")).strip() for field in fields)
        if any(not _is_real_reference(value) for value in key) or key in seen:
            continue

        deduped.append({field: value for field, value in zip(fields, key)})
        seen.add(key)

    return deduped


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
    profile = _unwrap_oscal_section(data.get("profile") or scheme_meta.get("profile", {}), "profile")
    catalog = _unwrap_oscal_section(data.get("catalog") or scheme_meta.get("catalog", {}), "catalog")

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
        "certifiable_standards": certifiable_standards,
        "risk_catalogue": risk_catalogue,
        "controls_list": controls_list,
        "catalog": catalog,
    }


def upload_certification_scheme(data):
    if not data:
        return {"error": "No JSON data provided"}, 400

    sections = _scheme_sections(data)
    scheme_id = sections["scheme_id"]
    scheme_meta = sections["scheme_meta"]
    scheme_content = sections["scheme_content"]
    compliance_metrics = sections["compliance_metrics"]
    certifiable_standards = sections["certifiable_standards"]
    risk_catalogue = sections["risk_catalogue"]
    controls_list = sections["controls_list"]
    catalog = sections["catalog"]

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
                        "description": _threat_description(threat),
                        "associated_risk_id": threat.get("associated_risk_id", risk_id),
                        "scheme_id": scheme_id,
                        "timestamp": ts,
                    }
                    threats_col.update_one({"threat_id": threat_id}, {"$set": threat_doc}, upsert=True)
                    counts["threats"] += 1

        catalog_index = _catalog_control_index(catalog)
        control_sources = {}
        for mapping in certifiable_standards:
            control_id = mapping.get("control_id")
            if _is_real_reference(control_id):
                control_sources[str(control_id).strip()] = mapping
        for control in controls_list:
            control_id = _control_key(control)
            if _is_real_reference(control_id):
                control_sources[str(control_id).strip()] = control

        control_ids = _referenced_control_ids(
            certifiable_standards,
            risk_catalogue,
            controls_list,
        )
        for control_id in control_ids:
            control_doc = _normalized_control_doc(
                control_id,
                scheme_id,
                ts,
                catalog_index,
                control_sources,
            )
            controls_col.update_one(
                {"scheme_id": scheme_id, "control_id": control_id},
                {"$set": control_doc},
                upsert=True,
            )
            counts["controls"] += 1

        metric_to_control = {}
        for metric in compliance_metrics:
            metric_id = metric.get("id")
            associated_control = metric.get("associated_control", {})
            control_requirement = associated_control.get("associated_control_requirement")
            if metric_id and _is_real_reference(control_requirement):
                metric_to_control[metric_id] = str(control_requirement).strip()

        explicit_cm = data.get("control_metric_mappings", []) or scheme_meta.get("control_metric_mappings", [])
        if explicit_cm:
            cm_mappings = explicit_cm
        elif certifiable_standards:
            cm_mappings = [
                {
                    "control_id": mapping.get("control_id"),
                    "metric_id": mapping.get("metric_id"),
                }
                for mapping in certifiable_standards
            ]
        else:
            cm_mappings = [
                {"control_id": control_id, "metric_id": metric_id}
                for metric_id, control_id in metric_to_control.items()
            ]
        cm_mappings = _dedupe_mappings(cm_mappings, ("control_id", "metric_id"))

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

            controls = set(_ordered_unique(risk.get("mapped_controls") or []))
            if not controls:
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
        rtc_mappings = _dedupe_mappings(rtc_mappings, ("risk_id", "threat_id", "control_id"))

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


def _metric_control_ref(metric):
    associated_control = metric.get("associated_control")
    if not isinstance(associated_control, dict):
        return ""
    return _first_non_empty(
        associated_control.get("associated_control_requirement"),
        associated_control.get("control_id"),
        associated_control.get("id"),
    )


def _metric_control_doc(control_id, metric):
    associated_control = metric.get("associated_control")
    if not isinstance(associated_control, dict):
        associated_control = {}

    return {
        "control_id": control_id,
        "name": control_id,
        "description": _first_non_empty(
            associated_control.get("control_description"),
            associated_control.get("description"),
            metric.get("control_description"),
            metric.get("description"),
        ),
    }


def _risk_description(risk):
    name = _first_non_empty(risk.get("risk_name"), risk.get("name"))
    details = _first_non_empty(risk.get("risk_details"), risk.get("description"))
    if name and details and name != details:
        return f"{name} - {details}"
    return _first_non_empty(details, name)


def _threat_description(threat):
    return _first_non_empty(
        threat.get("threat_description"),
        threat.get("description"),
        threat.get("details"),
        threat.get("name"),
    )


def _mapped_metric_ids(risk):
    refs = []
    for mapped_metric in risk.get("mapped_metrics") or []:
        if isinstance(mapped_metric, dict):
            refs.append(
                _first_non_empty(
                    mapped_metric.get("metric_id"),
                    mapped_metric.get("external_metric_id"),
                    mapped_metric.get("id"),
                )
            )
        else:
            refs.append(mapped_metric)
    return _ordered_unique(refs)


def _mapped_threats(risk, threats_by_risk):
    mapped = risk.get("mapped_threats") or []
    if mapped:
        return mapped
    return threats_by_risk.get(_risk_ref(risk), [])


def _control_metric_pairs(export_payload):
    pairs = _unique_pairs(export_payload.get("control_metric_mappings", []))
    seen = set(pairs)

    for metric in export_payload.get("metrics", []) or []:
        metric_id = _metric_ref(metric)
        control_id = _metric_control_ref(metric)
        key = (control_id, metric_id)
        if all(key) and key not in seen:
            pairs.append(key)
            seen.add(key)

    return pairs


def _risk_threat_control_triplets(export_payload, control_metric_pairs):
    triplets = _unique_triplets(export_payload.get("risk_threat_control_mappings", []))
    seen = set(triplets)
    controls_by_metric = {}
    threats_by_risk = {}

    for control_id, metric_id in control_metric_pairs:
        controls_by_metric.setdefault(metric_id, []).append(control_id)

    for threat in export_payload.get("threats", []) or []:
        risk_id = _first_non_empty(threat.get("associated_risk_id"), threat.get("risk_id"))
        if risk_id:
            threats_by_risk.setdefault(risk_id, []).append(threat)

    for risk in export_payload.get("risks", []) or []:
        risk_id = _risk_ref(risk)
        if not risk_id:
            continue

        control_ids = set(_ordered_unique(risk.get("mapped_controls") or []))
        for metric_id in _mapped_metric_ids(risk):
            control_ids.update(controls_by_metric.get(metric_id, []))

        for threat in _mapped_threats(risk, threats_by_risk):
            threat_id = _threat_ref(threat) if isinstance(threat, dict) else _first_non_empty(threat)
            for control_id in control_ids:
                key = (risk_id, threat_id, control_id)
                if all(key) and key not in seen:
                    triplets.append(key)
                    seen.add(key)

    return triplets


def _prepare_drm_entities(export_payload, control_metric_pairs=None, risk_threat_control_triplets=None):
    control_metric_pairs = control_metric_pairs or _control_metric_pairs(export_payload)
    risk_threat_control_triplets = (
        risk_threat_control_triplets
        if risk_threat_control_triplets is not None
        else _risk_threat_control_triplets(export_payload, control_metric_pairs)
    )
    metrics = _dedupe_by_ref(export_payload.get("metrics", []), _metric_ref)
    controls = _dedupe_by_ref(export_payload.get("controls", []), _control_ref)
    risks = _dedupe_by_ref(export_payload.get("risks", []), _risk_ref)
    threats = _dedupe_by_ref(export_payload.get("threats", []), _threat_ref)
    mapped_threat_sources = {}
    warnings = []

    for risk in export_payload.get("risks", []) or []:
        for threat in risk.get("mapped_threats") or []:
            if not isinstance(threat, dict):
                continue
            threat_id = _threat_ref(threat)
            if threat_id and threat_id not in mapped_threat_sources:
                mapped_threat_sources[threat_id] = threat

    for metric in export_payload.get("metrics", []) or []:
        metric_id = _metric_ref(metric)
        control_id = _metric_control_ref(metric)
        if not all((metric_id, control_id)) or control_id in controls:
            continue

        controls[control_id] = _metric_control_doc(control_id, metric)
        warnings.append(
            f"Control '{control_id}' was created from metric '{metric_id}' associated_control."
        )

    for control_id, metric_id in control_metric_pairs:
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

    for risk_id, threat_id, control_id in risk_threat_control_triplets:
        if risk_id not in risks:
            risks[risk_id] = {
                "risk_id": risk_id,
                "risk_name": risk_id,
                "risk_details": "Created from CCM risk-threat-control mapping.",
            }
            warnings.append(f"Risk '{risk_id}' was missing from export risks and was synthesized.")
        if threat_id not in threats:
            threat_source = mapped_threat_sources.get(threat_id, {})
            threats[threat_id] = {
                "threat_id": threat_id,
                "name": _first_non_empty(threat_source.get("name"), threat_source.get("threat_name"), threat_id),
                "description": _first_non_empty(
                    _threat_description(threat_source),
                    "Created from CCM risk-threat-control mapping.",
                ),
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
    control_metric_pairs = _control_metric_pairs(payload)
    risk_threat_control_triplets = _risk_threat_control_triplets(payload, control_metric_pairs)
    entities = _prepare_drm_entities(payload, control_metric_pairs, risk_threat_control_triplets)

    admin_email = _first_non_empty(
        scheme.get("scheme_admin_email"),
        os.getenv("DRM_SCHEME_ADMIN_EMAIL"),
        os.getenv("DRM_CREATOR_EMAIL"),
        "ccm@cobalt.eu",
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
                "description": _first_non_empty(
                    control.get("description"),
                    control.get("control_description"),
                    control.get("details"),
                ),
            }
            result = _drm_post(api_base, "/controls", control_payload, "control", local_id)
            remote_ids["controls"][local_id] = result["id"] or local_id
            created["controls"] += 1

        for control_id, metric_id in control_metric_pairs:
            link_payload = {
                "control_id": remote_ids["controls"][control_id],
                "metric_id": remote_ids["metrics"][metric_id],
            }
            _drm_post(api_base, "/links/cm", link_payload, "control_metric")
            created["control_metric_links"] += 1

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

        for local_id, risk in entities["risks"].items():
            risk_payload = {
                "scheme_id": drm_scheme_id,
                "name": _first_non_empty(risk.get("risk_id"), risk.get("name"), local_id),
                "description": _risk_description(risk),
                "creator_email": _first_non_empty(risk.get("creator_email"), creator_email),
            }
            result = _drm_post(api_base, "/risks", risk_payload, "risk", local_id)
            remote_ids["risks"][local_id] = result["id"] or local_id
            created["risks"] += 1

        for local_id, threat in entities["threats"].items():
            threat_payload = {
                "name": _first_non_empty(threat.get("name"), threat.get("threat_name"), local_id),
                "description": _threat_description(threat),
                "creator_email": _first_non_empty(threat.get("creator_email"), creator_email),
            }
            result = _drm_post(api_base, "/threats", threat_payload, "threat", local_id)
            remote_ids["threats"][local_id] = result["id"] or local_id
            created["threats"] += 1

        for risk_id, threat_id, control_id in risk_threat_control_triplets:
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
