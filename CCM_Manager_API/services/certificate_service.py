import logging
import os
from copy import deepcopy
from datetime import datetime, timedelta
from uuid import uuid4

from db import certificates_col, schemes_col, toes_col
from services.assessment_service import PDF_OUTPUT_DIR, generate_certificate
from services.ledger import ledger_auth_context, send_to_ledger


VALID_EVALUATION_TYPES = {"MANUAL": "Manual", "DYNAMIC": "DYNAMIC"}
VALID_EVALUATION_RESULTS = {"OK", "NOK"}
ACTIVE_CERTIFICATE_STATES = {"INITIATE", "VALID", "SUSPENDED"}
INACTIVE_CERTIFICATE_STATES = {"WITHDRAWN", "ARCHIVED", "EXPIRED", "ARCHIVED/EXPIRED"}


def _payload_value(data, *keys):
    for key in keys:
        value = data.get(key)
        if value not in (None, ""):
            return value
    return None


def _certificate_response_doc(certificate):
    response_doc = deepcopy(certificate)
    if "_id" in response_doc:
        response_doc["_id"] = str(response_doc["_id"])
    return response_doc


def _certificate_ledger_payload(certificate):
    payload = deepcopy(certificate)
    payload.pop("_id", None)
    payload.pop("ledger_hash", None)
    return payload


def _generate_updated_certificate_pdf(certificate):
    cert_uuid = certificate["certification"]["certification_id"]
    pdf_filename = f"cobalt_certificate_{cert_uuid}.pdf"
    pdf_path = os.path.join(PDF_OUTPUT_DIR, pdf_filename)
    pdf_certificate = _certificate_response_doc(certificate)
    assessment = pdf_certificate.setdefault("certification", {}).setdefault("assessment", {})
    if not assessment.get("evidence"):
        assessment["evidence"] = ["N/A"]

    generate_certificate(
        {
            "status": "success",
            "message": "Certificate updated from evaluation result.",
            "assessment_hash": certificate.get("assessment_hash", "N/A"),
            "certificate": pdf_certificate,
        },
        pdf_path,
    )
    return pdf_path


def _parse_date(value):
    if not value:
        return None
    try:
        return datetime.strptime(str(value)[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def _normalized_certificate_state(certificate):
    raw_status = (
        certificate.get("certification", {})
        .get("certification_decision", {})
        .get("decision_status")
    )
    status = str(raw_status or "INITIATE").strip().upper()
    legacy_map = {
        "GRANTED": "VALID",
        "REVOKED": "WITHDRAWN",
    }
    return legacy_map.get(status, status)


def _certificate_is_non_expired(certificate):
    end_date = (
        certificate.get("certification", {})
        .get("certification_decision", {})
        .get("validity_period", {})
        .get("end_date")
    )
    parsed_end = _parse_date(end_date)
    if parsed_end is None:
        return True
    return parsed_end >= datetime.utcnow().date()


def _active_certificate_for_toe_scheme(toe_id, scheme_id):
    candidates = certificates_col.find(
        {
            "certification.target_of_evaluation.toe_uuid": str(toe_id),
            "certification.certification_scheme": str(scheme_id),
        },
        sort=[("_id", -1)],
    )
    for certificate in candidates:
        state = _normalized_certificate_state(certificate)
        if state in INACTIVE_CERTIFICATE_STATES:
            continue
        if state not in ACTIVE_CERTIFICATE_STATES:
            continue
        if not _certificate_is_non_expired(certificate):
            continue
        return certificate
    return None


def _next_certificate_state(current_state, evaluation_type_key, result):
    if result == "NOK":
        return "SUSPENDED"
    if current_state == "SUSPENDED":
        return "VALID"
    if current_state == "INITIATE" and evaluation_type_key == "DYNAMIC":
        return "VALID"
    if current_state == "INITIATE" and evaluation_type_key == "MANUAL":
        return "INITIATE"
    return "VALID"


def _build_initial_certificate(toe_record, scheme_id, evaluation):
    now = datetime.utcnow()
    valid_to = now + timedelta(days=365)
    toe_name = toe_record.get("name") or evaluation["toe_id"]

    return {
        "certification": {
            "certification_id": str(uuid4()),
            "name": f"Certificate for {toe_name}",
            "version": "1.0",
            "certification_scheme": scheme_id,
            "certifying_body": {
                "name": "COBALT Automated CA",
                "accreditation_id": "COBALT-ACC-001",
                "contact_info": {
                    "email": "ca@cobalt.eu",
                    "website": "https://cobalt.eu",
                },
            },
            "applicant": {
                "organization_name": "ToE Owner",
                "organization_id": "ORG-001",
                "contact_person": {"name": "Admin", "email": "admin@org.com"},
            },
            "target_of_evaluation": {
                "toe_name": toe_name,
                "toe_uuid": evaluation["toe_id"],
                "description": "Automated Certification via CCM Manager",
            },
            "certification_scope": {
                "environment": "Cloud",
                "deployment_model": "SaaS",
                "services_included": ["Core Service"],
            },
            "assessment": {
                "assessment_id": evaluation.get("assessment_id") or str(uuid4()),
                "assessment_date": now.strftime("%Y-%m-%d"),
                "assessment_result": evaluation["result"],
                "evaluation_type": evaluation["evaluation_type"],
                "evidence": [evaluation.get("evidence_id") or "N/A"],
            },
            "certification_decision": {
                "decision_date": now.strftime("%Y-%m-%d"),
                "decision_status": "INITIATE",
                "certification_level": "Basic",
                "validity_period": {
                    "start_date": now.strftime("%Y-%m-%d"),
                    "end_date": valid_to.strftime("%Y-%m-%d"),
                },
            },
            "certificate_issuance": {
                "certificate_serial": uuid4().hex,
                "issue_date": now.strftime("%Y-%m-%d"),
                "issued_by": "COBALT Automated CA",
            },
            "history": [
                {
                    "event": "Certificate created with INITIATE status from Manual evaluation OK",
                    "date": now.strftime("%Y-%m-%d"),
                }
            ],
        },
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "last_evaluation": evaluation,
    }


def list_certificates():
    certificates = list(certificates_col.find({}, {"_id": 0}))
    return {"count": len(certificates), "certificates": certificates}, 200


def get_certificate(cert_uuid):
    cert = certificates_col.find_one(
        {"certification.certification_id": cert_uuid},
        {"_id": 0},
    )
    if not cert:
        return {"error": "Certificate not found", "cert_uuid": cert_uuid}, 404
    return cert, 200


def get_certification_scheme(scheme_id):
    scheme = schemes_col.find_one({"uuid": scheme_id}, {"_id": 0})
    if not scheme:
        return {"error": "Certification Scheme not found"}, 404
    return scheme, 200


def get_certification_scheme_section(scheme_id, section):
    if section not in {"catalog", "profile"}:
        return {"error": "Unsupported certification scheme section"}, 400

    scheme = schemes_col.find_one({"uuid": scheme_id}, {"_id": 0, "uuid": 1, "content": 1})
    if not scheme:
        return {"error": "Certification Scheme not found"}, 404

    content = scheme.get("content") or {}
    section_payload = content.get(section)
    if not section_payload:
        return {
            "error": f"Certification Scheme does not contain {section}",
            "scheme_id": scheme_id,
        }, 404

    return {
        "scheme_id": scheme_id,
        "section": section,
        section: section_payload,
    }, 200


def get_certificate_scheme_section(cert_uuid, section):
    if section not in {"catalog", "profile"}:
        return {"error": "Unsupported certificate section"}, 400

    certificate = certificates_col.find_one(
        {"certification.certification_id": cert_uuid},
        {"_id": 0, "certification.certification_scheme": 1},
    )
    if not certificate:
        return {"error": "Certificate not found", "cert_uuid": cert_uuid}, 404

    scheme_id = (
        certificate.get("certification", {})
        .get("certification_scheme")
    )
    if not scheme_id:
        return {
            "error": "Certificate is not linked to a certification scheme",
            "cert_uuid": cert_uuid,
        }, 404

    payload, status_code = get_certification_scheme_section(scheme_id, section)
    if status_code != 200:
        payload["cert_uuid"] = cert_uuid
        return payload, status_code

    payload["cert_uuid"] = cert_uuid
    return payload, 200


def delete_certification_scheme(scheme_id):
    result = schemes_col.delete_one({"uuid": scheme_id})
    if result.deleted_count == 0:
        return {"error": "Certification Scheme not found"}, 404

    return {
        "message": "Certification Scheme deleted successfully",
        "uuid": scheme_id,
    }, 200


def list_certification_schemes():
    schemes = list(schemes_col.find({}, {"_id": 0}))
    return {"count": len(schemes), "schemes": schemes}, 200


def withdraw_certificate(cert_uuid):
    cert = certificates_col.find_one({"certification.certification_id": cert_uuid})
    if not cert:
        return {"error": "Certificate not found"}, 404

    current_status = cert.get("certification", {}).get("certification_decision", {}).get("decision_status")
    if current_status == "Withdrawn":
        return {"message": "Certificate is already withdrawn"}, 200

    update_result = certificates_col.update_one(
        {"certification.certification_id": cert_uuid},
        {
            "$set": {
                "certification.certification_decision.decision_status": "Withdrawn",
            },
            "$push": {
                "certification.history": {
                    "event": "Certificate Withdrawn",
                    "date": datetime.utcnow().strftime("%Y-%m-%d"),
                }
            },
        },
    )

    if update_result.modified_count == 1:
        return {"message": "Certificate state changed to withdrawn successfully"}, 200

    logging.error("Failed to update certificate status for %s", cert_uuid)
    return {"error": "Failed to update certificate status"}, 500


def update_certificate_evaluation_result(data):
    if not data:
        return {"error": "No JSON data provided"}, 400

    toe_id = _payload_value(data, "toe_id", "toe_uuid", "target_of_evaluation_id")
    scheme_id = _payload_value(data, "scheme_id", "certification_scheme_id", "certification_scheme")
    evaluation_type_raw = _payload_value(data, "evaluation_type", "evaluationType")
    result_raw = _payload_value(data, "result", "RESULT", "assessment_result", "assessmentResult")

    missing = [
        field
        for field, value in {
            "toe_id": toe_id,
            "scheme_id": scheme_id,
            "evaluation_type": evaluation_type_raw,
            "result": result_raw,
        }.items()
        if value is None
    ]
    if missing:
        return {"error": f"Missing required field(s): {', '.join(missing)}"}, 400

    evaluation_type_key = str(evaluation_type_raw).strip().upper()
    if evaluation_type_key not in VALID_EVALUATION_TYPES:
        return {"error": "evaluation_type must be Manual or DYNAMIC"}, 400
    evaluation_type = VALID_EVALUATION_TYPES[evaluation_type_key]

    result = str(result_raw).strip().upper()
    if result not in VALID_EVALUATION_RESULTS:
        return {"error": "result must be OK or NOK"}, 400

    toe_record = toes_col.find_one({"uuid": str(toe_id)})
    if not toe_record:
        return {"error": f"ToE {toe_id} is not registered in CCM Manager"}, 404

    scheme_record = schemes_col.find_one({"uuid": str(scheme_id)})
    if not scheme_record:
        return {"error": f"Certification Scheme {scheme_id} not found"}, 404

    if toe_record.get("linked_scheme_id") and toe_record.get("linked_scheme_id") != str(scheme_id):
        return {
            "error": "ToE is linked to a different certification scheme.",
            "toe_id": str(toe_id),
            "linked_scheme_id": toe_record.get("linked_scheme_id"),
            "requested_scheme_id": str(scheme_id),
        }, 409

    now = datetime.utcnow()
    today = now.strftime("%Y-%m-%d")
    timestamp = now.isoformat()
    evaluation = {
        "toe_id": str(toe_id),
        "scheme_id": str(scheme_id),
        "evaluation_type": evaluation_type,
        "result": result,
        "timestamp": timestamp,
    }
    evidence_id = _payload_value(data, "evidence_id", "evidenceId")
    if evidence_id:
        evaluation["evidence_id"] = str(evidence_id)

    certificate = _active_certificate_for_toe_scheme(toe_id, scheme_id)
    if certificate:
        return {
            "error": "An active certificate already exists for this ToE and scheme. Submit /assessment-result to update its state.",
            "toe_id": str(toe_id),
            "scheme_id": str(scheme_id),
            "certificate_id": certificate.get("certification", {}).get("certification_id"),
        }, 409

    if evaluation_type_key != "MANUAL" or result != "OK":
        return {
            "error": "Initial certificate creation requires evaluation_type Manual and result OK.",
            "toe_id": str(toe_id),
            "scheme_id": str(scheme_id),
            "evaluation_type": evaluation_type,
            "result": result,
        }, 409

    decision_status = "INITIATE"
    updated_certificate = _build_initial_certificate(toe_record, str(scheme_id), evaluation)
    certification = updated_certificate["certification"]
    updated_certificate["updated_at"] = timestamp
    updated_certificate["last_evaluation"] = {
        **evaluation,
        "previous_state": None,
        "decision_status": decision_status,
    }

    warnings = []
    try:
        cert_hash = send_to_ledger(
            "/v1/certification-authority/certificate",
            _certificate_ledger_payload(updated_certificate),
        )
    except Exception as exc:
        logging.warning("Ledger unavailable for certificate update, using placeholder hash: %s", exc)
        cert_hash = "TempHashDueToHotFix"
        warnings.append(f"Ledger unavailable for certificate update: {exc}")

    updated_certificate["ledger_hash"] = cert_hash
    certificates_col.insert_one(updated_certificate)

    pdf_path = None
    try:
        pdf_path = _generate_updated_certificate_pdf(updated_certificate)
    except Exception as exc:
        logging.error(
            "Failed to regenerate PDF for certificate %s: %s",
            certification.get("certification_id"),
            exc,
        )
        warnings.append(f"Failed to regenerate certificate PDF: {exc}")

    return {
        "message": "Certificate created from evaluation result and uploaded to DLT.",
        "toe_id": str(toe_id),
        "scheme_id": str(scheme_id),
        "evaluation_type": evaluation_type,
        "result": result,
        "operation": "created",
        "previous_state": None,
        "decision_status": decision_status,
        "certificate_id": certification.get("certification_id"),
        "ledger_hash": cert_hash,
        "pdf_path": pdf_path,
        "certificate": _certificate_response_doc(updated_certificate),
        "outbound_auth": [ledger_auth_context()],
        "warnings": warnings,
    }, 201


def update_certificate_from_assessment_result(data, assessment_hash=None):
    toe_id = data.get("target_of_evaluation_id")
    if not toe_id:
        return {"error": "target_of_evaluation_id missing in assessment"}, 400

    toe_record = toes_col.find_one({"uuid": str(toe_id)})
    if not toe_record:
        return {"error": f"ToE {toe_id} is not registered in CCM Manager"}, 404

    scheme_id = toe_record.get("linked_scheme_id")
    if not scheme_id:
        return {
            "error": "Configuration Error: This ToE is not linked to any Certification Scheme. Cannot update certificate state."
        }, 409

    scheme_record = schemes_col.find_one({"uuid": str(scheme_id)})
    if not scheme_record:
        return {"error": "Linked Certification Scheme not found in database"}, 404

    compliant = data.get("compliant")
    if compliant is True:
        result = "OK"
    elif compliant is False:
        result = "NOK"
    else:
        return {"error": "Assessment result must contain boolean compliant field"}, 400

    evaluation_type_raw = _payload_value(data, "evaluation_type", "evaluationType", "assessment_type")
    evaluation_type_key = str(evaluation_type_raw or "DYNAMIC").strip().upper()
    if evaluation_type_key not in VALID_EVALUATION_TYPES:
        return {"error": "evaluation_type must be Manual or DYNAMIC"}, 400
    evaluation_type = VALID_EVALUATION_TYPES[evaluation_type_key]

    certificate = _active_certificate_for_toe_scheme(toe_id, scheme_id)
    if not certificate:
        return {
            "error": "No active certificate exists for this ToE and scheme. Create it first with /certificate-evaluation-result.",
            "toe_id": str(toe_id),
            "scheme_id": str(scheme_id),
            "assessment_hash": assessment_hash,
        }, 404

    now = datetime.utcnow()
    today = now.strftime("%Y-%m-%d")
    timestamp = now.isoformat()
    previous_state = _normalized_certificate_state(certificate)
    decision_status = _next_certificate_state(previous_state, evaluation_type_key, result)

    evaluation = {
        "toe_id": str(toe_id),
        "scheme_id": str(scheme_id),
        "assessment_id": data.get("id"),
        "assessment_hash": assessment_hash,
        "evaluation_type": evaluation_type,
        "result": result,
        "compliant": compliant,
        "evidence_id": data.get("evidence_id"),
        "metric_id": data.get("metric_id"),
        "resource_id": data.get("resource_id"),
        "timestamp": timestamp,
    }

    updated_certificate = deepcopy(certificate)
    certification = updated_certificate.setdefault("certification", {})
    decision = certification.setdefault("certification_decision", {})
    history = certification.setdefault("history", [])

    decision["decision_date"] = today
    decision["decision_status"] = decision_status
    history.append({
        "event": f"Assessment result {result}: {previous_state} -> {decision_status}",
        "date": today,
    })

    updated_certificate["updated_at"] = timestamp
    updated_certificate["last_assessment_result"] = evaluation
    updated_certificate["last_evaluation"] = {
        **evaluation,
        "previous_state": previous_state,
        "decision_status": decision_status,
    }

    warnings = []
    try:
        cert_hash = send_to_ledger(
            "/v1/certification-authority/certificate",
            _certificate_ledger_payload(updated_certificate),
        )
    except Exception as exc:
        logging.warning("Ledger unavailable for certificate assessment update, using placeholder hash: %s", exc)
        cert_hash = "TempHashDueToHotFix"
        warnings.append(f"Ledger unavailable for certificate assessment update: {exc}")

    updated_certificate["ledger_hash"] = cert_hash
    certificates_col.replace_one({"_id": certificate["_id"]}, updated_certificate)

    pdf_path = None
    try:
        pdf_path = _generate_updated_certificate_pdf(updated_certificate)
    except Exception as exc:
        logging.error(
            "Failed to regenerate PDF for certificate %s: %s",
            certification.get("certification_id"),
            exc,
        )
        warnings.append(f"Failed to regenerate certificate PDF: {exc}")

    return {
        "message": "Certificate state updated from assessment result and uploaded to DLT.",
        "toe_id": str(toe_id),
        "scheme_id": str(scheme_id),
        "assessment_hash": assessment_hash,
        "evaluation_type": evaluation_type,
        "result": result,
        "operation": "updated",
        "previous_state": previous_state,
        "decision_status": decision_status,
        "certificate_id": certification.get("certification_id"),
        "ledger_hash": cert_hash,
        "pdf_path": pdf_path,
        "certificate": _certificate_response_doc(updated_certificate),
        "outbound_auth": [ledger_auth_context()],
        "warnings": warnings,
    }, 200
