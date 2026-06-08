import json
import logging
import os
from datetime import datetime, timedelta
from uuid import uuid4

from jsonschema import validate

from db import certificates_col, collection, schemes_col, toes_col
from services.ledger import ledger_auth_context, send_to_ledger


SCHEMA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "schemas",
    "ASSESSMENT_SCHEMA.json",
)

with open(SCHEMA_PATH) as schema_file:
    ASSESSMENT_SCHEMA = json.load(schema_file)


def _build_certificate(data, toe_record, toe_id, scheme_id):
    cert_uuid = str(uuid4())
    now = datetime.utcnow()
    valid_to = now + timedelta(days=365)

    return {
        "certification": {
            "certification_id": cert_uuid,
            "name": f"Certificate for {toe_record.get('name')}",
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
                "toe_name": toe_record.get("name"),
                "toe_uuid": toe_id,
                "description": "Automated Certification via CCM Manager",
            },
            "certification_scope": {
                "environment": "Cloud",
                "deployment_model": "SaaS",
                "services_included": ["Core Service"],
            },
            "assessment": {
                "assessment_id": data.get("id"),
                "assessment_date": now.strftime("%Y-%m-%d"),
                "assessment_result": "PASS",
                "evidence": [data.get("evidence_id")],
            },
            "certification_decision": {
                "decision_date": now.strftime("%Y-%m-%d"),
                "decision_status": "Granted",
                "certification_level": "Basic",
                "validity_period": {
                    "start_date": now.strftime("%Y-%m-%d"),
                    "end_date": valid_to.strftime("%Y-%m-%d"),
                },
            },
            "certificate_issuance": {
                "certificate_serial": str(uuid4().hex),
                "issue_date": now.strftime("%Y-%m-%d"),
                "issued_by": "COBALT Automated CA",
            },
            "history": [
                {
                    "event": "Certificate Automatically Generated",
                    "date": now.strftime("%Y-%m-%d"),
                }
            ],
        }
    }


def process_assessment_result(data):
    if not data:
        return {"error": "Bad Request"}, 400

    try:
        validate(instance=data, schema=ASSESSMENT_SCHEMA)

        toe_id = data.get("target_of_evaluation_id")
        if not toe_id:
            return {"error": "target_of_evaluation_id missing in assessment"}, 400

        toe_record = toes_col.find_one({"uuid": toe_id})
        if not toe_record:
            return {"error": f"ToE {toe_id} is not registered in CCM Manager"}, 404

        scheme_id = toe_record.get("linked_scheme_id")
        if not scheme_id:
            return {
                "error": "Configuration Error: This ToE is not linked to any Certification Scheme. Cannot issue certificate."
            }, 409

        scheme_record = schemes_col.find_one({"uuid": scheme_id})
        if not scheme_record:
            return {"error": "Linked Certification Scheme not found in database"}, 404

        assessment_hash = send_to_ledger("/v1/manufacturer/ass-results", data)
        data["ledger_hash"] = assessment_hash
        collection.insert_one({
            "type": "assessment_result",
            "data": data,
            "timestamp": datetime.utcnow().isoformat(),
        })

        if data.get("compliant") is True:
            certificate_data = _build_certificate(data, toe_record, toe_id, scheme_id)
            cert_hash = send_to_ledger(
                "/v1/certification-authority/certificate",
                certificate_data,
            )
            certificate_data["ledger_hash"] = cert_hash

            certificates_col.insert_one(certificate_data)

            if "_id" in certificate_data:
                certificate_data["_id"] = str(certificate_data["_id"])

            return {
                "status": "success",
                "message": "Assessment processed and Certificate ISSUED.",
                "assessment_hash": assessment_hash,
                "certificate": certificate_data,
                "outbound_auth": [ledger_auth_context()],
            }, 201

        return {
            "status": "processed",
            "message": "Assessment processed but Non-Compliant. No Certificate issued.",
            "assessment_hash": assessment_hash,
            "outbound_auth": [ledger_auth_context()],
        }, 200

    except Exception as exc:
        logging.error("Error: %s", exc)
        return {"error": str(exc)}, 500
