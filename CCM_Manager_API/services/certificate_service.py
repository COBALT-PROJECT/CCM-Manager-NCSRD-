import logging
from datetime import datetime

from db import certificates_col, schemes_col


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
