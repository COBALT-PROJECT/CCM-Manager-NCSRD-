import uuid
import logging
from flask import jsonify

class SaaSBomHandler:
    def __init__(self, collection):
        self.collection = collection

    def handle_upload(self, saasbom_json):
        if saasbom_json.get("bomFormat") != "CycloneDX":
            return jsonify({"error": "'bomFormat' must be 'CycloneDX'."}), 400

        if saasbom_json.get("specVersion") != "1.4":
            return jsonify({"error": "'specVersion' must be '1.4'."}), 400

        if "serialNumber" not in saasbom_json:
            saasbom_json["serialNumber"] = f"urn:uuid:{str(uuid.uuid4())}"
        elif not self._is_valid_uuid(saasbom_json["serialNumber"]):
            return jsonify({"error": "'serialNumber' must be a valid 'urn:uuid'."}), 400

        if not isinstance(saasbom_json.get("version"), int):
            return jsonify({"error": "'version' must be an integer."}), 400

        metadata = saasbom_json.get("metadata", {})
        if "component" not in metadata:
            return jsonify({"error": "Missing 'component' in 'metadata'."}), 400

        services = saasbom_json.get("services")
        if not isinstance(services, list) or not services:
            return jsonify({"error": "Missing or invalid 'services' field — not a SaaSBOM."}), 400

        has_saasbom_indicators = any(
            isinstance(s, dict) and "data" in s and "x-trust-boundary" in s for s in services
        )
        if not has_saasbom_indicators:
            return jsonify({
                "error": "Service entries must contain 'data' and 'x-trust-boundary' — likely not a SaaSBOM."
            }), 400

        try:
            result = self.collection.insert_one(saasbom_json)
            logging.info(f"Document inserted with ID: {result.inserted_id}")
        except Exception as e:
            return jsonify({"error": f"Error inserting into database: {e}"}), 500

        return jsonify({
            "message": "SaaSBOM saved successfully.",
            "serialNumber": saasbom_json["serialNumber"]
        }), 200

    def _is_valid_uuid(self, value):
        if not isinstance(value, str) or not value.startswith("urn:uuid:"):
            return False
        try:
            uuid.UUID(value.replace("urn:uuid:", ""))
            return True
        except ValueError:
            return False
