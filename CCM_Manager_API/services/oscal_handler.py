import hashlib
import json
from uuid import uuid4
from flask import jsonify

class OscalHandler:
    def __init__(self, collection):
        self.collection = collection

    def handle_upload(self, request):
        try:
            oscal_json = self._parse_request(request)
            oscal_type, doc_uuid = self._identify_type(oscal_json)

            doc_hash = self._generate_hash(oscal_json)

            if oscal_type in ["catalog", "profile"]:
                return self._handle_catalog_or_profile(doc_uuid, oscal_type, oscal_json, doc_hash)
            else:
                return self._handle_other_types(doc_uuid, oscal_type, oscal_json, doc_hash)

        except ValueError as ve:
            return jsonify({"error": str(ve)}), 400
        except Exception as e:
            return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

    def _parse_request(self, request):
        if request.is_json:
            return request.get_json()
        elif 'file' in request.files:
            return json.load(request.files['file'])
        raise ValueError("No JSON data or file provided.")

    def _identify_type(self, data):
        if "component-definition" in data:
            return "component-definition", str(uuid4())
        elif "catalog" in data and "uuid" in data["catalog"]:
            return "catalog", data["catalog"]["uuid"]
        elif "profile" in data and "uuid" in data["profile"]:
            return "profile", data["profile"]["uuid"]
        else:
            raise ValueError("Unrecognized OSCAL type or missing UUID.")

    def _handle_catalog_or_profile(self, uuid, oscal_type, oscal_json, doc_hash):
        existing = self.collection.find_one({"uuid": uuid})
        if existing:
            if oscal_type in existing:
                return jsonify({
                    "message": f"Duplicate {oscal_type} already exists for this UUID.",
                    "uuid": uuid
                }), 200

            self.collection.update_one(
                {"uuid": uuid},
                {"$set": {
                    oscal_type: oscal_json,
                    f"{oscal_type}_hash": doc_hash
                }}
            )
            return jsonify({
                "message": f"{oscal_type} added to existing UUID.",
                "uuid": uuid
            }), 200

        self.collection.insert_one({
            "uuid": uuid,
            oscal_type: oscal_json,
            f"{oscal_type}_hash": doc_hash
        })
        return jsonify({
            "message": f"{oscal_type} document saved successfully.",
            "uuid": uuid
        }), 200

    def _handle_other_types(self, uuid, oscal_type, oscal_json, doc_hash):
        existing = self.collection.find_one({"oscal_type": oscal_type, "hash": doc_hash})
        if existing:
            return jsonify({
                "message": "Duplicate document already exists.",
                "uuid": existing["uuid"]
            }), 200

        self.collection.insert_one({
            "uuid": uuid,
            "hash": doc_hash,
            "oscal_type": oscal_type,
            "content": oscal_json
        })
        return jsonify({
            "message": f"{oscal_type} document saved successfully.",
            "uuid": uuid
        }), 200

    @staticmethod
    def _generate_hash(data):
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
