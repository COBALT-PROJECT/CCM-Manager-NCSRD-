import json
import logging
import io
import hashlib
from flask import jsonify

class CBOMRequestHandler:
    def __init__(self, cbom_generator, upload_folder):
        self.cbom_generator = cbom_generator
        self.upload_folder = upload_folder

    def handle_request(self, request):
        try:
            hashed_ip = self._hash_ip(request.remote_addr)

            data = self._extract_data(request)
            if data is None:
                return jsonify({"error": "No valid input provided."}), 400

            file_like = io.StringIO(json.dumps(data))
            response_data, error, status_code = self.cbom_generator.process_request(file_like, hashed_ip)

            if error:
                return jsonify(error), status_code
            return jsonify(response_data), status_code

        except ValueError as ve:
            logging.warning(f"Validation error: {str(ve)}")
            return jsonify({"error": str(ve)}), 400

        except Exception as e:
            logging.exception("Error in CBOMRequestHandler")
            return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

    def _extract_data(self, request):
        if 'file' in request.files:
            uploaded_file = request.files['file']
            if not uploaded_file.filename.endswith('.json'):
                raise ValueError("Invalid file format. Only .json files are allowed.")
            try:
                return json.load(uploaded_file)
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON file.")
        
        elif request.is_json:
            return request.get_json()
        
        return None

    @staticmethod
    def _hash_ip(ip):
        """Hashes the IP address using SHA-256."""
        return hashlib.sha256(ip.encode('utf-8')).hexdigest()
