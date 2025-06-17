from flask import Flask, jsonify, request
from flask import Blueprint as Blueprint
from pymongo import MongoClient
import os
import logging
from datetime import datetime
from dotenv import load_dotenv
import json
import time
import hashlib
from uuid import uuid4
import requests
from flask_cors import CORS
from config import Config as Config
from services.sbom_generator import SBOMGenerator
from services.cbom_generator import CbomGenerator
from services.cbom_request_handler import CBOMRequestHandler
from services.oscal_handler import OscalHandler
from services.saasbom_handler import SaaSBomHandler
from services.chain_trigger import ChainTriggerService
from services.sdt_sender import SdtSenderService

app = Flask(__name__)
CORS(app)
# Configuration settings
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit to 16 MB
client: MongoClient = MongoClient('mongodb://localhost:27017/')
db = client.mydatabase
collection = db.mycollection
counters = db.counters_ledger
load_dotenv()


os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(Config.TMP_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = Config.UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt'}
FORWARD_URL = os.getenv("FORWARD_URL")
# Set up detailed logging
logging.basicConfig(level=logging.DEBUG)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return jsonify({"message": "Flask API with MongoDB is running"})

generate_sbom_bp = Blueprint('generate_sbom', __name__)

# Define a route for generating an SBOM via a POST request
@generate_sbom_bp.route('/generate_sbom', methods=['POST'])
def generate_sbom():
    try:
        # Retrieve the folder path from the incoming form data
        folder_path = request.form.get('folder')

        # If the folder path is not provided, return a 400 Bad Request response
        if not folder_path:
            return jsonify({"error": "No folder path provided"}), 400

        # Instantiate the SBOM generator with the provided folder path
        generator = SBOMGenerator(folder_path)

        # Run the generator to create the SBOM; get the output file path
        sbom_path = generator.run()

        # Return a success message along with the path to the generated SBOM
        return jsonify({
            "message": "SBOM generated, project created, and vulnerabilities saved.",
            "sbom_file": sbom_path
        }), 200

    # Handle specific expected exceptions with appropriate HTTP status codes
    except ValueError as ve:
        logging.error(ve)
        return jsonify({"error": str(ve)}), 400  # Bad Request

    except FileNotFoundError as fnf:
        logging.error(fnf)
        return jsonify({"error": str(fnf)}), 404  # Not Found

    except RuntimeError as re:
        logging.error(re)
        return jsonify({"error": str(re)}), 500  # Internal Server Error

    # Catch-all for any other unhandled exceptions
    except Exception as e:
        logging.exception("Unexpected error")  # Log full traceback for debugging
        return jsonify({
            "error": "Internal server error",
            "details": str(e)
        }), 500

# Define a route to retrieve stored vulnerabilities via a GET request
@app.route('/show_vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    try:
        # Fetch all documents from the collection, excluding the MongoDB "_id" field
        vulnerabilities = list(collection.find({}, {'_id': 0}))

        # If any vulnerabilities are found, return them with a 200 OK response
        if vulnerabilities:
            return jsonify(vulnerabilities), 200
        else:
            # Return a 404 Not Found if the list is empty
            return jsonify({"message": "No vulnerabilities found"}), 404

    # Catch and log any unexpected errors, then return a 500 Internal Server Error
    except Exception as e:
        logging.error(f"An error occurred while fetching vulnerabilities: {e}")
        return jsonify({"error": "Internal server error"}), 500

cbom_generator = CbomGenerator(collection, app.config['UPLOAD_FOLDER'])

# Define a route to handle CBOM generation via a POST request
@app.route('/generate_cbom', methods=['POST'])
def generate_cbom():
    try:
        # Get the hashed IP address from the form data
        hashed_ip = request.form.get('hashed_ip')
        if not hashed_ip:
            return jsonify({"error": "hashed_ip is required"}), 400  # Bad Request

        # Ensure a file is included in the request
        if 'file' not in request.files:
            return jsonify({"error": "No file part in the request."}), 400

        file = request.files['file']

        # Check if the file was selected (filename not empty)
        if file.filename == '':
            return jsonify({"error": "No selected file."}), 400

        # Delegate processing to the CBOM generator
        response, error, status_code = cbom_generator.process_request(file, hashed_ip)

        # If an error occurred during processing, return it with the appropriate status code
        if error:
            return jsonify(error), status_code

        # If processing succeeded, return the response and status
        return jsonify(response), status_code

    # Catch and log any unexpected errors, then return a generic 500 Internal Server Error
    except Exception as e:
        logging.error(f"Error in generate_cbom: {str(e)}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

# Define a route to receive CBOM processing output via POST request
@app.route('/receive_output', methods=['POST'])
def receive_output():
    # Initialize the CBOM generator with the MongoDB collection and upload folder path
    cbom_generator = CbomGenerator(collection=collection, upload_folder=app.config['UPLOAD_FOLDER'])

    # Create a request handler for CBOM-related operations
    handler = CBOMRequestHandler(cbom_generator, app.config['UPLOAD_FOLDER'])

    # Delegate the request handling to the CBOM request handler
    return handler.handle_request(request)
    
# Define a route to handle OSCAL file uploads via POST request
@app.route('/upload_oscal', methods=['POST'])
def upload_oscal():
    # Initialize the OSCAL handler with the MongoDB collection
    handler = OscalHandler(collection=collection)

    # Delegate the upload handling to the OSCAL handler
    return handler.handle_upload(request)

# Define a route to retrieve control IDs from an OSCAL profile by document UUID
@app.route('/oscal_ids/<doc_uuid>', methods=['GET'])
def get_oscal_ids_by_doc_uuid(doc_uuid):
    # Query the MongoDB collection for a document matching the given UUID
    doc = collection.find_one({"uuid": doc_uuid})

    # If the document is not found or does not have the expected structure, return 404
    if not doc or "content" not in doc or "profile" not in doc["content"]:
        return jsonify({"error": "Profile not found"}), 404

    control_ids = []

    # Extract the list of imports from the profile
    imports = doc["content"]["profile"].get("imports", [])

    # Iterate through each import and collect control IDs from "include-controls"
    for imp in imports:
        for control in imp.get("include-controls", []):
            control_ids.extend(control.get("with-ids", []))

    # Return the list of unique control IDs
    return jsonify({"control_ids": list(set(control_ids))}), 200

# Define a route to handle SaaSBOM uploads via a POST request
@app.route('/upload_saasbom', methods=['POST'])
def upload_saasbom():
    # Ensure the request contains JSON data
    if not request.is_json:
        return jsonify({"error": "No JSON data provided."}), 400  # Bad Request

    # Parse the JSON payload from the request
    saasbom_json = request.get_json()

    # Initialize the SaaSBOM handler with the MongoDB collection
    handler = SaaSBomHandler(collection)

    # Delegate the upload processing to the handler
    return handler.handle_upload(saasbom_json)

# Define a route to upload a TOE (Target of Evaluation) descriptor via POST request
@app.route("/upload_toe_descriptor", methods=["POST"])
def upload_toe_descriptor():
    # Parse the incoming JSON payload
    data = request.get_json()

    # Validate that JSON payload exists
    if not data:
        return jsonify({"error": "No JSON payload provided"}), 400

    # Extract and validate the 'component' section
    oscal_component = data.get("component")
    if not oscal_component:
        return jsonify({"error": "Missing 'component' in payload"}), 400

    # Extract and validate the 'component-definition' section inside 'component'
    component_definition = oscal_component.get("component-definition")
    if not component_definition:
        return jsonify({"error": "Missing 'component-definition' in 'component'"}), 400

    # Get the list of components from the component-definition
    components = component_definition.get("components", [])
    if not components:
        return jsonify({"error": "No components found in 'component-definition'"}), 400

    # For now, only the first component is considered
    component = components[0]

    # Extract required fields: uuid and title (renamed as toe_id and name)
    toe_id = component.get("uuid")
    name = component.get("title")

    if not toe_id or not name:
        return jsonify({"error": "Missing 'toeId' (uuid) or 'name' (title) in 'components'"}), 400

    # Optional section: bills-of-material
    bills_of_material = data.get("bills-of-material", {})
    if not bills_of_material:
        print("Optional 'bills-of-material' section missing, proceeding without it.")

    # Optionally extract individual sub-documents from bills-of-material
    sbom = bills_of_material.get("sbom")
    vex = bills_of_material.get("vex")
    cbom = bills_of_material.get("cbom")
    saasbo = bills_of_material.get("saasbo")

    # Warn if any optional sub-sections are missing
    if not sbom or not vex or not cbom or not saasbo:
        print("Some optional sub-sections in 'bills-of-material' are missing.")

    # Optional MUD section
    mud = data.get("mud", {})
    if not mud:
        print("Optional 'mud' section missing, proceeding without it.")

    # Optional threat-MUD section
    threat_mud = data.get("threat-mud", {})
    if not threat_mud:
        print("Optional 'threat-mud' section missing, proceeding without it.")

    # Try to forward the full payload to another service
    try:
        response = requests.post(FORWARD_URL, json=data)
        response.raise_for_status()  # Raise an error for HTTP failure codes
    except requests.RequestException as e:
        return jsonify({"error": "Failed to forward data", "details": str(e)}), 502  # Bad Gateway

    # Return success response with forwarding status
    return jsonify({
        "status": "Descriptor received and forwarded successfully",
        "forward_status": response.status_code
    }), 200

# Define a route to handle Certification Scheme uploads via POST request
@app.route("/upload_certification_scheme", methods=["POST"])
def upload_certification_scheme():
    # Parse the incoming JSON payload
    data = request.get_json()

    # Validate the presence of the 'certificationScheme' object
    if "certificationScheme" not in data:
        return jsonify({"error": "'certificationScheme' object is missing in the request"}), 400

    # Extract the certification scheme data
    scheme = data["certificationScheme"]

    # Define required fields that must be present in the scheme
    required_fields = ["id", "complianceMetrics", "controls", "boundaryConditions", "productProfile"]

    # Check for missing required fields
    if not all(field in scheme for field in required_fields):
        return jsonify({"error": "Missing required fields in Certification Scheme"}), 400

    # Tag the type and compute a hash of the scheme for integrity tracking
    scheme["type"] = "certification_scheme"
    scheme["hash"] = generate_json_hash(scheme)

    scheme_id = scheme["id"]

    # Check if a document with this scheme ID already exists
    existing = collection.find_one({"$or": [
        {"uuid": scheme_id},
        {"certificationScheme.id": scheme_id}
    ]})

    if existing:
        # If exists, update the existing document with new data and hashes
        updated_doc = {
            "uuid": scheme_id,
            "certificationScheme": scheme,
            "certificationScheme_hash": scheme["hash"]
        }

        # Optionally update profile and its hash
        if "profile" in data:
            updated_doc["profile"] = data["profile"]
            updated_doc["profile_hash"] = generate_json_hash(data["profile"])

        # Optionally update catalog and its hash
        if "catalog" in data:
            updated_doc["catalog"] = data["catalog"]
            updated_doc["catalog_hash"] = generate_json_hash(data["catalog"])

        # Apply the update to the collection
        collection.update_one(
            {"uuid": scheme_id},
            {"$set": updated_doc}
        )

        # Return success response
        return jsonify({
            "message": "Certification Scheme and related documents updated successfully.",
            "uuid": scheme_id
        }), 200

    else:
        # If no existing document, prepare a new document for insertion
        new_doc = {
            "uuid": scheme_id,
            "certificationScheme": scheme,
            "certificationScheme_hash": scheme["hash"]
        }

        # Optionally add profile and its hash
        if "profile" in data:
            new_doc["profile"] = data["profile"]
            new_doc["profile_hash"] = generate_json_hash(data["profile"])

        # Optionally add catalog and its hash
        if "catalog" in data:
            new_doc["catalog"] = data["catalog"]
            new_doc["catalog_hash"] = generate_json_hash(data["catalog"])

        # Insert the new document into the collection
        result = collection.insert_one(new_doc)

        # Return success response with the inserted document ID
        return jsonify({
            "message": "Certification Scheme saved successfully with related documents.",
            "uuid": result.inserted_id
        }), 200

def generate_json_hash(data):
    normalized = json.dumps(data, sort_keys=True)
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()

# Define a route to store a component ledger entry via POST request
@app.route('/store-ledger', methods=['POST'])
def store_ledger_entry():
    # Parse the incoming JSON payload (force=True allows parsing even without 'Content-Type: application/json')
    oscal_json = request.get_json(force=True)

    # Extract the 'component-definition' section and validate its presence
    component_def = oscal_json.get("component-definition")
    if not component_def:
        return jsonify({"error": "Missing 'component-definition' section."}), 400

    # Generate a unique identifier for the wrapper document
    wrapper_uuid = str(uuid4())

    # Compute a hash of the entire JSON payload for integrity verification
    content_hash = generate_json_hash(oscal_json)

    # Wrap the document with metadata (type, hash, timestamp, etc.)
    wrapped_doc = {
        "type": "ccm_ledger",  # Label the document for classification
        "headers": {
            "uuid": wrapper_uuid,                # Unique ID for this ledger entry
            "hash": content_hash,                # Integrity hash of the content
            "timestamp": datetime.utcnow().isoformat()  # Record the time of entry (UTC)
        },
        "oscal_component": {
            "ref": wrapper_uuid,                # Reference to the document UUID
            "component-definition": component_def  # Include the actual component definition
        }
    }

    # Store the wrapped ledger entry in the MongoDB collection
    collection.insert_one(wrapped_doc)

    # Return a success response with the UUID and hash
    return jsonify({
        "message": "Stored",
        "uuid": wrapper_uuid,
        "hash": content_hash
    }), 201  # HTTP 201 Created

# Define a route to update an existing CCM ledger entry by UUID via PUT request
@app.route('/update-ledger/<uuid>', methods=['PUT'])
def update_ledger_entry(uuid):
    # Parse the incoming JSON payload (force=True ensures parsing even if headers are incorrect)
    oscal_json = request.get_json(force=True)

    # Generate a new hash for the updated component-definition to track changes
    new_hash = generate_json_hash(oscal_json)

    # Attempt to update the matching document based on UUID and type
    result = collection.update_one(
        {"headers.uuid": uuid, "type": "ccm_ledger"},  # Match criteria
        {"$set": {
            "oscal_component.component-definition": oscal_json.get("component-definition"),  # Update the definition
            "headers.hash": new_hash,               # Update the hash to reflect the new content
            "headers.timestamp": datetime.utcnow().isoformat()  # Update the timestamp
        }}
    )

    # If no document matched, return a 404 Not Found response
    if result.matched_count == 0:
        return jsonify({"error": "Entry not found"}), 404

    # Return success response with the UUID and new hash
    return jsonify({
        "message": "Ledger updated",
        "uuid": uuid,
        "hash": new_hash
    }), 200

# Define a route to send an SDT (Software Delivery Token) via POST request
@app.route("/send_sdt", methods=["POST"])
def send_sdt():
    # Parse the incoming JSON payload
    data = request.get_json()

    # Validate presence of 'hash' field in the request data
    if not data or "hash" not in data:
        return jsonify({"error": "Missing 'hash' in request body"}), 400

    # Extract the hash value from the request
    hash_value = data["hash"]

    # Initialize the service responsible for sending the SDT
    service = SdtSenderService(
        collection=collection,  # MongoDB collection for any required data operations
        file_path= os.getenv("SBOM"),  # Local path to the SBOM file
        deploy_host= os.getenv("HOST")  # Remote host to send the SDT
    )

    # Send the SDT using the service, receiving the result and HTTP status code
    result, status = service.send(hash_value)

    # Return the response from the service with the corresponding HTTP status
    return jsonify(result), status

# Define a route to trigger a delete action via POST request
@app.route('/trigger_delete', methods=['POST'])
def trigger_delete():
    # URL of the remote service that handles delete requests
    url = os.getenv("DELETE")
    
    # HTTP headers for the request specifying JSON content
    headers = {"Content-Type": "application/json"}
    
    # Payload containing the identifier to be deleted
    payload = {"identifier": "f5912dbc"}

    try:
        # Send a POST request to the remote delete endpoint
        response = requests.post(url, json=payload, headers=headers)
        
        # Return the status and body of the delete response to the client
        return jsonify({
            "message": "Triggered delete request",
            "delete_response_status": response.status_code,
            "delete_response_body": response.json()
        }), response.status_code

    except Exception as e:
        # Catch and return any exceptions as a 500 Internal Server Error
        return jsonify({"error": str(e)}), 500

ENDPOINTS = [
    os.getenv("ENDPOINT")
]

# Define a route to receive records and forward them to multiple endpoints
@app.route('/send_records', methods=['POST'])
def receive_and_forward():
    try:
        # Parse incoming JSON data from the request
        incoming_data = request.get_json()
        if not incoming_data:
            # Return 400 if JSON data is missing or invalid
            return jsonify({'error': 'Invalid or missing JSON'}), 400

        # Wrap the incoming data with additional metadata fields
        wrapped_doc = {
            "channel": "artifact",
            "smartContract": "artifactsc",
            "key": "test",
            "data": incoming_data
        }

        # Insert the wrapped document into the MongoDB collection
        collection.insert_one(wrapped_doc.copy())

        # Prepare HTTP headers for forwarding requests
        headers = {'Content-Type': 'application/json'}

        # Forward the wrapped document to each endpoint listed in ENDPOINTS
        for url in ENDPOINTS:
            try:
                requests.post(url, json=wrapped_doc, headers=headers, timeout=5)
            except requests.RequestException as e:
                # Log any failures in forwarding to individual endpoints
                print(f"Failed to forward to {url}: {e}")

        # Return success response after forwarding attempts
        return jsonify({'status': 'Success'}), 200

    except Exception as e:
        # Return 500 if any unexpected errors occur
        return jsonify({'error': str(e)}), 500
    
# POST endpoint to trigger a chain process using ChainTriggerService
@app.route('/trigger-chain', methods=['POST'])
def trigger_chain_post():
    # Initialize the service with counters and path to the SBOM file
    service = ChainTriggerService(
        counters, 
        '/home/stathis/Flask_API/sboms/sbom_20250516140023.json'
    )
    
    # Trigger the chain process and get the result
    result = service.trigger()
    
    # Return the JSON response and status code if result is a tuple,
    # otherwise return result with HTTP 200
    return jsonify(result[0]), result[1] if isinstance(result, tuple) else 200


# GET endpoint to simulate stopping the SDT manager
@app.route('/stop-sdt', methods=['GET'])
def stop_sdt():
    # Delay for 10 seconds to simulate shutdown or cleanup time
    time.sleep(10)
    
    # Print confirmation message to the console/log
    print("SDT manager has stopped")
    
    # Return a plain text response confirming the stop action
    return "SDT manager stopped", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)