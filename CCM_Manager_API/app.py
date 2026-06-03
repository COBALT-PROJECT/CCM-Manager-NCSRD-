from flask import Flask, jsonify, request
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from jsonschema import validate, ValidationError
import os
import json
import logging
import subprocess
from datetime import datetime, timedelta
from dotenv import load_dotenv
import uuid
import time
from algos_details import details # Assuming these local files exist
from generate_tree import handle_dynamic_path, Counter, build_tree
import networkx as nx
import re
import hashlib
from uuid import uuid4
import requests
from flask_cors import CORS 
from pymongo import ReturnDocument
import xml.etree.ElementTree as ET
try:
    from IdentityManagement import ComponentAuthClient, AuthError
except ImportError:
    ComponentAuthClient = None
    AuthError = Exception
    logging.warning("IdentityManagement not available (missing PyJWT?); auth disabled")

class Config:
    UPLOAD_FOLDER = './sboms'
    TMP_FOLDER = './tmp'

app = Flask(__name__)
CORS(app)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
load_dotenv()


# --- CONFIGURATION ---
# Centralize all config here. 
# NOTE: The default here is a fallback. Ideally, set these in your .env file.
MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017/")

# Use the hostname that works for your environment (e.g., the IP or the .local DNS)
LEDGER_BASE_URL = os.getenv("LEDGER_BASE_URL", "http://10.163.1.211:3000")
FORWARD_URL = os.getenv("FORWARD_URL", "http://orchestrator:3000/toe/register")

# Define specific Ledger endpoints based on the Base URL
LEDGER_SUBMIT_URL = f"{LEDGER_BASE_URL}/submit" # or whatever the specific endpoint is
# --- DATABASE SETUP ---
try:
    client = MongoClient(MONGO_URI)
    db = client.mydatabase
    collection = db.mycollection
    certificates_col = db.certificates
    schemes_col = db.schemes
    toes_col = db.toes
    risks_col = db.risks
    threats_col = db.threats
    metrics_col = db.metrics
    controls_col = db.controls
    rtc_col = db.risk_threat_control       # R↔T↔C triplets
    cm_col = db.control_metric             # C↔M mappings
    logging.info(f"Connected to MongoDB at {MONGO_URI}")
except Exception as e:
    logging.error(f"Failed to connect to MongoDB: {e}")

# --- COMPONENT AUTH CLIENT ---
_am_base = os.getenv("AM_BASE_URL", "")
_am_cid  = os.getenv("AM_CLIENT_ID", "")
_am_sec  = os.getenv("AM_CLIENT_SECRET", "")
_am_scope = os.getenv("AM_SCOPE", "digital_twins profile")
_am_verify = os.getenv("AM_VERIFY_TLS", "true").lower() in ("1", "true", "yes")

auth_client = None
if ComponentAuthClient is not None and _am_base and _am_cid and _am_sec:
    try:
        auth_client = ComponentAuthClient(
            base_url=_am_base,
            client_id=_am_cid,
            client_secret=_am_sec,
            default_scope=_am_scope,
            verify_tls=_am_verify,
        )
        logging.info(f"ComponentAuthClient initialized for {_am_cid} @ {_am_base}")
    except Exception as e:
        logging.warning(f"ComponentAuthClient init failed ({e}); running unauthenticated")
else:
    logging.warning("AM_BASE_URL / AM_CLIENT_ID / AM_CLIENT_SECRET not set; running unauthenticated")


def authed_request(method, url, **kwargs):
    """Route through ComponentAuthClient when available, raw requests otherwise."""
    if auth_client is not None:
        return auth_client.authenticated_request(method, url, **kwargs)
    return requests.request(method, url, **kwargs)


@app.route('/auth/status', methods=['GET'])
def auth_status():
    """Diagnostic endpoint — reports whether component auth is enabled, functional, and returns the token."""
    result = {
        "auth_enabled": auth_client is not None,
    }

    if auth_client is None:
        result["status"] = "disabled"
        return jsonify(result), 200

    try:
        # Retrieve the current active token (uses cached if valid, or fetches a new one)
        token = auth_client.get_token()
        result["status"] = "ok"
        result["active_token"] = token  # <-- Add this line to expose the token string
    except Exception as e:
        result["status"] = "token_error"
        result["details"] = str(e)

    return jsonify(result), 200

# Load ASSESSMENT_SCHEMA
with open(os.path.join(os.path.dirname(__file__), 'schemas', 'ASSESSMENT_SCHEMA.json')) as f:
    ASSESSMENT_SCHEMA = json.load(f)

# Helper: Generate Hash
def generate_json_hash(data):
    normalized = json.dumps(data, sort_keys=True)
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()

# Helper: Ledger Interaction
def send_to_ledger(endpoint, data):
    url = f"{LEDGER_BASE_URL}{endpoint}"
    # Swagger typically requires content as a stringified JSON inside a wrapper
    payload = {"content": json.dumps(data)}
    try:
        response = authed_request("POST", url, json=payload, timeout=10)
        response.raise_for_status()
        return response.json().get("hash")
    except requests.RequestException as e:
        logging.error(f"Ledger Error ({url}): {e}")
        # For development/testing, we might return a mock hash if ledger is down
        # return f"mock-hash-{uuid4()}" 
        raise e
ALLOWED_EXTENSIONS = {'json', 'txt', 'xml'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return jsonify({"message": "Flask API with MongoDB is running"})

@app.route('/data', methods=['POST'])
def insert_data():
    data = request.get_json()
    try:
        result = db.collection.insert_one(data)
        return jsonify({'status': 'success', 'id': str(result.inserted_id)}), 201
    except PyMongoError as e:
        return jsonify({'error': 'Database error', 'details': str(e)}), 500

@app.route('/generate_sbom', methods=['POST'])
def generate_sbom():
    try:
        # Ensure a folder path is provided in the request form data
        if 'folder' not in request.form:
            return jsonify({"error": "No folder path provided"}), 400

        folder_path = request.form['folder']
        
        # Check if the provided folder path exists
        if not os.path.isdir(folder_path):
            return jsonify({"error": f"The provided folder path does not exist: {folder_path}"}), 400

        # Logging provided folder path to check
        logging.debug(f"Searching for dependency files in the provided path: {folder_path}")

        # Initialize variables for the dependency file and language
        requirements_file = None
        language = None

        # Perform a strictly scoped search in the provided folder path
        for root, dirs, files in os.walk(folder_path):
            logging.debug(f"Checking directory: {root}")
            # Check for Java pom.xml
            if 'pom.xml' in files:
                requirements_file = os.path.join(root, 'pom.xml')
                language = 'java'
                logging.debug(f"Found Java pom.xml file at: {requirements_file}")
                break
            # Check for Python requirements.txt
            elif 'requirements.txt' in files:
                requirements_file = os.path.join(root, 'requirements.txt')
                language = 'python'
                logging.debug(f"Found Python requirements.txt file at: {requirements_file}")
                break
            # Check for Node.js package.json
            elif 'package.json' in files:
                requirements_file = os.path.join(root, 'package.json')
                language = 'nodejs'
                logging.debug(f"Found Node.js package.json file at: {requirements_file}")
                break

        # Return an error if no supported dependency file is found
        if not requirements_file:
            return jsonify({"error": "No recognized dependency file found in the provided folder or subdirectories."}), 400

        # Generate SBOM JSON file path
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        sbom_filepath = os.path.abspath(os.path.join(Config.UPLOAD_FOLDER, f'sbom_{timestamp}.json'))


        # Generate the SBOM based on the language type
        if language == 'python':
            subprocess.run(['./generate_sbom.sh', requirements_file, timestamp], check=True)
        elif language in ('nodejs', 'java'):
            # Set the directory to where the dependency file is located
            cwd = os.path.dirname(requirements_file)
            
            # Run cdxgen with the appropriate working directory
            result = subprocess.run(
                ['cdxgen', '-f', requirements_file, '-o', sbom_filepath],
                cwd=cwd,  # Set the working directory for the command
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                logging.error(f"Error generating SBOM with cdxgen: {result.stderr}")
                return jsonify({
                    "error": "Failed to generate SBOM",
                    "details": result.stderr,
                    "stdout": result.stdout
                }), 500

        # Verify if the SBOM file was actually created
        if not os.path.exists(sbom_filepath):
            return jsonify({"error": "Failed to generate SBOM"}), 500

        # Run the project creation script and pass the SBOM file path
        logging.debug(f"SBOM generated at: {sbom_filepath}")
        result = subprocess.run(
            ['./create_project.sh', sbom_filepath],
            capture_output=True,
            text=True,
            env={**os.environ}
        )

        logging.debug(f"Create project script return code: {result.returncode}")
        logging.debug(f"Create project script output: {result.stdout}")
        logging.error(f"Create project script stderr: {result.stderr}")

        if result.returncode != 0:
            return jsonify({
                "error": "Failed to create project",
                "details": result.stderr,
                "stdout": result.stdout
            }), 500

        # Retrieve and read the VEX JSON file
        vex_files = sorted([f for f in os.listdir(Config.UPLOAD_FOLDER) if f.startswith('vex_') and f.endswith('.json')], reverse=True)
        if vex_files:
            vex_filepath = os.path.join(Config.UPLOAD_FOLDER, vex_files[0])
            with open(vex_filepath, 'r') as vex_file:
                vex_data = json.load(vex_file)

            # Save the VEX data in MongoDB
            collection.insert_one({
                'sbom_filepath': sbom_filepath,
                'vulnerabilities': vex_data
            })

            return jsonify({"message": "SBOM generated, project created, and vulnerabilities saved successfully", "sbom_file": sbom_filepath}), 200
        else:
            return jsonify({"error": "Failed to retrieve vulnerabilities"}), 500

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/show_vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    try:
        # Fetch all vulnerabilities from the MongoDB collection
        vulnerabilities = list(collection.find({}, {'_id': 0}))  # Exclude the MongoDB ID field

        if vulnerabilities:
            return jsonify(vulnerabilities), 200
        else:
            return jsonify({"message": "No vulnerabilities found"}), 404

    except Exception as e:
        logging.error(f"An error occurred while fetching vulnerabilities: {e}")
        return jsonify({"error": "Internal server error"}), 500
    

def process_cipher(input_string):
    valid_modes = ["cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"]
    match = re.match(r"(AES(?:[A-Za-z]*))\((\d+)\)", input_string)

    if match:
        mode = match.group(1).replace("AES", "")
        key_size = match.group(2)
        if not mode:
            mode = "CBC"
        return f"AES_{mode.upper()}_{key_size}"

    elif "CHACHA20/POLY1305" in input_string:
        match = re.match(r"CHACHA20/POLY1305\((\d+)\)", input_string)
        if match:
            key_size = match.group(1)
            return f"CHACHA_{key_size}"
    
    elif "AESGCM" in input_string:
        match = re.match(r"AESGCM\((\d+)\)", input_string)
        if match:
            key_size = match.group(1)
            return f"AES_GCM_{key_size}"
        
    for mode in valid_modes:
        if mode in input_string.lower():
            if "AES" in input_string:
                match = re.match(r"AES\((\d+)\)", input_string)
                if match:
                    key_size = match.group(1)
                    return f"AES_{mode.upper()}_{key_size}"
            else:
                return f"{input_string.upper()}"

    return "Invalid input format"

@app.route('/generate_cbom', methods=['POST'])
def generate_cbom():
    try:
        # Get the hashed IP from the request
        hashed_ip = request.form.get('hashed_ip')
        if hashed_ip:
            print(f"Received Hashed IP: {hashed_ip}")
        else:
            print("No hashed IP received")

        if 'file' not in request.files:
            return jsonify({"error": "No file part in the request."}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No selected file."}), 400
        
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON file."}), 400
        
        if not data:
            return jsonify({"error": "No data provided."}), 400
        
        ciphers = data.get("ciphers", {}).get("tls", {})
        certificate_info = data.get("certificate", {})

        if not ciphers and not certificate_info:
            return jsonify({"error": "Input must contain either 'ciphers' or 'certificate' data."}), 400

        # Initialize graph
        G = nx.DiGraph()
        counter = Counter()
        root_node = "Root"
        G.add_node(root_node, label=root_node, level=0)

        # Rebuild the tree structure
        print("Adding primary nodes under the root...")
        G.add_node("Algorithms", label="Algorithms", level=1)
        G.add_node("Hash Function", label="Hash Function", level=1)
        G.add_node("Protocol", label="Protocol", level=1)
        G.add_edge(root_node, "Algorithms")
        G.add_edge(root_node, "Hash Function")
        G.add_edge(root_node, "Protocol")
        symmetric_node = "Symmetric"
        asymmetric_node = "Asymmetric"
        G.add_node(symmetric_node, label="Symmetric", level=2)
        G.add_node(asymmetric_node, label="Asymmetric", level=2)
        G.add_edge("Algorithms", symmetric_node)
        G.add_edge("Algorithms", asymmetric_node)

        for algorithm, details_data in details.items():
            algorithm_node = f"{algorithm}_{counter.increment()}"
            category_node = symmetric_node if algorithm in ['AES', 'Camellia', 'Blowfish'] else asymmetric_node
            
            G.add_node(algorithm_node, label=algorithm, json=details_data, level=3)
            G.add_edge(category_node, algorithm_node)

            if isinstance(details_data, dict):
                build_tree(G, algorithm_node, details_data, counter)

        existing_names = set()

        def is_duplicate(name):
            if name in existing_names:
                return True
            existing_names.add(name)
            return False

        #visualizer = GraphVisualizer(G)
        algorithm_components = []
        certificate_components = []
        protocol_components = []

        # Define the regex pattern for cipher parsing
        pattern = r"([A-Za-z]+)(\d+)?(?:-([A-Za-z]+)(\d+)?)?(?:-([A-Za-z]+)(\d+))?"
        for cipher_name, cipher_data in ciphers.items():
            if not cipher_name:
                return jsonify({"error": "Cipher name is required"}), 400

            # Use the encryption_algorithm as the name for the SBOM
            encryption_algorithm = cipher_data.get("encryption_algorithm", cipher_name)
            process_name = process_cipher(encryption_algorithm)
            if is_duplicate(process_name):
                continue
            normalized_cipher_name = process_name.lower()
            match = re.match(pattern, normalized_cipher_name)
            if not match:
                continue

            algorithm = match.group(1).upper()
            mode = match.group(2) or 'cbc'
            key_size = match.group(3) or '128'

            # Search path in the tree
            search_path = [algorithm, mode, key_size]
            path_data, information = handle_dynamic_path(G, search_path, counter)

            # Retrieve data from the search results
            #node_data = visualizer.search(path_data[-1])
            if not information:
                resolved_details = {
                    "Primitive": "Unknown",
                    "Functions": "Unknown",
                    "NIST_Security_Category": "0",
                    "certification level": "Unknown",
                    "Classic Security Level": "0"
                }
            else:
                resolved_details = {
                    "Primitive": information.get("Primitive", "Unknown"),
                    "Functions": information.get("Functions", "Unknown"),
                    "NIST_Security_Category": str(information.get("NIST_Security_Category", "0")),
                    "certification level": information.get("certification level", "Unknown"),
                    "Classic Security Level": information.get("Classic Security Level", "0")
                }
            # Handle Algorithms
            algorithm_components.append({
                "name": encryption_algorithm,
                "type": "cryptographic-asset",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": resolved_details["Primitive"],
                        "executionEnvironment": "software-plain-ram",
                        "implementationPlatform": "x86_64",
                        "certificationLevel": resolved_details["certification level"],
                        "cryptoFunctions": resolved_details["Functions"],
                        "classicalSecurityLevel": resolved_details["Classic Security Level"],
                        "nistQuantumSecurityLevel": resolved_details["NIST_Security_Category"]
                    },
                    "oid": cipher_data.get("oid", "unknown")
                }
            })

            # Handle Protocol
            protocol_components.append({
                "name": cipher_name,
                "type": "cryptographic-asset",
                "bom-ref": f"crypto/protocol/tls@{cipher_data.get('TLS_version', 'unknown')}",
                "cryptoProperties": {
                    "assetType": "protocol",
                    "protocolProperties": {
                        "type": "tls",
                        "version": cipher_data.get("TLS_version", "unknown"),
                        "cipherSuites": [{
                            "name": cipher_name,
                            "algorithms": [
                                f"crypto/algorithm/{algorithm.lower()}-{mode.lower()}@oid_placeholder",
                                f"crypto/algorithm/aes-{key_size}-gcm@oid_placeholder"
                            ],
                            "identifiers": ["0xC0", "0x30"]
                        }],
                        "cryptoRefArray": [
                            f"crypto/certificate/{cipher_data.get('TLS_version', 'unknown')}@oid_placeholder"
                        ]
                    },
                    "oid": "oid_placeholder"
                }
            })
        # Handle Certificate
        if certificate_info:
            def convert_to_iso8601(date_str):
                try:
                    parsed_date = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
                    return parsed_date.strftime("%Y-%m-%dT%H:%M:%SZ")
                except ValueError:
                    return "Unknown"

            not_valid_before = convert_to_iso8601(certificate_info.get("notValidBefore", "Unknown"))
            not_valid_after = convert_to_iso8601(certificate_info.get("notValidAfter", "Unknown"))
            subject_name_raw = certificate_info.get("subjectName", "Unknown")
            subject_name = re.search(r"CN\s*=\s*([^,]+)", subject_name_raw).group(1) if subject_name_raw else "Unknown"
            certificate_components.append({
                "name": subject_name,
                "type": "cryptographic-asset",
                "bom-ref": f"crypto/certificate/{subject_name}@{certificate_info.get('rsaPublicKey', 'unknown')}",
                "cryptoProperties": {
                    "assetType": "certificate",
                    "certificateProperties": {
                        "subjectName": subject_name,
                        "issuerName": certificate_info.get("issuerName", "Unknown"),
                        "notValidBefore": not_valid_before,
                        "notValidAfter": not_valid_after,
                        "signatureAlgorithmRef": f"crypto/algorithm/{certificate_info.get('signatureAlgorithm', 'unknown')}@{certificate_info.get('oid', 'unknown')}",
                        "subjectPublicKeyRef": f"crypto/key/{certificate_info.get('rsaPublicKey', 'unknown')}@{certificate_info.get('publicKeyAlgorithm', 'unknown')}",
                        "certificateFormat": "X.509",
                        "certificateExtension": "crt"
                    }
                }
            })

        def generate_sbom(components, sbom_type):
            return {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "serialNumber": f"urn:uuid:{str(uuid.uuid4())}",
                "version": 1,
                "metadata": {
                    "timestamp": datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'),
                    "component": {
                        "type": "application",
                        "name": "my application",
                        "version": "1.0"
                    }
                },
                "components": components
            }

        algorithm_sbom = generate_sbom(algorithm_components, "algorithm")
        certificate_sbom = generate_sbom(certificate_components, "certificate")
        protocol_sbom = generate_sbom(protocol_components, "protocol")
        
        sbom_data = {
            "_id": hashed_ip,  # Use hashed IP as the document ID
            "algorithm_sbom": algorithm_sbom,
            "certificate_sbom": certificate_sbom,
            "protocol_sbom": protocol_sbom
        }
        
        # Upsert the SBOM data into MongoDB (update if exists, insert if not)
        collection.update_one(
            {"_id": hashed_ip},
            {"$set": sbom_data},
            upsert=True
        )

        upload_folder = app.config['UPLOAD_FOLDER']
        algorithm_filename = f"algorithm_sbom_{datetime.now().strftime('%d-%m-%Y_%H-%M-%S')}.json"
        certificate_filename = f"certificate_sbom_{datetime.now().strftime('%d-%m-%Y_%H-%M-%S')}.json"
        protocol_filename = f"protocol_sbom_{datetime.now().strftime('%d-%m-%Y_%H-%M-%S')}.json"

        with open(os.path.join(upload_folder, algorithm_filename), 'w') as algo_file:
            json.dump(algorithm_sbom, algo_file, indent=4)

        with open(os.path.join(upload_folder, certificate_filename), 'w') as cert_file:
            json.dump(certificate_sbom, cert_file, indent=4)

        with open(os.path.join(upload_folder, protocol_filename), 'w') as proto_file:
            json.dump(protocol_sbom, proto_file, indent=4)

        return jsonify({
            "message": "SBOMs generated successfully",
            "algorithm_sbom": algorithm_filename,
            "certificate_sbom": certificate_filename,
            "protocol_sbom": protocol_filename
        }), 200

    except Exception as e:
        logging.error(f"Error in generate_cbom: {str(e)}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

def hash_ip(ip):
    """Hashes the IP address using SHA-256."""
    return hashlib.sha256(ip.encode('utf-8')).hexdigest()

@app.route('/receive_output', methods=['POST'])
def receive_output():
    try:
        client_ip = request.remote_addr
        hashed_ip = hash_ip(client_ip)
        print(f"Hashed IP: {hashed_ip}")

        if 'file' in request.files:
            file = request.files['file']
            if not file.filename.endswith('.json'):
                return jsonify({"error": "Invalid file format. Only .json files are allowed."}), 400
            
            temp_filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(temp_filepath)

            with app.test_request_context('/generate_cbom', method='POST', data={'file': open(temp_filepath, 'rb'), 'hashed_ip': hashed_ip}):
                return generate_cbom()

        elif request.is_json:
            data = request.get_json()
            if not data:
                return jsonify({"error": "Invalid JSON data."}), 400
            
            temp_filename = "temp_data.json"
            temp_filepath = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
            with open(temp_filepath, 'w') as temp_file:
                json.dump(data, temp_file)

            with app.test_request_context('/generate_cbom', method='POST', data={'file': open(temp_filepath, 'rb'), 'hashed_ip': hashed_ip}):
                return generate_cbom()

        else:
            return jsonify({"error": "No valid input provided."}), 400

    except Exception as e:
        logging.error(f"Error in receive_output: {str(e)}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    
def generate_hash(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

# @app.route('/upload_oscal', methods=['POST'])
# def upload_oscal():
#     if request.is_json:
#         oscal_json = request.get_json()
#     elif 'file' in request.files:
#         file = request.files['file']
#         oscal_json = json.load(file)
#     else:
#         return jsonify({"error": "No JSON data or file provided."}), 400

#     oscal_type = None
#     if "component-definition" in oscal_json:
#         oscal_type = "component-definition"
#         doc_uuid = str(uuid4())  # generate new UUID for this type
#     elif "catalog" in oscal_json and "uuid" in oscal_json["catalog"]:
#         oscal_type = "catalog"
#         doc_uuid = oscal_json["catalog"]["uuid"]
#     elif "profile" in oscal_json and "uuid" in oscal_json["profile"]:
#         oscal_type = "profile"
#         doc_uuid = oscal_json["profile"]["uuid"]
#     else:
#         return jsonify({"error": "Unrecognized OSCAL type or missing UUID."}), 400

#     doc_hash = generate_hash(oscal_json)

#     if oscal_type in ["catalog", "profile"]:
#         existing = collection.find_one({"uuid": doc_uuid})
#         if existing:
#             if oscal_type in existing:
#                 return jsonify({
#                     "message": f"Duplicate {oscal_type} already exists for this UUID.",
#                     "uuid": doc_uuid
#                 }), 200

#             collection.update_one(
#                 {"uuid": doc_uuid},
#                 {"$set": {
#                     oscal_type: oscal_json,
#                     f"{oscal_type}_hash": doc_hash
#                 }}
#             )
#             return jsonify({
#                 "message": f"{oscal_type} added to existing UUID.",
#                 "uuid": doc_uuid
#             }), 200

#         new_doc = {
#             "uuid": doc_uuid,
#             oscal_type: oscal_json,
#             f"{oscal_type}_hash": doc_hash
#         }
#         collection.insert_one(new_doc)
#         return jsonify({
#             "message": f"{oscal_type} document saved successfully.",
#             "uuid": doc_uuid
#         }), 200

#     else:
#         existing = collection.find_one({"oscal_type": oscal_type, "hash": doc_hash})
#         if existing:
#             return jsonify({
#                 "message": "Duplicate document already exists.",
#                 "uuid": existing["uuid"]
#             }), 200

#         wrapped_doc = {
#             "uuid": doc_uuid,
#             "hash": doc_hash,
#             "oscal_type": oscal_type,
#             "content": oscal_json
#         }
#         collection.insert_one(wrapped_doc)
#         return jsonify({
#             "message": f"{oscal_type} document saved successfully.",
#             "uuid": doc_uuid
#         }), 200


@app.route('/oscal_ids/<doc_uuid>', methods=['GET'])
def get_oscal_ids_by_doc_uuid(doc_uuid):
    doc = collection.find_one({"uuid": doc_uuid})
    if not doc or "content" not in doc or "profile" not in doc["content"]:
        return jsonify({"error": "Profile not found"}), 404

    control_ids = []
    imports = doc["content"]["profile"].get("imports", [])
    for imp in imports:
        for control in imp.get("include-controls", []):
            control_ids.extend(control.get("with-ids", []))

    return jsonify({"control_ids": list(set(control_ids))}), 200


def is_valid_uuid(value):
    if not isinstance(value, str) or not value.startswith("urn:uuid:"):
        return False
    try:
        uuid_str = value.replace("urn:uuid:", "")
        uuid.UUID(uuid_str)
        return True
    except ValueError:
        return False

@app.route('/upload_saasbom', methods=['POST'])
def upload_saasbom():
    if not request.is_json:
        return jsonify({"error": "No JSON data provided."}), 400

    saasbom_json = request.get_json()

    if saasbom_json.get("bomFormat") != "CycloneDX":
        return jsonify({"error": "'bomFormat' must be 'CycloneDX'."}), 400

    if saasbom_json.get("specVersion") != "1.4":
        return jsonify({"error": "'specVersion' must be '1.4'."}), 400

    if "serialNumber" not in saasbom_json:
        saasbom_json["serialNumber"] = f"urn:uuid:{str(uuid.uuid4())}"
    elif not is_valid_uuid(saasbom_json["serialNumber"]):
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
        result = collection.insert_one(saasbom_json)
        logging.info(f"Document inserted with ID: {result.inserted_id}")
    except Exception as e:
        return jsonify({"error": f"Error inserting into database: {e}"}), 500

    return jsonify({
        "message": "SaaSBOM saved successfully.",
        "serialNumber": saasbom_json["serialNumber"]
    }), 200

# @app.route("/upload_toe_descriptor", methods=["POST"])
# def upload_toe_descriptor():
#     data = request.get_json()
    
#     # Check for optional scheme linking parameter
#     # Can be passed in URL (?scheme_id=...) or body
#     scheme_id = request.args.get('scheme_id') or data.get('certification_scheme_id')

#     if not data or "component" not in data:
#         return jsonify({"error": "Missing 'component' in payload"}), 400

#     try:
#         comp_def = data["component"].get("component-definition", {})
#         components = comp_def.get("components", [])
        
#         if not components:
#             return jsonify({"error": "No components found"}), 400

#         toe_uuid = components[0].get("uuid")
#         toe_name = components[0].get("title")

#         if not toe_uuid:
#             return jsonify({"error": "Missing ToE UUID"}), 400

#         # 1. Validate Scheme Link if provided
#         linked_scheme = None
#         if scheme_id:
#             linked_scheme = schemes_col.find_one({"uuid": scheme_id})
#             if not linked_scheme:
#                 return jsonify({"error": f"Scheme {scheme_id} not found. Cannot link ToE."}), 404

#         # 2. Store ToE with Link
#         toe_entry = {
#             "type": "target_of_evaluation",
#             "uuid": toe_uuid,
#             "name": toe_name,
#             "content": data,
#             "linked_scheme_id": scheme_id, # <--- CRITICAL LINK
#             "timestamp": datetime.utcnow().isoformat()
#         }

#         toes_col.update_one(
#             {"uuid": toe_uuid},
#             {"$set": toe_entry},
#             upsert=True
#         )

#         # 3. Forward to Orchestrator/SDT (as per original logic)
#         try:
#             if FORWARD_URL:
#                 requests.post(FORWARD_URL, json=data, timeout=5)
#         except Exception as e:
#             logging.warning(f"Failed to forward ToE to Orchestrator: {e}")

#         return jsonify({
#             "message": "ToE registered and linked successfully",
#             "toe_uuid": toe_uuid,
#             "linked_scheme": scheme_id if scheme_id else "None (Warning: Scheme needed for certification)"
#         }), 200

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

@app.route("/upload_toe_descriptor", methods=["POST"])
def upload_toe_descriptor():
    data = request.get_json()
    
    scheme_id = request.args.get('scheme_id') or data.get('certification_scheme_id')

    if not data or "component" not in data:
        return jsonify({"error": "Missing 'component' in payload"}), 400

    try:
        comp_def = data["component"].get("component-definition", {})
        components = comp_def.get("components", [])
        
        if not components:
            return jsonify({"error": "No components found in component-definition"}), 400

        # Dictionary to group ALL BOMs from ALL components globally
        global_attached_boms = {}

        # Process each component to find and group referenced BOMs
        for component in components:
            links = component.get("links", [])

            for link in links:
                href = link.get("href", "")
                bom_type = link.get("text", "unknown-bom")
                
                # Extract potential UUID or filename from the href
                clean_ref = href.split('/')[-1].replace('.json', '').replace('urn:uuid:', '')
                
                # Search for the document in our artifacts collection
                bom_doc = collection.find_one({
                    "$or": [
                        {"uuid": clean_ref},
                        {"serialNumber": {"$regex": clean_ref}},
                        {"filename": {"$regex": clean_ref}},
                        {"_id": clean_ref}
                    ]
                }, {'_id': 0})

                if bom_doc:
                    # Initialize the array for this BOM type if it doesn't exist globally
                    if bom_type not in global_attached_boms:
                        global_attached_boms[bom_type] = []
                    
                    # Append the file to its specific type array
                    # We add 'source_component_uuid' so you don't lose the relationship
                    global_attached_boms[bom_type].append({
                        "source_component_uuid": component.get("uuid"),
                        "link_ref": href,
                        "content": bom_doc
                    })

        # Attach the grouped BOMs OUTSIDE the component-definition.
        # This makes it a sibling to the main "component" object.
        if global_attached_boms:
            data["attached_boms"] = global_attached_boms

        toe_uuid = components[0].get("uuid")
        toe_name = components[0].get("title")

        if not toe_uuid:
            return jsonify({"error": "Missing ToE UUID"}), 400

        # 1. Validate Scheme Link
        linked_scheme = None
        if scheme_id:
            linked_scheme = schemes_col.find_one({"uuid": scheme_id})
            if not linked_scheme:
                return jsonify({"error": f"Scheme {scheme_id} not found."}), 404

        # 2. Store updated ToE (now containing the global BOM arrays)
        toe_entry = {
            "type": "target_of_evaluation",
            "uuid": toe_uuid,
            "name": toe_name,
            "content": data, 
            "linked_scheme_id": scheme_id,
            "timestamp": datetime.utcnow().isoformat()
        }

        toes_col.update_one(
            {"uuid": toe_uuid},
            {"$set": toe_entry},
            upsert=True
        )

        # 3. Forward the enriched data to Orchestrator
        try:
            if FORWARD_URL:
                authed_request("POST", FORWARD_URL, json=data, timeout=5)
        except Exception as e:
            logging.warning(f"Failed to forward enriched ToE: {e}")

        return jsonify({
            "message": "ToE registered and BOM files grouped successfully",
            "toe_uuid": toe_uuid
        }), 200

    except Exception as e:
        logging.error(f"Error in upload_toe_descriptor: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/upload_certification_scheme", methods=["POST"])
def upload_certification_scheme():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    # ── Support two payload formats ──────────────────────────────────
    # 1. Wrapped:  { "certificationScheme": { "id": "…" }, "controls": […], … }
    # 2. Flat:     { "compliance_metrics": […], "risk_catalogue": […], … }
    if "certificationScheme" in data:
        scheme_meta = data["certificationScheme"]
        scheme_id = scheme_meta.get("id") or str(uuid4())
    else:
        scheme_meta = {}
        scheme_id = data.get("id") or str(uuid4())

    # ── Collect every section (top-level first, then inside wrapper) ──
    compliance_metrics = data.get("compliance_metrics", []) or scheme_meta.get("compliance_metrics", [])
    certifiable_standards = data.get("certifiable_standards_mapping", []) or scheme_meta.get("certifiable_standards_mapping", [])
    boundary_conditions = data.get("boundary_conditions", {}) or scheme_meta.get("boundary_conditions", {})
    risk_catalogue = data.get("risk_catalogue", []) or scheme_meta.get("risk_catalogue", [])
    product_profile = data.get("productProfile", {}) or scheme_meta.get("productProfile", {})
    controls_list = data.get("controls", []) or scheme_meta.get("controls", [])
    profile = data.get("profile", {}) or scheme_meta.get("profile", {})
    catalog = data.get("catalog", {}) or scheme_meta.get("catalog", {})

    # ── Build the full scheme content document ───────────────────────
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

    # ── 1. Send to Ledger (best-effort) ──────────────────────────────
    try:
        ledger_hash = send_to_ledger("/v1/certification-authority/certification-scheme", scheme_content)
    except Exception as e:
        logging.warning(f"Ledger unavailable, using placeholder hash: {e}")
        ledger_hash = "TempHashDueToHotFix"

    # ── 2. Populate individual entity collections (upserts = no duplicates) ──
    try:
        ts = datetime.utcnow().isoformat()
        counts = {"metrics": 0, "risks": 0, "threats": 0, "controls": 0,
                  "control_metric_mappings": 0, "risk_threat_control_mappings": 0}

        # --- Metrics (keyed by unique metric id) ---
        for m in compliance_metrics:
            mid = m.get("id")
            if mid:
                m_doc = {**m, "scheme_id": scheme_id, "timestamp": ts}
                metrics_col.update_one({"id": mid}, {"$set": m_doc}, upsert=True)
                counts["metrics"] += 1

        # --- Risks + extract Threats ---
        seen_threats = set()
        for r in risk_catalogue:
            rid = r.get("risk_id")
            if rid:
                r_doc = {**r, "scheme_id": scheme_id, "timestamp": ts}
                risks_col.update_one({"risk_id": rid}, {"$set": r_doc}, upsert=True)
                counts["risks"] += 1

                # Extract and deduplicate threats across all risks
                for t in r.get("mapped_threats", []):
                    tid = t.get("threat_id")
                    if tid and tid not in seen_threats:
                        seen_threats.add(tid)
                        t_doc = {
                            "threat_id": tid,
                            "name": t.get("name", ""),
                            "associated_risk_id": t.get("associated_risk_id", rid),
                            "scheme_id": scheme_id,
                            "timestamp": ts,
                        }
                        threats_col.update_one({"threat_id": tid}, {"$set": t_doc}, upsert=True)
                        counts["threats"] += 1

        # --- Controls (keyed by oscal_id + metric_id to avoid overwrites) ---
        for c in controls_list:
            oscal_id = c.get("oscal_id")
            metric_id = c.get("metric_id")
            if oscal_id and metric_id:
                c_doc = {**c, "scheme_id": scheme_id, "timestamp": ts}
                controls_col.update_one(
                    {"oscal_id": oscal_id, "metric_id": metric_id},
                    {"$set": c_doc},
                    upsert=True,
                )
                counts["controls"] += 1

        # ── 3. Derive and store C↔M mappings ─────────────────────────
        # Build a lookup: metric_id → control_requirement
        metric_to_control = {}
        for m in compliance_metrics:
            mid = m.get("id")
            ac = m.get("associated_control", {})
            ctrl_req = ac.get("associated_control_requirement")
            if mid and ctrl_req:
                metric_to_control[mid] = ctrl_req

        # Accept explicit C↔M mappings from payload, otherwise auto-derive
        explicit_cm = data.get("control_metric_mappings", []) or scheme_meta.get("control_metric_mappings", [])
        if explicit_cm:
            cm_mappings = explicit_cm
        else:
            cm_mappings = [
                {"control_id": ctrl, "metric_id": mid}
                for mid, ctrl in metric_to_control.items()
            ]

        # Replace all C↔M mappings for this scheme (delete-then-insert = no dups)
        cm_col.delete_many({"scheme_id": scheme_id})
        if cm_mappings:
            for cm in cm_mappings:
                cm["scheme_id"] = scheme_id
                cm["timestamp"] = ts
            cm_col.insert_many(cm_mappings)
            counts["control_metric_mappings"] = len(cm_mappings)

        # ── 4. Derive and store R↔T↔C triplets ───────────────────────
        # Build a lookup: risk_id → set of control_ids (via mapped_metrics → metric → control)
        risk_to_controls = {}
        for r in risk_catalogue:
            rid = r.get("risk_id")
            if not rid:
                continue
            ctrls = set()
            for mm in r.get("mapped_metrics", []):
                mid = mm.get("metric_id")
                if mid and mid in metric_to_control:
                    ctrls.add(metric_to_control[mid])
            # Also check the new mapped_risks on metrics (reverse direction)
            for m in compliance_metrics:
                if rid in (m.get("mapped_risks") or []):
                    ctrl = metric_to_control.get(m.get("id"))
                    if ctrl:
                        ctrls.add(ctrl)
            risk_to_controls[rid] = ctrls

        # Accept explicit R↔T↔C mappings from payload, otherwise auto-derive
        explicit_rtc = data.get("risk_threat_control_mappings", []) or scheme_meta.get("risk_threat_control_mappings", [])
        if explicit_rtc:
            rtc_mappings = explicit_rtc
        else:
            rtc_mappings = []
            for r in risk_catalogue:
                rid = r.get("risk_id")
                if not rid:
                    continue
                threats = r.get("mapped_threats", [])
                ctrls = risk_to_controls.get(rid, set())
                for t in threats:
                    tid = t.get("threat_id")
                    if not tid:
                        continue
                    for ctrl in ctrls:
                        rtc_mappings.append({
                            "risk_id": rid,
                            "threat_id": tid,
                            "control_id": ctrl,
                        })

        # Replace all R↔T↔C mappings for this scheme
        rtc_col.delete_many({"scheme_id": scheme_id})
        if rtc_mappings:
            for rtc in rtc_mappings:
                rtc["scheme_id"] = scheme_id
                rtc["timestamp"] = ts
            rtc_col.insert_many(rtc_mappings)
            counts["risk_threat_control_mappings"] = len(rtc_mappings)

        # ── 5. Store the full scheme document ────────────────────────
        db_entry = {
            "type": "certification_scheme",
            "uuid": scheme_id,
            "content": scheme_content,
            "ledger_hash": ledger_hash,
            "timestamp": ts,
        }
        schemes_col.update_one({"uuid": scheme_id}, {"$set": db_entry}, upsert=True)

        logging.info(
            f"Scheme {scheme_id} uploaded: {counts['metrics']} metrics, "
            f"{counts['risks']} risks, {counts['threats']} threats, "
            f"{counts['controls']} controls, "
            f"{counts['control_metric_mappings']} C↔M, "
            f"{counts['risk_threat_control_mappings']} R↔T↔C"
        )

        return jsonify({
            "message": "Certification Scheme uploaded and all entities populated",
            "uuid": scheme_id,
            "ledger_hash": ledger_hash,
            "populated": counts,
        }), 200

    except Exception as e:
        logging.error(f"Error in upload_certification_scheme: {e}")
        return jsonify({"error": str(e)}), 500

# --- Scheme Mapping & Export Endpoints ---

@app.route('/schemes/<scheme_id>/mappings/rtc', methods=['GET'])
def get_rtc_mappings(scheme_id):
    """Get all Risk↔Threat↔Control triplets for a scheme."""
    try:
        mappings = list(rtc_col.find({"scheme_id": scheme_id}, {'_id': 0}))
        return jsonify({"scheme_id": scheme_id, "count": len(mappings), "mappings": mappings}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/schemes/<scheme_id>/mappings/rtc', methods=['POST'])
def set_rtc_mappings(scheme_id):
    """Bulk create/replace R↔T↔C triplets for a scheme. Replaces all existing."""
    data = request.get_json()
    if not data or not isinstance(data, list):
        return jsonify({"error": "Payload must be a JSON array of {risk_id, threat_id, control_id} objects."}), 400
    try:
        ts = datetime.utcnow().isoformat()
        rtc_col.delete_many({"scheme_id": scheme_id})
        for item in data:
            item["scheme_id"] = scheme_id
            item["timestamp"] = ts
        if data:
            rtc_col.insert_many(data)
        return jsonify({"message": f"{len(data)} R↔T↔C mappings saved for scheme {scheme_id}."}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/schemes/<scheme_id>/mappings/cm', methods=['GET'])
def get_cm_mappings(scheme_id):
    """Get all Control↔Metric mappings for a scheme."""
    try:
        mappings = list(cm_col.find({"scheme_id": scheme_id}, {'_id': 0}))
        return jsonify({"scheme_id": scheme_id, "count": len(mappings), "mappings": mappings}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/schemes/<scheme_id>/mappings/cm', methods=['POST'])
def set_cm_mappings(scheme_id):
    """Bulk create/replace C↔M mappings for a scheme. Replaces all existing."""
    data = request.get_json()
    if not data or not isinstance(data, list):
        return jsonify({"error": "Payload must be a JSON array of {control_id, metric_id} objects."}), 400
    try:
        ts = datetime.utcnow().isoformat()
        cm_col.delete_many({"scheme_id": scheme_id})
        for item in data:
            item["scheme_id"] = scheme_id
            item["timestamp"] = ts
        if data:
            cm_col.insert_many(data)
        return jsonify({"message": f"{len(data)} C↔M mappings saved for scheme {scheme_id}."}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/schemes/<scheme_id>/export', methods=['GET'])
def export_scheme(scheme_id):
    """Full scheme export for DRM consumption — includes all entities and mappings."""
    try:
        # Fetch the scheme document
        scheme_doc = schemes_col.find_one({"uuid": scheme_id}, {'_id': 0})
        if not scheme_doc:
            return jsonify({"error": f"Scheme '{scheme_id}' not found."}), 404

        # Fetch all related entities for this scheme
        risks = list(risks_col.find({"scheme_id": scheme_id}, {'_id': 0}))
        threats = list(threats_col.find({"scheme_id": scheme_id}, {'_id': 0}))
        metrics = list(metrics_col.find({"scheme_id": scheme_id}, {'_id': 0}))
        controls = list(controls_col.find({"scheme_id": scheme_id}, {'_id': 0}))

        # Fetch relationship mappings
        rtc_mappings = list(rtc_col.find({"scheme_id": scheme_id}, {'_id': 0}))
        cm_mappings = list(cm_col.find({"scheme_id": scheme_id}, {'_id': 0}))

        export = {
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
        }

        return jsonify(export), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/schemes/<scheme_id>/sync-drm', methods=['POST'])
def sync_drm(scheme_id):
    """Forward the full scheme export to the DRM for ingestion."""
    drm_base = os.getenv("DRM_BASE_URL", "")
    if not drm_base:
        return jsonify({"error": "DRM_BASE_URL is not configured in .env"}), 503

    try:
        # Build the export payload internally
        scheme_doc = schemes_col.find_one({"uuid": scheme_id}, {'_id': 0})
        if not scheme_doc:
            return jsonify({"error": f"Scheme '{scheme_id}' not found."}), 404

        export_payload = {
            "scheme": scheme_doc.get("content", {}),
            "risks": list(risks_col.find({"scheme_id": scheme_id}, {'_id': 0})),
            "threats": list(threats_col.find({"scheme_id": scheme_id}, {'_id': 0})),
            "metrics": list(metrics_col.find({"scheme_id": scheme_id}, {'_id': 0})),
            "controls": list(controls_col.find({"scheme_id": scheme_id}, {'_id': 0})),
            "risk_threat_control_mappings": list(rtc_col.find({"scheme_id": scheme_id}, {'_id': 0})),
            "control_metric_mappings": list(cm_col.find({"scheme_id": scheme_id}, {'_id': 0})),
        }

        drm_endpoint = f"{drm_base.rstrip('/')}/api/v1/scheme/import"
        resp = authed_request("POST", drm_endpoint, json=export_payload, timeout=30)
        return jsonify({
            "message": "Scheme forwarded to DRM",
            "drm_status": resp.status_code,
            "drm_response": resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text,
        }), resp.status_code

    except Exception as e:
        logging.error(f"DRM sync failed for scheme {scheme_id}: {e}")
        return jsonify({"error": f"DRM sync failed: {str(e)}"}), 502

# --- CRUD Endpoints for Risk Catalogue Entities ---

# Metrics
@app.route('/metrics', methods=['GET'])
def get_all_metrics():
    try:
        metrics = list(metrics_col.find({}, {'_id': 0}))
        return jsonify(metrics), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/metrics/<id>', methods=['GET'])
def get_metric(id):
    try:
        metric = metrics_col.find_one({"id": id}, {'_id': 0})
        if metric:
            return jsonify(metric), 200
        return jsonify({"error": "Metric not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/metrics', methods=['POST', 'PUT'])
def upload_or_update_metric():
    if not request.is_json:
        return jsonify({"error": "No JSON data provided."}), 400
    data = request.get_json()
    
    # Handle both single object and list of objects
    if isinstance(data, list):
        inserted = 0
        for item in data:
            if "id" in item:
                item["timestamp"] = datetime.utcnow().isoformat()
                metrics_col.update_one({"id": item["id"]}, {"$set": item}, upsert=True)
                inserted += 1
        return jsonify({"message": f"{inserted} metrics saved successfully."}), 201
    else:
        if "id" not in data:
            return jsonify({"error": "Metric must have an 'id'."}), 400
        try:
            data["timestamp"] = datetime.utcnow().isoformat()
            metrics_col.update_one({"id": data["id"]}, {"$set": data}, upsert=True)
            return jsonify({"message": "Metric saved successfully.", "id": data["id"]}), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500

# Risks
@app.route('/risks', methods=['GET'])
def get_all_risks():
    try:
        risks = list(risks_col.find({}, {'_id': 0}))
        return jsonify(risks), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/risks/<risk_id>', methods=['GET'])
def get_risk(risk_id):
    try:
        risk = risks_col.find_one({"risk_id": risk_id}, {'_id': 0})
        if risk:
            return jsonify(risk), 200
        return jsonify({"error": "Risk not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/risks', methods=['POST', 'PUT'])
def upload_or_update_risk():
    if not request.is_json:
        return jsonify({"error": "No JSON data provided."}), 400
    data = request.get_json()
    
    if isinstance(data, list):
        inserted = 0
        for item in data:
            if "risk_id" in item:
                item["timestamp"] = datetime.utcnow().isoformat()
                risks_col.update_one({"risk_id": item["risk_id"]}, {"$set": item}, upsert=True)
                inserted += 1
        return jsonify({"message": f"{inserted} risks saved successfully."}), 201
    else:
        if "risk_id" not in data:
            return jsonify({"error": "Risk must have a 'risk_id'."}), 400
        try:
            data["timestamp"] = datetime.utcnow().isoformat()
            risks_col.update_one({"risk_id": data["risk_id"]}, {"$set": data}, upsert=True)
            return jsonify({"message": "Risk saved successfully.", "risk_id": data["risk_id"]}), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500

# Threats
@app.route('/threats', methods=['GET'])
def get_all_threats():
    try:
        threats = list(threats_col.find({}, {'_id': 0}))
        return jsonify(threats), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/threats/<threat_id>', methods=['GET'])
def get_threat(threat_id):
    try:
        threat = threats_col.find_one({"threat_id": threat_id}, {'_id': 0})
        if threat:
            return jsonify(threat), 200
        return jsonify({"error": "Threat not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/threats', methods=['POST', 'PUT'])
def upload_or_update_threat():
    if not request.is_json:
        return jsonify({"error": "No JSON data provided."}), 400
    data = request.get_json()
    
    if isinstance(data, list):
        inserted = 0
        for item in data:
            if "threat_id" in item:
                item["timestamp"] = datetime.utcnow().isoformat()
                threats_col.update_one({"threat_id": item["threat_id"]}, {"$set": item}, upsert=True)
                inserted += 1
        return jsonify({"message": f"{inserted} threats saved successfully."}), 201
    else:
        if "threat_id" not in data:
            return jsonify({"error": "Threat must have a 'threat_id'."}), 400
        try:
            data["timestamp"] = datetime.utcnow().isoformat()
            threats_col.update_one({"threat_id": data["threat_id"]}, {"$set": data}, upsert=True)
            return jsonify({"message": "Threat saved successfully.", "threat_id": data["threat_id"]}), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500

# Controls
@app.route('/controls', methods=['GET'])
def get_all_controls():
    try:
        controls = list(controls_col.find({}, {'_id': 0}))
        return jsonify(controls), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/controls/<control_id>', methods=['GET'])
def get_control(control_id):
    try:
        control = controls_col.find_one({"control_id": control_id}, {'_id': 0})
        if control:
            return jsonify(control), 200
        return jsonify({"error": "Control not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/controls', methods=['POST', 'PUT'])
def upload_or_update_control():
    if not request.is_json:
        return jsonify({"error": "No JSON data provided."}), 400
    data = request.get_json()
    
    if isinstance(data, list):
        inserted = 0
        for item in data:
            control_key = item.get("control_id") or item.get("associated_control_requirement") or item.get("id")
            if control_key:
                item["timestamp"] = datetime.utcnow().isoformat()
                controls_col.update_one({"control_id": control_key}, {"$set": item}, upsert=True)
                inserted += 1
        return jsonify({"message": f"{inserted} controls saved successfully."}), 201
    else:
        control_key = data.get("control_id") or data.get("associated_control_requirement") or data.get("id")
        if not control_key:
            return jsonify({"error": "Control must have a 'control_id' or equivalent."}), 400
        try:
            data["timestamp"] = datetime.utcnow().isoformat()
            controls_col.update_one({"control_id": control_key}, {"$set": data}, upsert=True)
            return jsonify({"message": "Control saved successfully.", "control_id": control_key}), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500


    
    
def generate_json_hash(data):
    normalized = json.dumps(data, sort_keys=True)
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()

@app.route('/store-ledger', methods=['POST'])
def store_ledger_entry():
    oscal_json = request.get_json(force=True)
    component_def = oscal_json.get("component-definition")
    if not component_def:
        return jsonify({"error": "Missing 'component-definition' section."}), 400

    wrapper_uuid = str(uuid4())
    content_hash = generate_json_hash(oscal_json)

    wrapped_doc = {
        "type": "ccm_ledger",
        "headers": {
            "uuid": wrapper_uuid,
            "hash": content_hash,
            "timestamp": datetime.utcnow().isoformat()
        },
        "oscal_component": {
            "ref": wrapper_uuid,
            "component-definition": component_def
        }
    }

    collection.insert_one(wrapped_doc)
    return jsonify({"message": "Stored", "uuid": wrapper_uuid, "hash": content_hash}), 201

@app.route('/update-ledger/<uuid>', methods=['PUT'])
def update_ledger_entry(uuid):
    oscal_json = request.get_json(force=True)
    new_hash = generate_json_hash(oscal_json)

    result = collection.update_one(
        {"headers.uuid": uuid, "type": "ccm_ledger"},
        {"$set": {
            "oscal_component.component-definition": oscal_json.get("component-definition"),
            "headers.hash": new_hash,
            "headers.timestamp": datetime.utcnow().isoformat()
        }}
    )

    if result.matched_count == 0:
        return jsonify({"error": "Entry not found"}), 404

    return jsonify({"message": "Ledger updated", "uuid": uuid, "hash": new_hash}), 200



@app.route("/send_sdt", methods=["POST"])
def send_std():
    try:
        print("\nStarting SBOM send workflow...\n")

        data = request.get_json()
        if not data or "hash" not in data:
            return jsonify({"error": "Missing 'hash' in request body"}), 400

        hash_value = data["hash"]
        print(f"Received hash: {hash_value}")

        # Step 1: POST /deploy
        print("Step 1: Deploying environment...")
        deploy_resp = authed_request("POST", os.getenv("DEPLOY_SDT"))
        print(f"Deploy step completed (status {deploy_resp.status_code})")
        deploy_resp.raise_for_status()

        # Step 2: GET /deployments
        print("Step 2: Checking current deployments...")
        deployments_resp = authed_request("GET", os.getenv("DEPLOYMENTS_SDT"))
        print(f"Deployments fetched (status {deployments_resp.status_code})")
        deployments_resp.raise_for_status()

        time.sleep(30)

        # files_to_send = [
        #     {
        #         "path": os.getenv("SBOM_JSON"),
        #         "hash": hash_value
        #     }
        # ]
        first_record = collection.find_one()
        if first_record:
            files_to_send = [
                {
                    "path": first_record.get("path"),
                    "hash": first_record.get("hash")
                }
            ]
        else:
            files_to_send = []

        for file in files_to_send:
            if not os.path.exists(file["path"]):
                print(f"File not found: {file['path']}")
                return jsonify({"error": f"{file['path']} not found"}), 404

            with open(file["path"], "r") as f:
                content = json.load(f)

            create_url = (
                f"{os.getenv('CREATE_SDT')}?toeid=00000000-0000-0000-0000-000000000000"
                f"&payload_type=BOMS&hash_value={file['hash']}"
            )

            try:
                resp = authed_request("POST", create_url, json=content)
                print(f"Sent to /create (status {resp.status_code})")
                resp.raise_for_status()
            except requests.RequestException as e:
                print(f"Failed to send to /create: {e}")
                # Fallback: save the file to MongoDB
                fallback_data = {
                    "filename": os.path.basename(file["path"]),
                    "hash": file["hash"],
                    "content": content,
                    "timestamp": time.time(),
                    "note": "Saved due to /create endpoint failure"
                }
                collection.insert_one(fallback_data)
                print("Saved SBOM file to MongoDB as fallback.")
                return jsonify({
                    "status": "Fallback save to MongoDB",
                    "error": str(e),
                    "saved_file": fallback_data["filename"]
                }), 500

        print("\nAll files sent successfully!")

        return jsonify({
            "status": "Files sent successfully",
            "deploy_status": deploy_resp.status_code,
            "deployments_status": deployments_resp.status_code,
            "create_status": 200,
        }), 200

    except requests.RequestException as e:
        print(f"\nRequest error: {e}")
        return jsonify({"error": "Request failed", "details": str(e)}), 502
    except Exception as ex:
        print(f"\nUnexpected error: {ex}")
        return jsonify({"error": "Unexpected error", "details": str(ex)}), 500


@app.route('/trigger_delete', methods=['POST'])
def trigger_delete():
    data = request.get_json()
    if not data or "identifier" not in data:
        return jsonify({"error": "Missing 'identifier' in request body"}), 400
    
    url = os.getenv("DELETE_SDT")
    if not url:
        return jsonify({"error": "DELETE_SDT environment variable not configured"}), 500
    
    headers = {"Content-Type": "application/json"}
    payload = {"identifier": data["identifier"]}

    try:
        response = authed_request("POST", url, json=payload, headers=headers)
        return jsonify({
            "message": "Triggered delete request",
            "delete_response_status": response.status_code,
            "delete_response_body": response.json()
        }), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

ENDPOINTS = [
    os.getenv("ENDPOINTS")
]

@app.route('/send_records', methods=['POST'])
def receive_and_forward():
    try:
        incoming_data = request.get_json()
        if not incoming_data:
            return jsonify({'error': 'Invalid or missing JSON'}), 400

        wrapped_doc = {
            "channel": "artifact",
            "smartContract": "artifactsc",
            "key": "test",
            "data": incoming_data
        }

        collection.insert_one(wrapped_doc.copy())

        headers = {'Content-Type': 'application/json'}
        for url in ENDPOINTS:
            try:
                authed_request("POST", url, json=wrapped_doc, headers=headers, timeout=5)
            except requests.RequestException as e:
                print(f"Failed to forward to {url}: {e}")

        return jsonify({'status': 'Success'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

## Counter for unique keys (MongoDB collection)
counters = db.counters
counter_doc = counters.find_one_and_update(
    {"_id": "unique_key_counter"},
    {"$inc": {"seq": 1}},
    return_document=ReturnDocument.AFTER,
    upsert=True
)
unique_key = str(counter_doc["seq"])

@app.route('/trigger-chain', methods=['POST'])
def trigger_chain_post():
    # Ideally, get filename/path from request data or form
    file_path = request.json.get('bom_path')  # e.g. '/path/to/bom.json'
    if not file_path:
        return jsonify({"error": "No BOM file path provided"}), 400

    if not os.path.exists(file_path):
        return jsonify({"error": "BOM file not found"}), 404

    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    try:
        if ext in ['.json']:
            # Load JSON file (works for CycloneDX JSON or OSCAL JSON)
            with open(file_path, 'r') as file:
                bom_data = json.load(file)
        elif ext in ['.xml']:
            # Parse XML file (works for CycloneDX XML or OSCAL XML)
            tree = ET.parse(file_path)
            root = tree.getroot()
            # Convert XML tree to a dict or JSON serializable form (simple example)
            def xml_to_dict(elem):
                d = {elem.tag: {} if elem.attrib else None}
                children = list(elem)
                if children:
                    dd = {}
                    for dc in map(xml_to_dict, children):
                        for k, v in dc.items():
                            if k in dd:
                                if not isinstance(dd[k], list):
                                    dd[k] = [dd[k]]
                                dd[k].append(v)
                            else:
                                dd[k] = v
                    d = {elem.tag: dd}
                if elem.attrib:
                    d[elem.tag].update(('@' + k, v) for k, v in elem.attrib.items())
                if elem.text:
                    text = elem.text.strip()
                    if children or elem.attrib:
                        if text:
                            d[elem.tag]['#text'] = text
                    else:
                        d[elem.tag] = text
                return d

            bom_data = xml_to_dict(root)
        else:
            return jsonify({"error": f"Unsupported file extension: {ext}"}), 400
    except Exception as e:
        return jsonify({"error": "Failed to parse BOM file", "details": str(e)}), 500

    # Construct unique key or get it from request or generation logic
    unique_key = request.json.get('unique_key')
    if not unique_key:
        return jsonify({"error": "unique_key not provided"}), 400

    post_url = f"{LEDGER_BASE_URL}/api/ledger" # Or specific endpoint path
    post_headers = {
        'accept': '*/*',
        'Content-Type': 'application/json'
    }

    payload = {
        "channel": "artifact",
        "smartContract": "artifactsc",
        "key": unique_key,
        "data": bom_data
    }

    try:
        post_response = authed_request("POST", post_url, headers=post_headers, json=payload)
        post_response.raise_for_status()
    except requests.RequestException as e:
        return jsonify({"error": "POST to blockchain failed", "details": str(e)}), 500

    get_url = os.getenv("LEDGER_HASH")
    get_params = {
        "channel": "artifact",
        "smartContract": "artifactsc",
        "key": unique_key
    }
    get_headers = {
        'accept': 'application/json'
    }

    try:
        get_response = authed_request("GET", get_url, headers=get_headers, params=get_params)
        get_response.raise_for_status()
        hash_value = get_response.json().get("hash")
    except requests.RequestException as e:
        return jsonify({"error": "GET hash failed", "details": str(e)}), 500

    send_sdt_url = os.getenv("SEND_SDT")
    send_sdt_payload = {"hash": hash_value}

    try:
        send_sdt_resp = authed_request("POST", send_sdt_url, json=send_sdt_payload)
        send_sdt_resp.raise_for_status()
        send_sdt_result = send_sdt_resp.json()
    except requests.RequestException as e:
        return jsonify({"error": "Failed to call /send_sdt", "details": str(e)}), 500

    return jsonify({
        "status": "success",
        "hash": hash_value,
        "send_sdt_response": send_sdt_result
    })


@app.route('/stop-sdt', methods=['GET'])
def stop_sdt():
    time.sleep(10)
    print("SDT manager has stopped")
    return "SDT manager stopped", 200

@app.route('/evidence', methods=['POST'])
def upload_evidence():
    try:
        evidence = request.get_json(force=True)
        required_fields = ['timestamp', 'toolId', 'raw', 'resource', 'id']
        if not all(field in evidence for field in required_fields):
            return jsonify(error="Missing required fields in evidence"), 400

        db.collection.insert_one({'type': 'evidence', 'data': evidence})
        return jsonify(message="Evidence stored", id=evidence['id']), 201
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route('/assessment-result', methods=['POST'])
def post_assessment_result():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Bad Request"}), 400

    try:
        # 1. Validate Schema
        validate(instance=data, schema=ASSESSMENT_SCHEMA)
        
        # 2. Extract ToE ID
        toe_id = data.get("target_of_evaluation_id")
        if not toe_id:
            return jsonify({"error": "target_of_evaluation_id missing in assessment"}), 400

        # 3. CHECK LINK: Is ToE linked to a Scheme?
        toe_record = toes_col.find_one({"uuid": toe_id})
        if not toe_record:
            return jsonify({"error": f"ToE {toe_id} is not registered in CCM Manager"}), 404
        
        scheme_id = toe_record.get("linked_scheme_id")
        if not scheme_id:
            return jsonify({
                "error": "Configuration Error: This ToE is not linked to any Certification Scheme. Cannot issue certificate."
            }), 409 # Conflict/Precondition failed

        # Verify scheme exists
        scheme_record = schemes_col.find_one({"uuid": scheme_id})
        if not scheme_record:
            return jsonify({"error": "Linked Certification Scheme not found in database"}), 404

        # 4. Save Assessment to Ledger & DB (Standard monitoring)
        assessment_hash = send_to_ledger("/v1/manufacturer/ass-results", data)
        data['ledger_hash'] = assessment_hash
        collection.insert_one({'type': 'assessment_result', 'data': data, 'timestamp': datetime.utcnow().isoformat()})

        # 5. GENERATE CERTIFICATE (If Compliant)
        # Note: Real logic might wait for ALL metrics. Here we assume 1 result triggers update/creation.
        certificate_data = None
        
        if data.get("compliant") is True:
            # Construct Certificate Object (Based on D2.2 Schema)
            cert_uuid = str(uuid4())
            now = datetime.utcnow()
            valid_to = now + timedelta(days=365)
            
            certificate_data = {
                "certification": {
                    "certification_id": cert_uuid,
                    "name": f"Certificate for {toe_record.get('name')}",
                    "version": "1.0",
                    "certification_scheme": scheme_id,
                    "certifying_body": {
                        "name": "COBALT Automated CA",
                        "accreditation_id": "COBALT-ACC-001",
                        "contact_info": {"email": "ca@cobalt.eu", "website": "https://cobalt.eu"}
                    },
                    "applicant": {
                        "organization_name": "ToE Owner", # Could be fetched from ToE metadata
                        "organization_id": "ORG-001",
                        "contact_person": {"name": "Admin", "email": "admin@org.com"}
                    },
                    "target_of_evaluation": {
                        "toe_name": toe_record.get("name"),
                        "toe_uuid": toe_id,
                        "description": "Automated Certification via CCM Manager"
                    },
                    "certification_scope": {
                        "environment": "Cloud",
                        "deployment_model": "SaaS",
                        "services_included": ["Core Service"]
                    },
                    "assessment": {
                        "assessment_id": data.get("id"),
                        "assessment_date": now.strftime("%Y-%m-%d"),
                        "assessment_result": "PASS",
                        "evidence": [data.get("evidence_id")]
                    },
                    "certification_decision": {
                        "decision_date": now.strftime("%Y-%m-%d"),
                        "decision_status": "Granted",
                        "certification_level": "Basic",
                        "validity_period": {
                            "start_date": now.strftime("%Y-%m-%d"),
                            "end_date": valid_to.strftime("%Y-%m-%d")
                        }
                    },
                    "certificate_issuance": {
                        "certificate_serial": str(uuid4().hex),
                        "issue_date": now.strftime("%Y-%m-%d"),
                        "issued_by": "COBALT Automated CA"
                    },
                    "history": [
                        {"event": "Certificate Automatically Generated", "date": now.strftime("%Y-%m-%d")}
                    ]
                }
            }

            # 6. Upload Certificate to Ledger
            cert_hash = send_to_ledger("/v1/certification-authority/certificate", certificate_data)
            certificate_data["ledger_hash"] = cert_hash
            
            # 7. Store Certificate in MongoDB
            certificates_col.insert_one(certificate_data)
            
            if '_id' in certificate_data:
                certificate_data['_id'] = str(certificate_data['_id'])
                
            return jsonify({
                "status": "success",
                "message": "Assessment processed and Certificate ISSUED.",
                "assessment_hash": assessment_hash,
                "certificate": certificate_data
            }), 201

        else:
            return jsonify({
                "status": "processed",
                "message": "Assessment processed but Non-Compliant. No Certificate issued.",
                "assessment_hash": assessment_hash
            }), 200

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return jsonify({"error": str(e)}), 500
    

# --- HELPER FUNCTION (WAS MISSING) ---
def extract_linked_ids(document, root_toe_id):
    """
    Recursively searches a JSON document for UUIDs or links 
    that might be referenced in the database.
    """
    linked_ids = set()
    
    def clean_id(val):
        if isinstance(val, str):
            if val.startswith("urn:uuid:"):
                return val.replace("urn:uuid:", "")
        return val

    def traverse(node):
        if isinstance(node, dict):
            for key, value in node.items():
                # Check for explicit UUID fields
                if key in ['uuid', 'party-uuids', 'role-id', 'id']:
                    if isinstance(value, list):
                        for v in value:
                            linked_ids.add(clean_id(v))
                    else:
                        linked_ids.add(clean_id(value))
                
                # Check for links/hrefs
                if key == 'href' and isinstance(value, str):
                    if "urn:uuid:" in value:
                        linked_ids.add(clean_id(value))
                
                traverse(value)
        elif isinstance(node, list):
            for item in node:
                traverse(item)

    traverse(document)
    
    # Remove the ToE ID itself to avoid redundancy
    if root_toe_id in linked_ids:
        linked_ids.remove(root_toe_id)
        
    return list(linked_ids)
# -------------------------------------



@app.route('/retrieve_toe/<toe_id>', methods=['GET'])
def retrieve_toe_data(toe_id):
    try:
        # 1. Search for the ToE document in the dedicated 'toes' collection
        # This is where /upload_toe_descriptor now saves the data
        root_doc = toes_col.find_one({"uuid": toe_id}, {'_id': 0})

        # Fallback: check the generic collection (for backwards compatibility with OSCAL uploads)
        if not root_doc:
            primary_query = {
                "$or": [
                    {"content.component-definition.uuid": toe_id},            
                    {"content.component-definition.components.uuid": toe_id}, 
                    {"component-definition.uuid": toe_id},                    
                    {"uuid": toe_id}                                          
                ]
            }
            root_doc = collection.find_one(primary_query, {'_id': 0})

        if not root_doc:
            return jsonify({
                "message": "No root document found for the provided ToE ID", 
                "toe_id": toe_id
            }), 404

        # 2. Extract Linked IDs (SBOMs, VEX, etc.) from the ToE file
        linked_uuids = extract_linked_ids(root_doc, toe_id)
        
        # 3. Retrieve All Linked Documents across ALL collections
        # We search in 'collection' (artifacts), 'certificates_col', and 'schemes_col'
        artifact_query = {
            "$or": [
                {"uuid": {"$in": linked_uuids}},
                {"serialNumber": {"$in": [f"urn:uuid:{uid}" for uid in linked_uuids]}},
                {"target_of_evaluation_id": toe_id}, # Find assessments linked to this ToE
                {"certification.target_of_evaluation.toe_uuid": toe_id} # Find certificates
            ]
        }

        linked_artifacts = list(collection.find(artifact_query, {'_id': 0}))
        # Also grab the certificate specifically if it exists
        certificates = list(certificates_col.find({"certification.target_of_evaluation.toe_uuid": toe_id}, {'_id': 0}))
        
        return jsonify({
            "toe_id": toe_id,
            "root_document": root_doc,
            "linked_files_count": len(linked_artifacts) + len(certificates),
            "linked_ids_detected": linked_uuids,
            "linked_documents": linked_artifacts + certificates
        }), 200

    except Exception as e:
        logging.error(f"Error retrieving ToE data: {e}")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500
    
@app.route('/sdts', methods=['GET'])
def get_sdts():
    url = os.getenv("DEPLOYMENTS_SDT")
    if not url:
        return jsonify({"error": "DEPLOYMENTS_SDT environment variable not configured"}), 500
    
    try:
        response = authed_request("GET", url, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        sdt_ids = []
        if isinstance(data, list):
            sdt_ids = [item.get("id") or item.get("identifier") for item in data if isinstance(item, dict)]
            if not sdt_ids and all(isinstance(x, (str, int)) for x in data):
                sdt_ids = data
        elif isinstance(data, dict):
            # Try to extract from a key that might hold the list, e.g., 'deployments'
            for key in ["deployments", "sdts", "data", "items"]:
                if key in data and isinstance(data[key], list):
                    sdt_ids = [item.get("id") or item.get("identifier") for item in data[key] if isinstance(item, dict)]
                    if not sdt_ids and all(isinstance(x, (str, int)) for x in data[key]):
                        sdt_ids = data[key]
                    break
            
            if not sdt_ids:
                # Fallback: if data contains identifier
                if "identifier" in data or "id" in data:
                    sdt_ids.append(data.get("identifier") or data.get("id"))
                
        # Filter out None
        sdt_ids = [str(x) for x in sdt_ids if x is not None]
        
        return jsonify(sdt_ids), 200
    except requests.RequestException as e:
        return jsonify({"error": "Failed to fetch from SDT deployment service", "details": str(e)}), 502
@app.route('/retrieve_toes', methods=['GET'])
def retrieve_all_toes():
    try:
        # 1. Retrieve all ToE documents from the dedicated 'toes' collection
        dedicated_toes = list(toes_col.find({}, {'_id': 0}))

        # 2. Retrieve ToE documents from the fallback generic collection
        # Looking for documents that contain OSCAL component-definition structures
        fallback_query = {
            "$or": [
                {"content.component-definition": {"$exists": True}},
                {"component-definition": {"$exists": True}}
            ]
        }
        fallback_toes = list(collection.find(fallback_query, {'_id': 0}))

        # Combine the results from both collections
        all_toes_raw = dedicated_toes + fallback_toes
        
        # 3. Deduplicate ToEs by UUID 
        # (Prevents returning duplicates if a ToE exists in both collections during a migration)
        unique_toes = {}
        for toe in all_toes_raw:
            # Attempt to extract the UUID based on known schema paths
            toe_uuid = toe.get('uuid')
            
            # Fallback UUID extractions if it's nested deep in OSCAL formatting
            if not toe_uuid:
                if 'component-definition' in toe:
                    toe_uuid = toe['component-definition'].get('uuid')
                elif 'content' in toe and 'component-definition' in toe['content']:
                    toe_uuid = toe['content']['component-definition'].get('uuid')

            # If we found a UUID, add it to our dictionary (overwrites duplicates)
            if toe_uuid:
                unique_toes[toe_uuid] = toe
            else:
                # If no UUID could be parsed at all, keep it using its memory reference or hash to be safe
                unique_toes[str(id(toe))] = toe

        final_toes_list = list(unique_toes.values())

        return jsonify({
            "count": len(final_toes_list),
            "toes": final_toes_list
        }), 200

    except Exception as e:
        logging.error(f"Error retrieving all ToEs: {e}")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

@app.route('/certificates', methods=['GET'])
def get_all_certificates():
    try:
        # Fetch all certificates, excluding the MongoDB '_id' field
        certificates = list(certificates_col.find({}, {'_id': 0}))
        
        return jsonify({
            "count": len(certificates),
            "certificates": certificates
        }), 200

    except Exception as e:
        logging.error(f"Error retrieving all certificates: {e}")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

@app.route('/certificates/<cert_uuid>', methods=['GET'])
def get_certificate(cert_uuid):
    try:
        # Find the specific certificate by its certification_id
        cert = certificates_col.find_one(
            {"certification.certification_id": cert_uuid}, 
            {'_id': 0}
        )
        
        if not cert:
            return jsonify({"error": "Certificate not found", "cert_uuid": cert_uuid}), 404
            
        return jsonify(cert), 200

    except Exception as e:
        logging.error(f"Error retrieving certificate {cert_uuid}: {e}")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route("/certification_scheme/<scheme_id>", methods=["GET"])
def get_certification_scheme(scheme_id):
    try:
        # Search the collection for the scheme, excluding the MongoDB _id
        scheme = schemes_col.find_one({"uuid": scheme_id}, {"_id": 0})
        
        if not scheme:
            return jsonify({"error": "Certification Scheme not found"}), 404
            
        return jsonify(scheme), 200

    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

@app.route("/certification_scheme/<scheme_id>", methods=["DELETE"])
def delete_certification_scheme(scheme_id):
    try:
        # Attempt to delete the document from MongoDB
        result = schemes_col.delete_one({"uuid": scheme_id})
        
        if result.deleted_count == 0:
            return jsonify({"error": "Certification Scheme not found"}), 404
            
        # Note: If your ledger architecture requires a revocation transaction 
        # for deleted items, you would insert that API call right here.
        
        return jsonify({
            "message": "Certification Scheme deleted successfully",
            "uuid": scheme_id
        }), 200

    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route("/certification_schemes", methods=["GET"])
def get_all_certification_schemes():
    try:
        # Retrieve all schemes, excluding the MongoDB _id
        schemes = list(schemes_col.find({}, {"_id": 0}))
        
        return jsonify({
            "count": len(schemes),
            "schemes": schemes
        }), 200

    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route('/certificates/<cert_uuid>/withdraw', methods=['PUT'])
def withdraw_certificate(cert_uuid):
    cert = certificates_col.find_one({"certification.certification_id": cert_uuid})
    if not cert:
        return jsonify({"error": "Certificate not found"}), 404
        
    now_str = datetime.utcnow().strftime("%Y-%m-%d")
    
    current_status = cert.get("certification", {}).get("certification_decision", {}).get("decision_status")
    if current_status == "Withdrawn":
        return jsonify({"message": "Certificate is already withdrawn"}), 200

    update_result = certificates_col.update_one(
        {"certification.certification_id": cert_uuid},
        {
            "$set": {
                "certification.certification_decision.decision_status": "Withdrawn"
            },
            "$push": {
                "certification.history": {
                    "event": "Certificate Withdrawn",
                    "date": now_str
                }
            }
        }
    )
    
    if update_result.modified_count == 1:
        return jsonify({"message": "Certificate state changed to withdrawn successfully"}), 200
    else:
        return jsonify({"error": "Failed to update certificate status"}), 500

if __name__ == '__main__':
    # Auto-initialize the Risk Catalogue collections from JSON
    catalogue_path = os.path.join(os.path.dirname(__file__), 'ai_catalogue.json')
    if os.path.exists(catalogue_path):
        try:
            with open(catalogue_path, 'r') as f:
                cat_data = json.load(f)
                
            # Populate Metrics if empty
            if metrics_col.count_documents({}) == 0:
                metrics_list = cat_data.get("compliance_metrics", [])
                if metrics_list:
                    metrics_col.insert_many(metrics_list)
                    logging.info(f"Initialized {len(metrics_list)} AI compliance metrics into MongoDB.")
                    
            # Populate Controls if empty
            if controls_col.count_documents({}) == 0:
                controls_list = cat_data.get("certifiable_standards_mapping", [])
                if controls_list:
                    # Some controls are duplicated by multiple metrics pointing to them, let's unique them by control_id or just insert
                    controls_col.insert_many(controls_list)
                    logging.info(f"Initialized {len(controls_list)} AI controls into MongoDB.")
                    
            # Populate Risks and extract Threats if empty
            if risks_col.count_documents({}) == 0 and threats_col.count_documents({}) == 0:
                risks_list = cat_data.get("risk_catalogue", [])
                threats_list = []
                
                for risk in risks_list:
                    mapped_threats = risk.pop("mapped_threats", [])
                    for threat in mapped_threats:
                        threat["associated_risk_id"] = risk.get("risk_id")
                        threats_list.append(threat)
                
                if risks_list:
                    risks_col.insert_many(risks_list)
                    logging.info(f"Initialized {len(risks_list)} AI risks into MongoDB.")
                if threats_list:
                    threats_col.insert_many(threats_list)
                    logging.info(f"Initialized {len(threats_list)} AI threats into MongoDB.")
                    
        except Exception as e:
            logging.error(f"Failed to auto-initialize AI catalogue from JSON: {e}")

    app.run(host='0.0.0.0', port=5001, debug=True)
    # DEV CCM MANAGER CODE BELOW THIS LINE IS FOR TESTING PURPOSES ONLY - NOT FOR PRODUCTION USE YET
