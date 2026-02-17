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

class Config:
    UPLOAD_FOLDER = './sboms'
    TMP_FOLDER = './tmp'

app = Flask(__name__)
CORS(app)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
load_dotenv()

# --- CONFIGURATION ---
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
    logging.info(f"Connected to MongoDB at {MONGO_URI}")
except Exception as e:
    logging.error(f"Failed to connect to MongoDB: {e}")

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
        response = requests.post(url, json=payload, timeout=10)
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

@app.route('/upload_oscal', methods=['POST'])
def upload_oscal():
    if request.is_json:
        oscal_json = request.get_json()
    elif 'file' in request.files:
        file = request.files['file']
        oscal_json = json.load(file)
    else:
        return jsonify({"error": "No JSON data or file provided."}), 400

    oscal_type = None
    if "component-definition" in oscal_json:
        oscal_type = "component-definition"
        doc_uuid = str(uuid4())  # generate new UUID for this type
    elif "catalog" in oscal_json and "uuid" in oscal_json["catalog"]:
        oscal_type = "catalog"
        doc_uuid = oscal_json["catalog"]["uuid"]
    elif "profile" in oscal_json and "uuid" in oscal_json["profile"]:
        oscal_type = "profile"
        doc_uuid = oscal_json["profile"]["uuid"]
    else:
        return jsonify({"error": "Unrecognized OSCAL type or missing UUID."}), 400

    doc_hash = generate_hash(oscal_json)

    if oscal_type in ["catalog", "profile"]:
        existing = collection.find_one({"uuid": doc_uuid})
        if existing:
            if oscal_type in existing:
                return jsonify({
                    "message": f"Duplicate {oscal_type} already exists for this UUID.",
                    "uuid": doc_uuid
                }), 200

            collection.update_one(
                {"uuid": doc_uuid},
                {"$set": {
                    oscal_type: oscal_json,
                    f"{oscal_type}_hash": doc_hash
                }}
            )
            return jsonify({
                "message": f"{oscal_type} added to existing UUID.",
                "uuid": doc_uuid
            }), 200

        new_doc = {
            "uuid": doc_uuid,
            oscal_type: oscal_json,
            f"{oscal_type}_hash": doc_hash
        }
        collection.insert_one(new_doc)
        return jsonify({
            "message": f"{oscal_type} document saved successfully.",
            "uuid": doc_uuid
        }), 200

    else:
        existing = collection.find_one({"oscal_type": oscal_type, "hash": doc_hash})
        if existing:
            return jsonify({
                "message": "Duplicate document already exists.",
                "uuid": existing["uuid"]
            }), 200

        wrapped_doc = {
            "uuid": doc_uuid,
            "hash": doc_hash,
            "oscal_type": oscal_type,
            "content": oscal_json
        }
        collection.insert_one(wrapped_doc)
        return jsonify({
            "message": f"{oscal_type} document saved successfully.",
            "uuid": doc_uuid
        }), 200

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

@app.route("/upload_toe_descriptor", methods=["POST"])
def upload_toe_descriptor():
    data = request.get_json()
    
    # Check for optional scheme linking parameter
    # Can be passed in URL (?scheme_id=...) or body
    scheme_id = request.args.get('scheme_id') or data.get('certification_scheme_id')

    if not data or "component" not in data:
        return jsonify({"error": "Missing 'component' in payload"}), 400

    try:
        comp_def = data["component"].get("component-definition", {})
        components = comp_def.get("components", [])
        
        if not components:
            return jsonify({"error": "No components found"}), 400

        toe_uuid = components[0].get("uuid")
        toe_name = components[0].get("title")

        if not toe_uuid:
            return jsonify({"error": "Missing ToE UUID"}), 400

        # 1. Validate Scheme Link if provided
        linked_scheme = None
        if scheme_id:
            linked_scheme = schemes_col.find_one({"uuid": scheme_id})
            if not linked_scheme:
                return jsonify({"error": f"Scheme {scheme_id} not found. Cannot link ToE."}), 404

        # 2. Store ToE with Link
        toe_entry = {
            "type": "target_of_evaluation",
            "uuid": toe_uuid,
            "name": toe_name,
            "content": data,
            "linked_scheme_id": scheme_id, # <--- CRITICAL LINK
            "timestamp": datetime.utcnow().isoformat()
        }

        toes_col.update_one(
            {"uuid": toe_uuid},
            {"$set": toe_entry},
            upsert=True
        )

        # 3. Forward to Orchestrator/SDT (as per original logic)
        try:
            if FORWARD_URL:
                requests.post(FORWARD_URL, json=data, timeout=5)
        except Exception as e:
            logging.warning(f"Failed to forward ToE to Orchestrator: {e}")

        return jsonify({
            "message": "ToE registered and linked successfully",
            "toe_uuid": toe_uuid,
            "linked_scheme": scheme_id if scheme_id else "None (Warning: Scheme needed for certification)"
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/upload_certification_scheme", methods=["POST"])
def upload_certification_scheme():
    data = request.get_json()
    if not data or "certificationScheme" not in data:
        return jsonify({"error": "Missing 'certificationScheme' object"}), 400

    scheme = data["certificationScheme"]
    scheme_id = scheme.get("id")
    
    if not scheme_id:
        return jsonify({"error": "Scheme ID is required"}), 400

    try:
        # 1. Send to Ledger
        ledger_hash = send_to_ledger("/v1/certification-authority/certification-scheme", scheme)
        
        # 2. Store in MongoDB with Hash
        db_entry = {
            "type": "certification_scheme",
            "uuid": scheme_id,
            "content": scheme,
            "ledger_hash": ledger_hash,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Upsert
        schemes_col.update_one(
            {"uuid": scheme_id}, 
            {"$set": db_entry}, 
            upsert=True
        )

        return jsonify({
            "message": "Certification Scheme uploaded and ledgerized successfully",
            "uuid": scheme_id,
            "ledger_hash": ledger_hash
        }), 200

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
        deploy_resp = requests.post(os.getenv("DEPLOY_SDT"))
        print(f"Deploy step completed (status {deploy_resp.status_code})")
        deploy_resp.raise_for_status()

        # Step 2: GET /deployments
        print("Step 2: Checking current deployments...")
        deployments_resp = requests.get(os.getenv("DEPLOYMENTS_SDT"))
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
                resp = requests.post(create_url, json=content)
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
        response = requests.post(url, json=payload, headers=headers)
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
                requests.post(url, json=wrapped_doc, headers=headers, timeout=5)
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
        post_response = requests.post(post_url, headers=post_headers, json=payload)
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
        get_response = requests.get(get_url, headers=get_headers, params=get_params)
        get_response.raise_for_status()
        hash_value = get_response.json().get("hash")
    except requests.RequestException as e:
        return jsonify({"error": "GET hash failed", "details": str(e)}), 500

    send_sdt_url = os.getenv("SEND_SDT")
    send_sdt_payload = {"hash": hash_value}

    try:
        send_sdt_resp = requests.post(send_sdt_url, json=send_sdt_payload)
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
    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)




# DEV CCM MANAGER FOR TESTING PURPOSES ONLY - NOT FOR PRODUCTION USE YET

