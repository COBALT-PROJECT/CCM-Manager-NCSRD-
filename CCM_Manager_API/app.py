from flask import Flask, jsonify, request
from pymongo import MongoClient
#from werkzeug.utils import secure_filename
import os
import logging
import subprocess
from datetime import datetime
from dotenv import load_dotenv
import json
import uuid
from algos_details import details
from generate_tree import handle_dynamic_path, Counter, build_tree
import networkx as nx
import re
import requests

app = Flask(__name__)

# Configuration settings
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit to 16 MB
client: MongoClient = MongoClient('mongodb://localhost:27017/')
db = client.mydatabase
collection = db.mycollection
load_dotenv()

UPLOAD_FOLDER = './sboms'
TMP_FOLDER = './tmp'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(TMP_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt'}

# Set up detailed logging
logging.basicConfig(level=logging.DEBUG)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return jsonify({"message": "Flask API with MongoDB is running"})

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
        sbom_filepath = os.path.abspath(os.path.join(UPLOAD_FOLDER, f'sbom_{timestamp}.json'))


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

        # Additional logging to verify subprocess execution results
        logging.debug(f"Create project script return code: {result.returncode}")
        logging.debug(f"Create project script output: {result.stdout}")
        logging.error(f"Create project script stderr: {result.stderr}")

        if result.returncode != 0:
            return jsonify({
                "error": "Failed to create project",
                "details": result.stderr,
                "stdout": result.stdout
            }), 500

        # Retrieve and read the VEX JSON file, assuming it's generated in UPLOAD_FOLDER
        vex_files = sorted([f for f in os.listdir(UPLOAD_FOLDER) if f.startswith('vex_') and f.endswith('.json')], reverse=True)
        if vex_files:
            vex_filepath = os.path.join(UPLOAD_FOLDER, vex_files[0])
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
        data = request.get_json()
        
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
                "name": encryption_algorithm,  # Use the encryption_algorithm here
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
    
@app.route('/receive_output', methods=['POST'])
def receive_files():
    try:
        files = request.files

        if not files:
            return jsonify({"error": "No files provided."}), 400

        json_data = None
        processed_files = {} 

        for file_key in files:
            file = files[file_key]
            filename = file.filename

            if filename.endswith('.json'):
                try:
                    json_data = json.load(file)
                except json.JSONDecodeError:
                    return jsonify({"error": f"Invalid JSON in file {filename}."}), 400

            elif filename.endswith('.conf'):
                processed_files['conf'] = file.read().decode('utf-8')

            elif filename.endswith('.log'):
                processed_files['log'] = file.read().decode('utf-8')

            else:
                return jsonify({"error": f"Invalid file format for file {filename}. Allowed formats are .json, .conf, and .log."}), 400

        if not json_data:
            return jsonify({"error": "No valid .json file provided."}), 400

        result = generate_cbom(json_data, processed_files)  # Modify generate_cbom to accept additional data if needed
        return result

    except Exception as e:
        logging.error(f"Error in receive_files: {str(e)}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
    
@app.route('/trigger', methods=['POST'])
def trigger_post():
    try:
        ip_list = os.getenv('IP_LIST')
        if not ip_list:
            return jsonify({"error": "No IP list found in .env file."}), 500
        
        ip_addresses = ip_list.split(',')

        request_data = request.get_json()
        if not request_data or 'ip' not in request_data:
            return jsonify({"error": "Please provide an IP in the request body."}), 400

        target_ip = request_data['ip']

        if target_ip not in ip_addresses:
            return jsonify({"error": f"IP {target_ip} does not exist in the known IPs."}), 404

        url = f"http://{target_ip}:6868/trigger"
        try:
            response = requests.post(url, json={"message": "triggered"})
            return jsonify({
                "ip": target_ip,
                "status": "success",
                "response_code": response.status_code,
                "response_body": response.json() if response.headers.get("Content-Type") == "application/json" else response.text,
            }), 200

        except requests.RequestException as e:
            return jsonify({"error": f"Failed to send POST request to {target_ip}: {str(e)}"}), 500

    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
