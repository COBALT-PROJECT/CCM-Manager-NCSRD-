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
from algos_details import resources

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
    

@app.route('/generate_cbom', methods=['POST'])
def generate_crypto_sbom():
    try:
        if 'file' in request.files:
            file = request.files['file']
            if file.filename.endswith('.json'):
                data = json.load(file)
            else:
                return jsonify({"error": "Invalid file format. Only .json files are allowed."}), 400
        elif request.is_json:
            data = request.get_json()
            if data is None:
                return jsonify({"error": "Failed to decode JSON. Please ensure valid JSON is provided."}), 400
        else:
            return jsonify({"error": "No valid JSON or file provided."}), 400

        algorithms = data.get("algorithms", [])

        algorithm_components = []
        algorithm_primitive = "unknown"
        functions = "unknown"
        nist_security_category = "0"
        certificate_level = "none"
        classic_security_level = ""

        for algorithm in algorithms:
            if not algorithm.get("name"):
                return jsonify({"error": "Algorithm name is required"}), 400

            if details.get(algorithm["name"]):  
                algorithm_primitive = details.get(algorithm["name"]).get("Primitive")
                functions = details.get(algorithm["name"]).get("Functions")
                nist_security_category = details.get(algorithm["name"]).get("NIST_Security_Category") 
                certificate_level = details.get(algorithm["name"]).get("certification level")
            
            for resource in resources:
                if resource["Algorithm"] == algorithm["name"]:
                    classic_security_level = resource.get("Classic Security Level")
                    break

            algorithm_components.append({
                "name": algorithm.get("name"),
                "type": "cryptographic-asset",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": algorithm_primitive,
                        "executionEnvironment": "software-plain-ram",
                        "implementationPlatform": "x86_64",
                        "certificationLevel": certificate_level,
                        "cryptoFunctions": functions,
                        "classicalSecurityLevel": classic_security_level,
                        "nistQuantumSecurityLevel": nist_security_category
                    },
                    "oid": algorithm.get("oid", "")
                }
            })

        algorithm_sbom = {
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
            "components": algorithm_components
        }

        algorithm_sbom_filename = f"algorithm_sbom_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"
        algorithm_sbom_filepath = os.path.join(app.config['UPLOAD_FOLDER'], algorithm_sbom_filename)

        with open(algorithm_sbom_filepath, 'w+') as algo_file:
            json.dump(algorithm_sbom, algo_file, indent=4)

        logging.info(f"Algorithm SBOM saved at {algorithm_sbom_filepath}")

        return jsonify({
            "message": "SBOM generated successfully",
            "algorithm_sbom_file": algorithm_sbom_filename
        }), 200

    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)