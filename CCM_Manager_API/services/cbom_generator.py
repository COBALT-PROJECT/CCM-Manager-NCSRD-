import os
import re
import json
import uuid
import networkx as nx
from itertools import count
from datetime import datetime

# Add this function to fix the undefined error
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


class CbomGenerator:
    def __init__(self, collection, upload_folder):
        self.collection = collection
        self.upload_folder = upload_folder

    def process_request(self, file, hashed_ip):
        counter = count(1)

        algorithm_components = []
        protocol_components = []
        certificate_components = []

        try:
            data = json.load(file)
        except json.JSONDecodeError:
            return None, {"error": "Invalid JSON file."}, 400

        if not data:
            return None, {"error": "No data provided."}, 400

        ciphers = data.get("ciphers", {}).get("tls", {})
        certificate_info = data.get("certificate", {})

        if not ciphers and not certificate_info:
            return None, {"error": "Input must contain either 'ciphers' or 'certificate' data."}, 400

        G = nx.DiGraph()
        root_node = "Root"
        G.add_node(root_node, label=root_node, level=0)

        for cipher_name, cipher_data in ciphers.items():
            unique_id = next(counter)

            # Use the process_cipher function
            processed_cipher = process_cipher(cipher_name)

            algorithm_components.append({
                "name": f"{processed_cipher}_{unique_id}",
                "type": "cryptographic-asset",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "ExamplePrimitive",
                        "executionEnvironment": "software-plain-ram",
                        "implementationPlatform": "x86_64",
                        "certificationLevel": "Unknown",
                        "cryptoFunctions": "ExampleFunctions",
                        "classicalSecurityLevel": "0",
                        "nistQuantumSecurityLevel": "0"
                    },
                    "oid": cipher_data.get("oid", "unknown")
                }
            })

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
                            "algorithms": [processed_cipher],
                            "identifiers": []
                        }],
                        "cryptoRefArray": []
                    },
                    "oid": "oid_placeholder"
                }
            })

        if certificate_info:
            certificate_components.append({
                "name": certificate_info.get("subjectName", "Unknown"),
                "type": "cryptographic-asset",
                "cryptoProperties": {
                    "assetType": "certificate",
                    "certificateProperties": {
                        "subjectName": certificate_info.get("subjectName", "Unknown"),
                    }
                }
            })

        algorithm_cbom = self.generate_cbom(algorithm_components)
        certificate_cbom = self.generate_cbom(certificate_components)
        protocol_cbom = self.generate_cbom(protocol_components)

        cbom_data = {
            "_id": hashed_ip,
            "algorithm_cbom": algorithm_cbom,
            "certificate_cbom": certificate_cbom,
            "protocol_cbom": protocol_cbom
        }
        self.collection.insert_one(cbom_data)

        algorithm_filename = self._save_cbom_file(algorithm_cbom, "algorithm_cbom")
        certificate_filename = self._save_cbom_file(certificate_cbom, "certificate_cbom")
        protocol_filename = self._save_cbom_file(protocol_cbom, "protocol_cbom")

        return {
            "message": "CBOMs generated successfully",
            "algorithm_cbom": algorithm_filename,
            "certificate_cbom": certificate_filename,
            "protocol_cbom": protocol_filename
        }, None, 200

    def generate_cbom(self, components):
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

    def _save_cbom_file(self, cbom, prefix):
        filename = f"{prefix}_{datetime.now().strftime('%d-%m-%Y_%H-%M-%S')}.json"
        filepath = os.path.join(self.upload_folder, filename)
        with open(filepath, 'w') as f:
            json.dump(cbom, f, indent=4)
        return filename
