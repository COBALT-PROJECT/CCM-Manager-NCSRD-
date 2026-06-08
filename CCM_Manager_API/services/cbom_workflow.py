import json
import logging
import os
import re
import uuid
from datetime import datetime

import networkx as nx

from algos_details import details
from db import collection
from generate_tree import Counter, build_tree, handle_dynamic_path


def process_cipher(input_string):
    valid_modes = ["cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"]
    match = re.match(r"(AES(?:[A-Za-z]*))\((\d+)\)", input_string)

    if match:
        mode = match.group(1).replace("AES", "")
        key_size = match.group(2)
        if not mode:
            mode = "CBC"
        return f"AES_{mode.upper()}_{key_size}"

    if "CHACHA20/POLY1305" in input_string:
        match = re.match(r"CHACHA20/POLY1305\((\d+)\)", input_string)
        if match:
            key_size = match.group(1)
            return f"CHACHA_{key_size}"

    if "AESGCM" in input_string:
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
            return f"{input_string.upper()}"

    return "Invalid input format"


def _build_algorithm_graph():
    graph = nx.DiGraph()
    counter = Counter()
    root_node = "Root"
    graph.add_node(root_node, label=root_node, level=0)

    graph.add_node("Algorithms", label="Algorithms", level=1)
    graph.add_node("Hash Function", label="Hash Function", level=1)
    graph.add_node("Protocol", label="Protocol", level=1)
    graph.add_edge(root_node, "Algorithms")
    graph.add_edge(root_node, "Hash Function")
    graph.add_edge(root_node, "Protocol")

    symmetric_node = "Symmetric"
    asymmetric_node = "Asymmetric"
    graph.add_node(symmetric_node, label="Symmetric", level=2)
    graph.add_node(asymmetric_node, label="Asymmetric", level=2)
    graph.add_edge("Algorithms", symmetric_node)
    graph.add_edge("Algorithms", asymmetric_node)

    for algorithm, details_data in details.items():
        algorithm_node = f"{algorithm}_{counter.increment()}"
        category_node = symmetric_node if algorithm in ["AES", "Camellia", "Blowfish"] else asymmetric_node

        graph.add_node(algorithm_node, label=algorithm, json=details_data, level=3)
        graph.add_edge(category_node, algorithm_node)

        if isinstance(details_data, dict):
            build_tree(graph, algorithm_node, details_data, counter)

    return graph, counter


def _convert_to_iso8601(date_str):
    try:
        parsed_date = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        return parsed_date.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return "Unknown"


def _cyclonedx_document(components):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{str(uuid.uuid4())}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {
                "type": "application",
                "name": "my application",
                "version": "1.0",
            },
        },
        "components": components,
    }


def _save_json(upload_folder, filename, payload):
    with open(os.path.join(upload_folder, filename), "w") as output_file:
        json.dump(payload, output_file, indent=4)


def generate_cbom_from_request(files, hashed_ip, upload_folder):
    try:
        if hashed_ip:
            print(f"Received Hashed IP: {hashed_ip}")
        else:
            print("No hashed IP received")

        if "file" not in files:
            return {"error": "No file part in the request."}, 400

        file = files["file"]
        if file.filename == "":
            return {"error": "No selected file."}, 400

        try:
            data = json.load(file)
        except json.JSONDecodeError:
            return {"error": "Invalid JSON file."}, 400

        if not data:
            return {"error": "No data provided."}, 400

        ciphers = data.get("ciphers", {}).get("tls", {})
        certificate_info = data.get("certificate", {})

        if not ciphers and not certificate_info:
            return {"error": "Input must contain either 'ciphers' or 'certificate' data."}, 400

        graph, counter = _build_algorithm_graph()
        existing_names = set()
        algorithm_components = []
        certificate_components = []
        protocol_components = []
        pattern = r"([A-Za-z]+)(\d+)?(?:-([A-Za-z]+)(\d+)?)?(?:-([A-Za-z]+)(\d+))?"

        for cipher_name, cipher_data in ciphers.items():
            if not cipher_name:
                return {"error": "Cipher name is required"}, 400

            encryption_algorithm = cipher_data.get("encryption_algorithm", cipher_name)
            process_name = process_cipher(encryption_algorithm)
            if process_name in existing_names:
                continue
            existing_names.add(process_name)

            normalized_cipher_name = process_name.lower()
            match = re.match(pattern, normalized_cipher_name)
            if not match:
                continue

            algorithm = match.group(1).upper()
            mode = match.group(2) or "cbc"
            key_size = match.group(3) or "128"

            _, information = handle_dynamic_path(graph, [algorithm, mode, key_size], counter)
            if not information:
                resolved_details = {
                    "Primitive": "Unknown",
                    "Functions": "Unknown",
                    "NIST_Security_Category": "0",
                    "certification level": "Unknown",
                    "Classic Security Level": "0",
                }
            else:
                resolved_details = {
                    "Primitive": information.get("Primitive", "Unknown"),
                    "Functions": information.get("Functions", "Unknown"),
                    "NIST_Security_Category": str(information.get("NIST_Security_Category", "0")),
                    "certification level": information.get("certification level", "Unknown"),
                    "Classic Security Level": information.get("Classic Security Level", "0"),
                }

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
                        "nistQuantumSecurityLevel": resolved_details["NIST_Security_Category"],
                    },
                    "oid": cipher_data.get("oid", "unknown"),
                },
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
                            "algorithms": [
                                f"crypto/algorithm/{algorithm.lower()}-{mode.lower()}@oid_placeholder",
                                f"crypto/algorithm/aes-{key_size}-gcm@oid_placeholder",
                            ],
                            "identifiers": ["0xC0", "0x30"],
                        }],
                        "cryptoRefArray": [
                            f"crypto/certificate/{cipher_data.get('TLS_version', 'unknown')}@oid_placeholder"
                        ],
                    },
                    "oid": "oid_placeholder",
                },
            })

        if certificate_info:
            not_valid_before = _convert_to_iso8601(certificate_info.get("notValidBefore", "Unknown"))
            not_valid_after = _convert_to_iso8601(certificate_info.get("notValidAfter", "Unknown"))
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
                        "certificateExtension": "crt",
                    },
                },
            })

        algorithm_sbom = _cyclonedx_document(algorithm_components)
        certificate_sbom = _cyclonedx_document(certificate_components)
        protocol_sbom = _cyclonedx_document(protocol_components)

        collection.update_one(
            {"_id": hashed_ip},
            {"$set": {
                "_id": hashed_ip,
                "algorithm_sbom": algorithm_sbom,
                "certificate_sbom": certificate_sbom,
                "protocol_sbom": protocol_sbom,
            }},
            upsert=True,
        )

        timestamp = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
        algorithm_filename = f"algorithm_sbom_{timestamp}.json"
        certificate_filename = f"certificate_sbom_{timestamp}.json"
        protocol_filename = f"protocol_sbom_{timestamp}.json"

        _save_json(upload_folder, algorithm_filename, algorithm_sbom)
        _save_json(upload_folder, certificate_filename, certificate_sbom)
        _save_json(upload_folder, protocol_filename, protocol_sbom)

        return {
            "message": "SBOMs generated successfully",
            "algorithm_sbom": algorithm_filename,
            "certificate_sbom": certificate_filename,
            "protocol_sbom": protocol_filename,
        }, 200

    except Exception as exc:
        logging.error("Error in generate_cbom: %s", exc)
        return {"error": f"An unexpected error occurred: {str(exc)}"}, 500
