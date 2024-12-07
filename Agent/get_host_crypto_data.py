import json
import subprocess
#import uuid
import re
from datetime import datetime
#import requests

# Path to the JSON file where we will append data
timestamp = datetime.now().strftime("%y%m%d%H%M%S")
output_file = f"output-{timestamp}.json"
oid_mappings_file = "oid_mappings.json"
algorithms_file = "algorithms-security-levels.txt"

def parse_ciphers_file(filepath):
    ciphers = {}  # Initialize an empty dictionary
    with open(filepath, "r") as file:
        for line in file.readlines()[1:]:  # Skipping header row
            columns = line.split('|')
            if len(columns) >= 6:
                cipher = {
                    "name-ssl": columns[1].strip(),
                    "name-nist": columns[2].strip(),
                    "cipher-suite": columns[3].strip("{} "),
                    "fips-140-2": columns[4].strip(),
                    "supported-in-tls-version": columns[5].strip(),
                    "oid": columns[6].strip()
                }
                cipher_name = columns[1].strip()  # Use the SSL name as the key in the dictionary
                ciphers[cipher_name] = cipher  # Store the cipher in the dictionary with the cipher name as key
    #print("Ciphers content:", ciphers)
    return ciphers

def parse_security_levels(filepath):

    # Parse the algorithms-security-levels.txt file to create a mapping of
    # algorithms to their classic and NIST quantum security levels.

    security_levels = []

    with open(filepath, 'r') as file:
        lines = file.readlines()

        #Map header names to corresponding fields
#        name_col = columns[0].strip()
#        classic_sec_lvl = columns[1].strip()
#        nist_quantum_sec_lvl = columns[2].strip()
#        algo_ref = columns[3].strip()

        # Parse the lines for data and skip first row of headers
        for line in lines[1:]:
            columns = line.strip().split('|')
            if len(columns) >= 4:
#                algorithm = {
#                    "name": columns[0].strip(),
#                    "classicSecLvl": int(columns[1].strip().split()[0]),  # Extracting number from '112 bits'
#                    "nistQuantumSecLvl": int(columns[2].strip().split()[0]),  # Extracting number from '128 bits'
#                    "references": columns[3].strip(),
#                }
#                algorithms.append(algorithm)
                name_col = columns[0].strip()
                classic_sec_lvl = int(columns[1].strip().replace(" bits", ""))
                nist_quantum_sec_lvl = int(columns[2].strip().replace(" bits", ""))
                algo_ref = columns[3].strip()

                # Add the parsed data to the dictionary
                security_levels = {
                    "classicSecLvl": classic_sec_lvl,
#                    "nistQuantumSecLvl": nist_quantum_sec_lvl,
                }

#    return {"algorithms": algorithms}
    return security_levels


# Helper function to get the list of disabled algorithms
def get_disabled_algorithms():
    command = ["openssl", "list", "-disabled"]
    output = subprocess.check_output(command, text=True)

    disabled_algorithms = set()  # Use a set to store disabled algorithms for fast lookup

    # Split the output by lines and process each line
    for line in output.splitlines():
        if line and line != "Disabled algorithms:" :
            disabled_algorithms.add(line.strip())

#    print("Disabled: ", disabled_algorithms)
    return disabled_algorithms


# Function to filter out disabled algorithms
#def filter_disabled_algorithms(algorithms, disabled_algorithms):
#    filtered_algorithms = [algo for algo in algorithms if algo["name"] not in disabled_algorithms]
#    return filtered_algorithms

# Function to filter out disabled algorithms
def filter_enabled_algorithms(algorithms, disabled_algorithms):
    enabled_algorithms = {}

    for algo_name, algo_data in algorithms.items():
        # Check if the algorithm name starts with or contains any of the disabled algorithms
        if not any(disabled in algo_name for disabled in disabled_algorithms):
            enabled_algorithms[algo_name] = algo_data

    return enabled_algorithms

# Main function to get enabled algorithms
def get_enabled_algorithms():
    all_algorithms = get_all_algorithms()
    disabled_algorithms = get_disabled_algorithms()

    # Filter out the disabled algorithms
    enabled_algorithms = filter_enabled_algorithms(all_algorithms, disabled_algorithms)
    return enabled_algorithms


def get_ssh_crypto_info():
    try:
        # Execute the command to gather algorithm-related settings from SSH
        command = ["sshd", "-T"]
        output = subprocess.check_output(command, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        return {}

    # Initialize a dictionary to store the algorithms categorized by type
    ssh_crypto_info = {}


    for line in output.splitlines():
        # We only want lines that contain an 'algo' keyword
        if "algorithms" in line:
            try:
                # Split the line into key and value (e.g., kexalgorithms sntrup761x25519-sha512@openssh.com,...)
                key, value = line.split(None, 1)
                # Split the value by commas to get individual algorithms
                algorithms = value.split(',')

                # Add the algorithms to the dictionary, using the key as the algorithm type
                ssh_crypto_info[key] = algorithms
            except ValueError as ve:
                print(f"Skipping line due to format error: {line} - {ve}")
        elif "ciphers" in line:
            try:
                key,value = line.split(None, 1)
                ciphers = value.split(',')
                ssh_crypto_info[key] = ciphers
            except ValueError as ve:
                print(f"Skipping line due to format error: {line} - {ve}")
        elif "macs" in line:
            try:
                key, value = line.split(None, 1)
                macs = value.split(',')
                ssh_crypto_info[key] = macs
            except ValueError as ve:
                print(f"Skipping line due to format error: {line} - {ve}")


    #print(json.dumps({"ssh_crypto_info": ssh_crypto_info}, indent=2))
    return ssh_crypto_info


def filter_matching_algorithms(ssh_crypto_info, algorithms):
    # We will now iterate over the algorithm types in ssh_crypto_info
    # Make a copy of the dictionary for safe iteration
    ssh_algo_types = list(ssh_crypto_info.keys())

    # Iterate over the ssh_algo_types to filter out non-matching algorithms
    for algo_type in ssh_algo_types:
        if algo_type in algorithms:  # If the algorithm type exists in both SSH and SSL lists
            # Get the algorithms list for the current type
            current_ssh_algorithms = ssh_crypto_info[algo_type]
            current_ssl_algorithms = algorithms[algo_type]

            # Filter to keep only the matching algorithms
            filtered_algorithms = [algo for algo in current_ssh_algorithms if algo in current_ssl_algorithms]

            # Update the ssh_crypto_info dictionary with the filtered list
            ssh_crypto_info[algo_type] = filtered_algorithms

            # Update the algorithms dictionary with the filtered list (if required)
            algorithms[algo_type] = filtered_algorithms

        else:
            # If the algorithm type is not found in SSL, remove it from SSH
            del ssh_crypto_info[algo_type]

    # Return the updated ssh_crypto_info and algorithms
    return ssh_crypto_info, algorithms


# Helper function to get certificate information from openssl x509 command
def get_certificate_info():
    # Ask the user for the path to the certificate file
    cert_path = input("Please enter the path to the certificate file: ")

    command = ["openssl", "x509", "-noout", "-text", "-in", cert_path]
    output = subprocess.check_output( command, text=True)

    certificate_data = {}
    # Define regex for each piece of data to extract
    issuer_regex = r"Issuer: (.*)"
    subject_regex = r"Subject: (.*)"
    validity_not_before_regex = r"Not Before: (.*)"
    validity_not_after_regex = r"Not After : (.*)"
    signature_algorithm_regex = r"Signature Algorithm: (.*)"
    public_key_algorithm_regex = r"Public Key Algorithm: (.*)"
    public_key_regex = r"Public-Key: (.*)"

    certificate_data['issuerName'] = re.search(issuer_regex, output).group(1)
    certificate_data['subjectName'] = re.search(subject_regex, output).group(1)
    certificate_data['notValidBefore'] = re.search(validity_not_before_regex, output).group(1)
    certificate_data['notValidAfter'] = re.search(validity_not_after_regex, output).group(1)
    certificate_data['signatureAlgorithm'] = re.search(signature_algorithm_regex, output).group(1)
    certificate_data['publicKeyAlgorithm'] = re.search(public_key_algorithm_regex, output).group(1)

    # Check if RSA public key exists in the certificate
    rsa_match = re.search(public_key_regex, output)
    certificate_data['rsaPublicKey'] = rsa_match.group(1) if rsa_match else "Not Available"

    certificate_data['rsaPublicKey'] = re.search(public_key_regex, output).group(1)
    if rsa_match:
        rsa_public_key = rsa_match.group(1)
        # Remove parentheses and spaces
        rsa_public_key_clean = rsa_public_key.replace('(', '').replace(')', '').strip()
        certificate_data['rsaPublicKey'] = rsa_public_key_clean

    return certificate_data