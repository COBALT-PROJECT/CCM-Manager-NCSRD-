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

        # Parse the lines for data and skip first row of headers
        for line in lines[1:]:
            columns = line.strip().split('|')
            if len(columns) >= 4:
                name_col = columns[0].strip()
                classic_sec_lvl = int(columns[1].strip().replace(" bits", ""))
                nist_quantum_sec_lvl = int(columns[2].strip().replace(" bits", ""))
                algo_ref = columns[3].strip()

                # Add the parsed data to the dictionary
                security_levels = {
                    "classicSecLvl": classic_sec_lvl,
#                    "nistQuantumSecLvl": nist_quantum_sec_lvl,
                }
    return security_levels


# Helper function to get the list of disabled algorithms
def get_disabled_algorithms():
    command = ["openssl", "list", "-disabled"]
    output = subprocess.check_output(command, text=True)

    disabled_algorithms = set()  # Use a set to store disabled algorithms for fast lookup

    # Split the output by lines and process each line
    for line in output.splitlines():
        if line.strip():  # Ignore empty lines
            disabled_algorithms.add(line.strip())

    return disabled_algorithms


# Update function to filter out disabled algorithms
def filter_disabled_algorithms(algorithms, disabled_algorithms):
    filtered_algorithms = [algo for algo in algorithms if algo["name"] not in disabled_algorithms]
    return filtered_algorithms

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

# Helper function to execute the openssl list -objects command and save output to JSON
def get_system_oids():
    command = ["openssl", "list", "-objects"]
    output = subprocess.check_output(command, text=True)

    # Default values in case we can't retrieve them
    classic_sec_lvl = 0

    oid_mappings = []

#    security_levels = parse_security_levels('algorithms-security-levels.txt')
#    algorithms = json.loads(output)
#    algorithms_with_security = append_security_levels_to_algorithms(algorithms, security_levels)


    # Split the output by lines and process each line
    for line in output.splitlines():
        if line.strip():  # Ignore empty lines
            # Extract the name and OID parts using regex
            match = re.match(r"([^\s=]+)\s*=\s*(.*)", line)
            if match:
                name = match.group(1).strip()
                alias_oid = match.group(2).strip()

                # Check if the alias_oid is an OID (numeric format)
                if re.match(r"^\d+(\.\d+)*$", alias_oid):
                    # It's an OID, no alias
                    alias = ""
                    oid = alias_oid
                else:
                    # It has both alias and OID
                    parts = alias_oid.split(",")
                    if len(parts) == 2:
                        alias = parts[0].strip()
                        oid = parts[1].strip()
                    else:
                        alias = parts[0].strip()
                        oid = ""  # If there's only one part, leave OID empty

                # Construct the dictionary for this entry
                oid_mappings.append({
                    "name": name,
                    "alias": alias,
                    "oid": f"{oid}" if alias else oid,  # Only combine if there's an alias
                    "classicSecLvl": classic_sec_lvl,
                })

    # Write the oid mappings to oid_mappings.json
    with open(oid_mappings_file, "w") as json_file:
        json.dump(oid_mappings, json_file, indent=2)

#    return algo_data

def get_kernel_info():
    # Run the command to get information from /proc/crypto
    command = "cat /proc/crypto"
    output = subprocess.check_output(command, shell=True, text=True)
    
    # Initialize an empty list to store the parsed algorithm data
    kernel_info = []
    
    # Regular expressions for matching algorithm details in /proc/crypto
    algorithm_pattern = re.compile(r"^name\s*:\s*(?P<name>.*)$")
    type_pattern = re.compile(r"^type\s*:\s*(?P<type>.*)$")
    provider_pattern = re.compile(r"^provider\s*:\s*(?P<provider>.*)$")
    
    # Variables to store current algorithm's details
    current_algo = {}

    # Process each line in the output from /proc/crypto
    for line in output.splitlines():
        line = line.strip()

        # Match algorithm name
        match = algorithm_pattern.match(line)
        if match:
            if current_algo:
                # If there's a previous algorithm, add it to the list before starting a new one
                kernel_info.append(current_algo)
            current_algo = {"name": match.group("name")}

        # Match algorithm type
        match = type_pattern.match(line)
        if match:
            current_algo["type"] = match.group("type")
        
        # Match provider (implementation)
        match = provider_pattern.match(line)
        if match:
            current_algo["provider"] = match.group("provider")

    # Add the last algorithm if it exists
    if current_algo:
        kernel_info.append(current_algo)
    
    # Return the kernel information in JSON format
#    return json.dumps(kernel_info, indent=2)
    return kernel_info

# Main function to populate JSON data
def populate_json():
    # First, get the system OIDs and save them in oid_mappings.json
    get_system_oids()

    # Parse the security levels
    security_levels = parse_security_levels('algorithms-security-levels.txt')

    # Load the OID mappings to populate the algorithms block
    with open(oid_mappings_file, "r") as json_file:
        algorithms = json.load(json_file)

    # Parse the algorithms file for security levels
#    algorithm_security_levels = parse_algorithms_file(algorithms_file)
    algorithm_security_levels = parse_security_levels(algorithms_file)

    # Get the list of disabled algorithms
    disabled_algorithms = get_disabled_algorithms()

    # Filter out the disabled algorithms
    algorithms = filter_disabled_algorithms(algorithms, disabled_algorithms)

    # Load the OID mappings
    with open("oid_mappings.json", "r") as json_file:
        algorithms = json.load(json_file)

    # Update algorithms with security levels
    for algo in algorithms:
        name = algo.get("name", "").strip()
        if name in security_levels:
            algo.update(security_levels[name])
    
    # Gather SSH crypto info (ciphers, MACs, KEX, etc.)
    ssh_crypto_info = get_ssh_crypto_info()

    # Filter algorithms to ensure only matching ones stay
#    ssh_crypto_info, algorithms = filter_matching_algorithms(ssh_crypto_info, algorithms)

    # Get cipher details from the ciphers file
    ciphers = parse_ciphers_file("ciphers-and-cipher-values.txt")

    # Append security levels to the algorithms
    # algorithms = append_security_levels_to_algorithms(algorithms, security_levels)
    # Update cipher data with security levels
    for cipher_name, cipher in ciphers.items():
        if cipher_name in security_levels:
            cipher["classicSecurityLevel"] = security_levels[cipher_name]["classicSecurityLevel"]

    # Get certificate info
    certificate_info = get_certificate_info()

    # Get kernel info from executing cat /proc/crypto to be used in the creation of the CBOM file in the API
    kernels = get_kernel_info()

    data = {
        "algorithms": algorithms,
        "ciphers": ciphers,
        "certificate": certificate_info,
        "ssh_crypto_info": ssh_crypto_info,
        "kernel_crypto_info": kernels
    }

    # Append to the JSON file
    with open(output_file, "w") as json_file:
        json.dump(data, json_file, indent=2)

# Execute script
if __name__ == "__main__":
    populate_json()
    print(f"Data appended to {output_file}")
