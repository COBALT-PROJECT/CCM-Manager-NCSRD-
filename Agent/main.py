<<<<<<< Updated upstream
import json
# import subprocess
# import uuid
# import re
from datetime import datetime
from parsers import parse_security_levels, parse_ciphers_file
from enabled_algorithms import get_disabled_algorithms, get_enabled_algorithms
from ssh_info import get_ssh_crypto_info
from certificates import get_certificate_info
from oids import get_system_oids
from kernels import get_kernel_info
#import requests

# Path to the JSON file where we will append data
timestamp = datetime.now().strftime("%y%m%d%H%M%S")
output_file = f"output-{timestamp}.json"
oid_mappings_file = "oid_mappings.json"
algorithms_file = "algorithms-security-levels.txt"

# Function to populate JSON data
def populate_json():
    # First, get the system OIDs and save them in oid_mappings.json
    get_system_oids()

    # Parse the security levels
    security_levels = parse_security_levels('algorithms-security-levels.txt')

    # Load the OID mappings to populate the algorithms-oid block
    with open(oid_mappings_file, "r") as json_file:
        oids = json.load(json_file)

    # Parse the algorithms file for security levels
#    algorithm_security_levels = parse_algorithms_file(algorithms_file)
    algorithm_security_levels = parse_security_levels(algorithms_file)

    print("Algorithms security levels", algorithm_security_levels)

    # Get the list of disabled algorithms
    disabled_algorithms = get_disabled_algorithms()
    print("Disabled Algos: ", disabled_algorithms)

    # Filter out the disabled algorithms
    algorithms = get_enabled_algorithms()
    print("enabled Algos: ", algorithms)

    # Load the OID mappings
    with open("oid_mappings.json", "r") as json_file:
        algorithms = json.load(json_file)

    # Update algorithms with security levels
    for algo in algorithms:
        name = algo.get("name", "").strip()
        if name in security_levels:
            algo.update(security_levels[name])

    # Debugging: print the structure of algorithms to check if it's a list or dict
#    print("Structure of algorithms:", type(algorithms))

    # If algorithms is a list, convert it to a dictionary for processing
#    if isinstance(algorithms, list):
        # You may want to categorize these algorithms into different types (e.g., ssl, ssh)
#        algorithms = {'ssl': algorithms}  # Example, adjust based on actual structure
#        print("Algorithms converted to dictionary:", algorithms)

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

    # Cross-reference algorithms with security levels and add the data
    # for cipher in ciphers:
    #     cipher_name = cipher["name-ssl"]
    #     if cipher_name in algorithm_security_levels:
    #         cipher["classicSecurityLevel"] = algorithm_security_levels[cipher_name]["classicSecurityLevel"]
    #         cipher["nistQuantumSecurityLevel"] = algorithm_security_levels[cipher_name]["nistQuantumSecurityLevel"]

    #for cipher_name, cipher in ciphers.items():
    #    if cipher_name in algorithm_security_levels:
    #        cipher["classicSecurityLevel"] = algorithm_security_levels[cipher_name]["classicSecurityLevel"]

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
=======
import json
import os
import time
# import subprocess
# import uuid
# import re
from datetime import datetime
from parsers import parse_security_levels, parse_ciphers_file
from enabled_algorithms import get_disabled_algorithms, get_enabled_algorithms
from ssh_info import get_ssh_crypto_info
from certificates import get_certificate_info
from oids import get_system_oids
from ssl_tls_cipher_info import get_tls_cipher_info, get_nmap_tls_info
#from kernels import get_kernel_info ## NOT YET
#import requests

# Path to the JSON file where we will append data
timestamp = datetime.now().strftime("%y%m%d%H%M%S")
output_file = f"output-{timestamp}.json"
oid_mappings_file = "oid_mappings.json"
algorithms_file = "algorithms-security-levels.txt"

# Function to populate JSON data
def populate_json():
    # First, get the system OIDs and save them in oid_mappings.json
    get_system_oids()

    # Parse the security levels
    security_levels = parse_security_levels('algorithms-security-levels.txt')

    # Load the OID mappings to populate the algorithms-oid block
    with open(oid_mappings_file, "r") as json_file:
        oids = json.load(json_file)

    # Parse the algorithms file for security levels
    algorithm_security_levels = parse_security_levels(algorithms_file)
    # Debugging if needed
#    print("Algorithms security levels", algorithm_security_levels)

    # Get the list of disabled algorithms
    disabled_algorithms = get_disabled_algorithms()

    # Debugging if needed
#    print("Disabled Algos: ", disabled_algorithms)

    # Filter out the disabled algorithms
    algos = get_enabled_algorithms()
    # Debugging if needed
    #print("enabled Algos: ", algos)

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

    # Get cipher details from calling on the function get_tls_cipher_info() which executes the command "openssl ciphers -v"
    ciphers = get_tls_cipher_info()

    # Append security levels to the algorithms
    # algorithms = append_security_levels_to_algorithms(algorithms, security_levels)
    # Update cipher data with security levels
    for cipher_name, cipher in ciphers.items():
        if cipher_name in security_levels:
            cipher["classicSecurityLevel"] = security_levels[cipher_name]["classicSecurityLevel"]

    # # Get nmap TLS information of the host
    nmap_tls_dets = get_nmap_tls_info()
    
    # Get certificate information by calling on the function get_certificate_info() 
    certificate_info = get_certificate_info()

    # Get kernel info from executing cat /proc/crypto to be used in the creation of the CBOM file in the API
    #kernels = get_kernel_info() ## TO BE IMPLEMENTED LATER

    data = {
        "oid_refs": algos,
        "ciphers": {"tls" : ciphers},
        "nmap_tls_info": nmap_tls_dets,
        "certificate": certificate_info,
        "ssh_crypto_info": ssh_crypto_info,
#        "kernel_crypto_info": kernels ## LATER
    }

    # Append to the JSON file
    with open(output_file, "w") as json_file:
        json.dump(data, json_file, indent=2)

def send_json_to_api(file_path, api_url):
    
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} does not exist.")
        return None

    # Read the JSON file content
    with open(file_path, 'r') as json_file:
        json_data = json_file.read()

    try:
        headers = {"Content-Type": "application/json"}
        response = requests.post(api_url, data=json_data, headers=headers)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx, 5xx)
        print(f"File {file_path} successfully sent to {api_url}. Response: {response.text}")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error sending file {file_path} to {api_url}: {e}")
        return None

# Execute script
if __name__ == "__main__":
    start_time = time.time()
    populate_json()
    print(f"Data appended to {output_file}")

    print(f"Sending {output_file} to CCM Manager for further processing...")
    
    file_path = output_file  # Ensure the variable is used correctly
    api_url = "http://10.160.1.189:5001/receive_output"
    response = send_json_to_api(file_path, api_url)  # Capture the response here

    if response is None:
        print(f"Error sending {output_file} to API.")
    elif isinstance(response, dict) and "error" in response:
        print(f"Error sending {output_file} to API: {response}")
    else:
        print(f"{output_file} sent to CCM Manager. API response:", response)

    end_time = time.time()
    # Calculate elapsed time in seconds
    elapsed_time = end_time - start_time
    minutes, seconds = divmod(int(elapsed_time), 60)
    print(f"*** Total time elapsed: {minutes} minutes {seconds} seconds ***")
>>>>>>> Stashed changes
