import json
import os
import time
import socket
# import subprocess
# import uuid
import logging
from logging.handlers import RotatingFileHandler
# import re
from datetime import datetime
from parsers import parse_security_levels
from enabled_algorithms import get_disabled_algorithms, get_enabled_algorithms
from ssh_info import get_ssh_crypto_info
from certificates import get_certificate_info
from oids import get_system_oids
from ssl_tls_cipher_info import get_tls_cipher_info, get_nmap_tls_info
from set_ccma_conf_file import log_ccm_data
#from kernels import get_kernel_info ## NOT YET
import requests
from configure_logger import configure_logger, close_logger

global custom_id
custom_id = 22524368

# Starting logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create rotating file handler for the logger
# max_bytes = 15 * 1024 * 1024  # 15 MB
max_bytes = 50 * 1024 # 5KB to test the rotation
backup_count = 30 # up to 30 old log files
#file_handler = logging.FileHandler('ccm-agent.log')
file_handler = RotatingFileHandler('ccm-agent.log', 'a', max_bytes, backup_count)
file_handler.setLevel(logging.INFO)

# Create formatter of the log file
script_name = os.path.basename(__name__)


logger = configure_logger(script_name, custom_id)

formatter = logging.Formatter(f'%(asctime)s - %(name)s - %(levelname)s - %{custom_id}s: %(message)s')
# formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s: %(message)s')
file_handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(file_handler)

logger.info("[%s]: #--------------------------------------------------#", custom_id)
logger.info("[%s]: #----------- INITIATING LOCAL CCM AGENT -----------#", custom_id)
logger.info("[%s]: #--------------------------------------------------#", custom_id)

# Path to the JSON file where we will append data
timestamp = datetime.now().strftime("%y%m%d%H%M%S")
output_file = f"output-{timestamp}.json"
oid_mappings_file = "oid_mappings.json"
algorithms_file = "algorithms-security-levels.txt"

# Function to populate JSON data
def populate_json():
    # Log our entry in the function
    logger.info("Populate oid_mappings.json file with system's hardwired OID information.")

    # First, get the system OIDs and save them in oid_mappings.json
    custom_id = 6750
    get_system_oids()
    custom_id = 22524368

    # Parse the security levels
    logger.info("[%s]: Parse security levels.", custom_id)
    custom_id = 4180
    security_levels = parse_security_levels('algorithms-security-levels.txt')
    custom_id = 22524368

    # Load the OID mappings to populate the algorithms-oid block
    logger.info("[%s]: Load OID mappings JSON file and populate algorithms-oid block.", custom_id)
    with open(oid_mappings_file, "r") as json_file:
        oids = json.load(json_file)

    # Parse the algorithms file for security levels
    logger.info("[%s]: Parse the algorithms file to get the security levels.", custom_id)
    custom_id = 4180
    algorithm_security_levels = parse_security_levels(algorithms_file)
    # Debugging if needed
#    print("Algorithms security levels", algorithm_security_levels)
    custom_id = 22524368

    # Get the list of disabled algorithms
    logger.info("[%s]: Call upon a function to get the list of the system's disabled algorithms.", custom_id)
    custom_id = 8446
    disabled_algorithms = get_disabled_algorithms()
    custom_id = 22524368

    # Debugging if needed
#    print("Disabled Algos: ", disabled_algorithms)

    # Filter out the disabled algorithms
    logger.info("[%s]: Filter out disabled algorithms from the list the CCM Agent sends to the CCM Manager.", custom_id)
    custom_id = 8446
    algos = get_enabled_algorithms()
    # Debugging if needed
    #print("enabled Algos: ", algos)
    custom_id = 22524368

    # Load the OID mappings
    logger.info("[%s]: Load the OID mappings JSON file for update.", custom_id)
    with open("oid_mappings.json", "r") as json_file:
        algorithms = json.load(json_file)

    # Update algorithms with security levels
    logger.info("[%s]: update the algorithms with their respective security level.", custom_id)
    for algo in algorithms:
        name = algo.get("name", "").strip()
        if name in security_levels:
            algo.update(security_levels[name])

    # Gather SSH crypto info (ciphers, MACs, KEX, etc.)
    logger.info("[%s]: Call upon function to gather SSH crypto information (ciphers, MACs, KEX, etc).", custom_id)
    custom_id = 4253
    ssh_crypto_info = get_ssh_crypto_info()
    custom_id = 22524368

    # Filter algorithms to ensure only matching ones stay
#    ssh_crypto_info, algorithms = filter_matching_algorithms(ssh_crypto_info, algorithms)

    # Get cipher details from calling on the function get_tls_cipher_info() which executes the command "openssl ciphers -v"
    logger.info("[%s]: Call upon function to gather TLS cipher details by executing the command \"openssl ciphers -v\".", custom_id)
    custom_id = 6101
    ciphers = get_tls_cipher_info()
    custom_id = 22524368

    # Append security levels to the algorithms
    # algorithms = append_security_levels_to_algorithms(algorithms, security_levels)
    # Update cipher data with security levels
    logger.info("[%s]: Upate cipher data gathered with their respective security levels.", custom_id)
    for cipher_name, cipher in ciphers.items():
        if cipher_name in security_levels:
            cipher["classicSecurityLevel"] = security_levels[cipher_name]["classicSecurityLevel"]

    # # Get nmap TLS information of the host
    logger.info("[%s]: Call upon function to gather nmap TLS information from the host.", custom_id)
    custom_id = 6101
    nmap_tls_dets = get_nmap_tls_info()
    custom_id = 22524368

    # Get certificate information by calling on the function get_certificate_info()
    logger.info("[%s]: Call upon function to gather certificate centric information of the host.", custom_id)
    custom_id = 5280
    certificate_info = get_certificate_info()
    custom_id = 22524368

    # Get kernel info from executing cat /proc/crypto to be used in the creation of the CBOM file in the API
    # custom_id = 1337
    #kernels = get_kernel_info() ## TO BE IMPLEMENTED LATER
    # custom_id = 22524368

    logger.info("[%s]: Construct data structure to collect cryptographic related information to send to the CCM Manager API.", custom_id)
    data = {
        "oid_refs": algos,
        "ciphers": {"tls" : ciphers},
        "nmap_tls_info": nmap_tls_dets,
        "certificate": certificate_info,
        "ssh_crypto_info": ssh_crypto_info,
#        "kernel_crypto_info": kernels ## LATER
    }

    # Append to the JSON file
    logger.info("[%s]: Append data structure to the final file.", custom_id)
    with open(output_file, "w") as json_file:
        json.dump(data, json_file, indent=2)

# def send_json_to_api(file_path, api_url):
#     logger.info("[%s]: Trying to send file %s to the CCM Manager..........", custom_id, file_path)
#     if not os.path.exists(file_path):
#         logger.error("[%s]: Error: file %s does not exist.", custom_id, file_path)
#         return None
#
#     # Read the JSON file content
#     with open(file_path, 'r') as json_file:
#         json_data = json_file.read()
#
#     try:
#         headers = {"Content-Type": "application/json"}
#         response = requests.post(api_url, data=json_data, headers=headers)
#         response.raise_for_status()  # Raise an HTTPError for bad responses (4xx, 5xx)
#         logger.info("[%s]: File %s successfully sent to %s. response: %s", custom_id, file_path, api_url, response.text)
#         return response.json()
#     except requests.exceptions.RequestException as e:
#         logger.error("[%s]: Error sending file %s to CCM Manager API %s: %s", custom_id, file_path, api_url, e)
#         return None

def send_files_to_api(main_file_path, api_url):
    hostname = socket.gethostname()
    local_conf_file = f"ccm-a-{hostname}-local.conf"
    local_log_file = "ccm-a-{hostname}-local-conf.log"

    # Check if all files exist
    files_to_send = {
        "main_file": main_file_path,
        "local_conf_file": local_conf_file,
        "local_log_file": local_log_file,
    }

    for key, file_path in files_to_send.items():
        if not os.path.exists(file_path):
            logger.error("Error: %s (%s) does not exist.", key, file_path)
            return None

    # Open all files to send as multipart data
    try:
        with open(main_file_path, 'r') as main_file, \
                open(local_conf_file, 'r') as conf_file, \
                open(local_log_file, 'r') as local_log_file:

            files = {
                "json_file": (os.path.basename(main_file_path), main_file, "application/json"),
                "local_conf": (os.path.basename(local_conf_file), conf_file, "application/json"),
                "local_log_file": (os.path.basename(local_log_file), local_log_file, "text/plain"),
            }

            response = requests.post(api_url, files=files)
            response.raise_for_status()  # Raise an HTTPError for bad responses (4xx, 5xx)
            logger.info("All files successfully sent to %s. Response: %s", api_url, response.text)
            return response.json()

    except requests.exceptions.RequestException as e:
        logger.error("Error sending files to CCM Manager API %s: %s", api_url, e)
        return None
    except Exception as e:
        logger.error("An unexpected error occurred while preparing files: %s", e)
        return None

# Execute script
if __name__ == "__main__":
    start_time = time.time()
    log_ccm_data()

    populate_json()
    logger.info("[%s]: Data appended to %s.", custom_id, output_file)

    logger.info("[%s]: Sending %s to CCM Manager for further proscessing...", custom_id, output_file)
    logger.info("[%s]: Trying to connect with CCM Manager...", custom_id)

    main_file_path = output_file  # Ensure the variable is used correctly
    api_url = "http://10.160.1.189:5001/receive_output"
    response = send_files_to_api(main_file_path, api_url)  # Capture the response here

    if response is None:
        logger.error("[%s]: Error sending %s to API.", custom_id, output_file)
    elif isinstance(response, dict) and "error" in response:
        logger.error("[%s]: Error sending %s to API: %s", custom_id, output_file, response)
    else:
        logger.info("[%s]: %s successfully sent to CCM Manager. API response: %s", custom_id, output_file, response)

    # file_path = "{output_file}"
    # api_url = "http://10.160.1.189:5001/receive_output"
    # send_json_to_api(file_path, api_url)
    # if isinstance(response, dict) and "error" in response:
    #     logger.error("[%s]: Error sending {output_file} to API:", response)
    # else:
    #     logger.info(f"{output_file} sent to CCM Manager. API response:", response)

    end_time = time.time()
    # Calculate elapsed time in seconds
    elapsed_time = end_time - start_time
    minutes, seconds = divmod(int(elapsed_time), 60)
    # logger.info("[%s]: *** Total time elapsed: %s minutes %s seconds ***", custom_id, minutes, seconds)
    logger.info("*** Total time elapsed: {minutes} minutes {seconds} seconds ***")
    # print(f"*** Total time elapsed: {minutes} minutes {seconds} seconds ***")
    logger.info("[%s]: #--------------------------------------------------#", custom_id)
    logger.info("[%s]: #----------- TERMINATING LOCAL CCM AGENT ----------#", custom_id)
    logger.info("[%s]: #--------------------------------------------------#", custom_id)
    logger.handlers[0].flush()
    logger.handlers[0].close()
    close_logger(logger)