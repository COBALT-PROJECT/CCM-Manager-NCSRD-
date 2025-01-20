import os
import socket
import uuid
import hashlib
from datetime import datetime
import json
import logging
import subprocess
import re

hostname = socket.gethostname()

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler(f'ccm-a-{hostname}-local-conf.log')

script_name = os.path.basename(__file__)  # Get the script name
formatter = logging.Formatter(f'%(asctime)s - {script_name} - [%(process)d] - %(levelname)s: %(message)s')
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


def get_or_create_ccma_id_file():
    logger.info("Running on %s", hostname)
    logger.info(f"Checking if this is the first time the CCM Agent runs on this system ({hostname})")
    id_file_name = f"{hostname}_id.cnf"

    # Check if the file already exists
    if os.path.exists(id_file_name):
        logger.info(f"ID file {id_file_name} already exists. Loading existing ccma_id.")
        with open(id_file_name, 'r') as f:
            try:
                data = json.load(f)
                ccma_id = data.get("ccma_id")
                if ccma_id:
                    logger.info(f"Loaded ccma_id: {ccma_id}")
                    return ccma_id, id_file_name
            except json.JSONDecodeError:
                logger.error(f"Failed to parse {id_file_name}. Regenerating ccma_id.")

    # If the file doesn't exist or parsing fails, generate a new UUID
    ccma_id = str(uuid.uuid4())
    with open(id_file_name, 'w') as f:
        json.dump({"ccma_id": ccma_id}, f, indent=4)
    logger.info(f"Generated and saved new ccma_id: {ccma_id} to {id_file_name}")
    return ccma_id, id_file_name

def get_mac_address():
    logger.info("Searching for the system's MAC address....")
    try:
        result = subprocess.run(['ip', 'a'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            logger.error(f"Failed to execute 'ip a': {result.stderr.strip()}")
            raise RuntimeError(f"Failed to execute 'ip a': {result.stderr.strip()}")

        pattern = r"2:\s([\w\d\-]+):.*?\n\s+link/ether\s([0-9a-f:]+)"
        match = re.search(pattern, result.stdout, re.IGNORECASE)

        if match:
            interface = match.group(1)
            mac_address = match.group(2)
            logger.info(f"Found system {hostname}'s MAC address to be {mac_address} for the interface {interface}.")
            return mac_address
        else:
            logger.error("MAC address not found.")
            raise ValueError("MAC address not found.")

    except Exception as e:
        logger.error("Error getting the system's MAC address.")
        return "00:00:00:00:00:00"

def log_ccm_data():
    hostname = socket.gethostname()
    ccma_id, id_file_name = get_or_create_ccma_id_file()

    tID = datetime.now().strftime('%Y%m%d-%H%M%S-') + str(uuid.uuid4())

    logger.info("Generated tID = %s", tID)

    hashed_ccma_id = hashlib.sha256(ccma_id.encode('utf-8')).hexdigest()
    hashed_tID = hashlib.sha256(tID.encode('utf-8')).hexdigest()

    logger.info("Hashing ccma_id and tID....")
    logger.info("Hashed ccma_id = %s", hashed_ccma_id)
    logger.info("Hashed tID = %s", hashed_tID)

    mac_address = get_mac_address()

    filename = f"ccm-a-{hostname}-local.conf"
    data = {
        "hashed_ccma_id": hashed_ccma_id,
        "hashed_tID": hashed_tID,
        "mac_address": mac_address,
        "first_run": None,
        "last_update": datetime.now().isoformat(),
    }

    logger.info("Creating file to save local CCM Agent information named %s.", filename)

    if os.path.exists(filename):
        with open(filename, 'r') as f:
            existing_data = json.load(f)
            data["first_run"] = existing_data.get("first_run", data["last_update"])
    else:
        data["first_run"] = data["last_update"]

    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

    logger.info(f"CCM Agent initialized with ccma_id: {ccma_id} (saved in {id_file_name})")
    logger.info(f"Data logged successfully in {filename}")

# Run the function
# log_ccm_data()
