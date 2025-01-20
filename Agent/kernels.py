import subprocess
import re
import logging
import os
from configure_logger import configure_logger, close_logger

script_name = os.path.basename(__file__)
kernel_id = 1337
logger = configure_logger(script_name, kernel_id)
# logger = logging.getLogger(__name__)

def get_kernel_info():

    # Run the command to get information from /proc/crypto
    logger.info("Gathering Kernel crypto information.")
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
    logger.info("Finished gathering Kernel crypto information.")
    #close_logger(logger)
    return kernel_info
