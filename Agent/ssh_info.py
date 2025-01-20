import subprocess
import logging
import os
from configure_logger import configure_logger, close_logger

script_name = os.path.basename(__file__)
ssh_id = 4253
logger = configure_logger(script_name, ssh_id)
# logger = logging.getLogger(__name__)

def get_ssh_crypto_info():
    logger.info("Gathering SSH crypto information....")
    try:
        # Execute the command to gather algorithm-related settings from SSH
        command = ["sshd", "-T"]
        output = subprocess.check_output(command, text=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"[{ssh_id}]: Error executing command: {e}")
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
                logger.error(f"[{ssh_id}]: Skipping line due to format error: {line} - value error: {ve}")
        elif "ciphers" in line:
            try:
                key,value = line.split(None, 1)
                ciphers = value.split(',')
                ssh_crypto_info[key] = ciphers
            except ValueError as ve:
                logger.error(f"[{ssh_id}]: Skipping line due to format error: {line} - value error: {ve}")
        elif "macs" in line:
            try:
                key, value = line.split(None, 1)
                macs = value.split(',')
                ssh_crypto_info[key] = macs
            except ValueError as ve:
                logger.error(f"[{ssh_id}]: Skipping line due to format error: {line} - value error: {ve}")


    #print(json.dumps({"ssh_crypto_info": ssh_crypto_info}, indent=2))
    logger.info("Finished gathering SSH crypto information.")
    return ssh_crypto_info

def filter_matching_algorithms(ssh_crypto_info, algorithms):
    # We will now iterate over the algorithm types in ssh_crypto_info
    # Make a copy of the dictionary for safe iteration
    logger.info("Starting SSH information iteration for safe iteration")
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
    logger.info("Finished iteration.")
    return ssh_crypto_info, algorithms

#close_logger(logger)
