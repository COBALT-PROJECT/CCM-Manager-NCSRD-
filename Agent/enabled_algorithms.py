import subprocess
import re
import os
import logging
from configure_logger import configure_logger, close_logger

script_name = os.path.basename(__file__)
enabled_id = 8446
logger = configure_logger(script_name, enabled_id)
# logger = logging.getLogger(__name__)

#Helper function to get all algorithms within the system
def get_all_algorithms():
    #Gathering signature and cipher algorithms to be inserted into a list
    # Define commands to fetch algorithms
    logger.info("Gathering SSL Algorithms information...")
    commands = [
        ["openssl", "list", "-signature-algorithms"],
        ["openssl", "list", "-cipher-algorithms"]
    ]

    all_algos = {}

    # Process each command
    for command in commands:
        try:
            output = subprocess.check_output(command, text=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Error executing command: {e}")
            return []

    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue


        main_part = line.split('{')[1].split('}')[0]
        elements = [item.strip() for item in main_part.split(',')]

        # Separate OIDs and algorithm names
        oids = [elem for elem in elements if re.match(r"^\d+(\.\d+)+$", elem)]
        names = [elem for elem in elements if not re.match(r"^\d+(\.\d+)+$", elem)]
               #[elements.pop(0).strip() for _ in range(2)] if len(elements) > 2 else [elements.pop(0).strip()]

        # Associate OIDs with algorithm names
        for index, algo_name in enumerate(names):
            oid = oids[index] if index < len(oids) else "N/A"
            all_algos[algo_name] = {"algo_oid": oid}


    #Debugging output if needed
    # print("Algos gathered: ", all_algos)

    logger.info("SSL Algorithms information gathered.")
    return all_algos


# Helper function to get the list of disabled algorithms
def get_disabled_algorithms():
    logger.info("Gathering system's disabled algorithms, if any....")
    command = ["openssl", "list", "-disabled"]
    output = subprocess.check_output(command, text=True)

    disabled_algorithms = set()  # Use a set to store disabled algorithms for fast lookup

    # Split the output by lines and process each line
    for line in output.splitlines():
        if line and line != "Disabled algorithms:" :
            disabled_algorithms.add(line.strip())
    # Debugging output if needed
#    print("Disabled:", disabled_algorithms)
    logger.info("Gathered disabled algorithms.")
    return disabled_algorithms


# Function to filter out disabled algorithms
#def filter_disabled_algorithms(algorithms, disabled_algorithms):
#    filtered_algorithms = [algo for algo in algorithms if algo["name"] not in disabled_algorithms]
#    return filtered_algorithms

# Function to filter out disabled algorithms
def filter_enabled_algorithms(algorithms, disabled_algorithms):
    logger.info("Filtering out disabled algorithms from collection.")
    enabled_algorithms = {}

    for algo_name, algo_data in algorithms.items():
        # Check if the algorithm name starts with or contains any of the disabled algorithms
        if not any(disabled in algo_name for disabled in disabled_algorithms):
            enabled_algorithms[algo_name.strip(" }")] = algo_data

    #Debugging output if needed
    # print("Enabled algos gathered: ", enabled_algorithms)

    return enabled_algorithms


# Main function to get enabled algorithms
def get_enabled_algorithms():
    logger.info("Gathering enbaled algorithms.")
    all_algorithms = get_all_algorithms()
    disabled_algorithms = get_disabled_algorithms()

    # Filter out the disabled algorithms
    enabled_algorithms = filter_enabled_algorithms(all_algorithms, disabled_algorithms)

    #Debugging output if needed
    # print("Enabled algos gathered: ", enabled_algorithms)

#    #close_logger(logger)
    return enabled_algorithms
