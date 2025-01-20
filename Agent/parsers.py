import logging
import os
from configure_logger import configure_logger, close_logger

script_name = os.path.basename(__file__)
parser_id = 4180
logger = configure_logger(script_name, parser_id)
# logger = logging.getLogger(__name__)

def parse_ciphers_file(filepath):
    logger.info("Parsing ciphers' file....")
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
    logger.info("Finished parsing ciphers' file.")
    return ciphers

def parse_security_levels(filepath):

    # Parse the algorithms-security-levels.txt file to create a mapping of
    # algorithms to their classic and NIST quantum security levels.
    logger.info("Parsing algorithms' security levels file....")
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
    logger.info("Finished parsing algorithms security levels file.")
    #close_logger(logger)
    return security_levels
