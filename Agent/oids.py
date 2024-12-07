<<<<<<< Updated upstream
import subprocess
import re
import json

# Helper function to execute the openssl list -objects command and save output to JSON
def get_system_oids():
    command = ["openssl", "list", "-objects"]
    output = subprocess.check_output(command, text=True)

    oid_mappings_file = "oid_mappings.json"

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

    return oid_mappings
=======
import subprocess
import re
import json

# Helper function to execute the openssl list -objects command and save output to JSON
def get_system_oids():
    command = ["openssl", "list", "-objects"]
    output = subprocess.check_output(command, text=True)

    oid_mappings_file = "oid_mappings.json"

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

    return oid_mappings
>>>>>>> Stashed changes
