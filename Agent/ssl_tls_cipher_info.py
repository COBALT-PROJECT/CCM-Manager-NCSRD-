import subprocess
import json
import re

def get_tls_cipher_info():
    # Use openssl ciphers -v to gather information about the ciphers
    command = ["openssl", "ciphers", "-v"]
    try:
        output = subprocess.check_output(command, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        return {}

    tls_info = {}

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Each line consists of several pieces of information, so we split by spaces
        parts = line.split()

        # Extract cipher name (the first part of the line)
        cipher_name = parts[0]

        # Extract TLS version (second part of the line)
        tls_version = parts[1]

        # Extract key exchange algorithm (third part of the line)
        key_exchange_algorithm = parts[2].split("=")[1] if "Kx=" in parts[2] else "N/A"

        # Extract authentication (fourth part of the line)
        authentication = parts[3].split("=")[1] if "Au=" in parts[3] else "N/A"

        # Extract encryption algorithm (fifth part of the line)
        encryption_algorithm = parts[4].split("=")[1] if "Enc=" in parts[4] else "N/A"

        # Extract MAC algorithm (sixth part of the line)
        mac = parts[5].split("=")[1] if "Mac=" in parts[5] else "N/A"

        # Create a dictionary for the cipher
        tls_info[cipher_name] = {
            "TLS_version": tls_version,
            "key_exchange_algorithm": key_exchange_algorithm,
            "authentication": authentication,
            "encryption_algorithm": encryption_algorithm,
            "mac": mac
        }
    return tls_info


def get_nmap_tls_info():
    # Run the nmap command to get TLS ciphers
    command_nmap = ["nmap", "-sV", "--script", "ssl-enum-ciphers", "-p-", "localhost"]
    try:
        output_nmap = subprocess.check_output(command_nmap, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing nmap command: {e}")
        return {}

    nmap_tls_ssl_info = {"nmap_tls_ssl_enum_ciphers_info": {}}

    curr_port = None
    curr_tls_version = None
    in_tls_section = False

    for line in output_nmap.splitlines():
        line = line.strip()
        
        # Detect port and protocol
        port_match = re.match(r"(\d+)/(\w+)\s+(\w+)", line)
        if port_match:
            curr_port = int(port_match.group(1))
            net_proto = port_match.group(2)
            status = port_match.group(3)

            # Initialize port details
            nmap_tls_ssl_info["nmap_tls_ssl_enum_ciphers_info"][curr_port] = {
                "net_proto": net_proto,
                "status": status,
                "tls_vers_enabled": {}
            }
            # Reset for new port
            curr_tls_version = None
            in_tls_section = False
            continue

        # Detect TLS version (adjusted regex to handle any spaces)
        tls_match = re.match(r"^\|?\s*(TLSv[0-9\.]+):", line)
        if tls_match:
            curr_tls_version = tls_match.group(1)
            in_tls_section = True
            nmap_tls_ssl_info["nmap_tls_ssl_enum_ciphers_info"][curr_port]["tls_vers_enabled"][curr_tls_version] = []
            continue

        # Detect cipher details if in a TLS section (adjusted regex for capturing cipher lines)
        if in_tls_section and curr_tls_version:
            cipher_suite_match = re.match(r"^\|\s*(\S.*)", line)  # Match ciphers that start with '|' or spaces
            if cipher_suite_match:
                cipher_details = cipher_suite_match.group(1)
                nmap_tls_ssl_info["nmap_tls_ssl_enum_ciphers_info"][curr_port]["tls_vers_enabled"][curr_tls_version].append(cipher_details)

    return nmap_tls_ssl_info