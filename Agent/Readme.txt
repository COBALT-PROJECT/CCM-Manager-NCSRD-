main.py calls functions from other custom python scripts that are dedicated to gathering specific information or doing specific jobs on the host system we need to validate.

Automated delivery of output file to the CCM Manager to specified endpoint has been tested and worked as intended.

Commands used:
--------------
Right now we gather information from: 
- "openssl ciphers -v", to gather the SSL ciphers on the system
- "openssl x509 -noout -text -in <certificate.cer>" where certificate.cer is dynamically found on the host system, and all pre-installed certificates that come with the installation of OpenSSL get ignored in this process, 
- "sudo sshd -T | grep algorithms" SSH algorithms' information 
- "nmap -sV --script ssl-enum-ciphers -p- localhost", to gather which TLS cipher suites are used in the system and on which ports

Text/JSON files and explanations:
---------------------------------
- oid_mappings.json is generated each time the Agent is executed and gathers the OIDs the system knows
- cipher-and-cipher-values.txt is taken from http://oid-info.com/get/1.3.6.1.4.1.11.2.4.3.20.74
- algorithms-security-levels.txt was an initial approach to gathering the security levels of several of the most known algorithms and their NIST security levels based on their keysize

Further actions:
----------------
- Check and review service and trigger
- Enrich code with information about the host's cryptographic information from the kernel


More information TBA