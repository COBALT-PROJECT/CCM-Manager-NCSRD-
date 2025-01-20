import subprocess
import re
import os
import fnmatch
import logging
from configure_logger import configure_logger

script_name = os.path.basename(__file__)
cert_id = 5280
# logger = logging.getLogger(__name__)
logger = configure_logger(script_name, cert_id)

# Helper function to get the certificate of the host being validated
def find_certificate():
# List of common directories to search for certificates
    cert_directories = [
        "/etc/ssl",
        #"/usr/share/ca-certificates",
        "/var/lib/ca-certificates",
        "/etc/pki/tls/certs",
        "/etc/pki/ca-trust/extracted",
    ]

    preinstalled_certificates = [
        "*.0",
        "Atos_TrustedRoot_Root_CA_RSA_TLS_2021.pem",
        "CommScope_Public_Trust_ECC_Root-01.pem",
        "Sectigo_Public_Server_Authentication_Root_E46.pem",
        "CommScope_Public_Trust_RSA_Root-02.pem",
        "Atos_TrustedRoot_Root_CA_ECC_TLS_2021.pem",
        "CommScope_Public_Trust_ECC_Root-02.pem",
        "BJCA_Global_Root_CA1.pem",
        "SSL.com_TLS_RSA_Root_CA_2022.pem",
        "TrustAsia_Global_Root_CA_G3.pem",
        "CommScope_Public_Trust_RSA_Root-01.pem",
        "SSL.com_TLS_ECC_Root_CA_2022.pem",
        "TrustAsia_Global_Root_CA_G4.pem",
        "Sectigo_Public_Server_Authentication_Root_R46.pem",
        "ca-certificates.crt",
        "ssl-cert-snakeoil.pem",
        "ACCVRAIZ1.pem",
        "AC_RAIZ_FNMT-RCM.pem",
        "AC_RAIZ_FNMT-RCM_SERVIDORES_SEGUROS.pem",
        "Actalis_Authentication_Root_CA.pem",
        "AffirmTrust_Commercial.pem",
        "AffirmTrust_Networking.pem",
        "AffirmTrust_Premium_ECC.pem",
        "AffirmTrust_Premium.pem",
        "Amazon_Root_CA_1.pem",
        "Amazon_Root_CA_2.pem",
        "Amazon_Root_CA_3.pem",
        "Amazon_Root_CA_4.pem",
        "ANF_Secure_Server_Root_CA.pem",
        "Atos_TrustedRoot_2011.pem",
        "Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem",
        "Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068_2.pem",
        "Baltimore_CyberTrust_Root.pem",
        "BJCA_Global_Root_CA2.pem",
        "Buypass_Class_2_Root_CA.pem",
        "Buypass_Class_3_Root_CA.pem",
        "CA_Disig_Root_R2.pem",
        "Certainly_Root_E1.pem",
        "Certainly_Root_R1.pem",
        "Certigna.pem",
        "Certigna_Root_CA.pem",
        "certSIGN_Root_CA_G2.pem",
        "certSIGN_ROOT_CA.pem",
        "Certum_EC-384_CA.pem",
        "Certum_Trusted_Network_CA_2.pem",
        "Certum_Trusted_Network_CA.pem",
        "Certum_Trusted_Root_CA.pem",
        "CFCA_EV_ROOT.pem",
        "Comodo_AAA_Services_root.pem",
        "COMODO_Certification_Authority.pem",
        "COMODO_ECC_Certification_Authority.pem",
        "COMODO_RSA_Certification_Authority.pem",
        "D-TRUST_BR_Root_CA_1_2020.pem",
        "D-TRUST_EV_Root_CA_1_2020.pem",
        "D-TRUST_Root_Class_3_CA_2_2009.pem",
        "D-TRUST_Root_Class_3_CA_2_EV_2009.pem",
        "DigiCert_Assured_ID_Root_CA.pem",
        "DigiCert_Assured_ID_Root_G2.pem",
        "DigiCert_Assured_ID_Root_G3.pem",
        "DigiCert_Global_Root_CA.pem",
        "DigiCert_Global_Root_G2.pem",
        "DigiCert_Global_Root_G3.pem",
        "DigiCert_High_Assurance_EV_Root_CA.pem",
        "DigiCert_TLS_ECC_P384_Root_G5.pem",
        "DigiCert_TLS_RSA4096_Root_G5.pem",
        "DigiCert_Trusted_Root_G4.pem",
        "E-Tugra_Certification_Authority.pem",
        "E-Tugra_Global_Root_CA_ECC_v3.pem",
        "E-Tugra_Global_Root_CA_RSA_v3.pem",
        "emSign_ECC_Root_CA_-_C3.pem",
        "emSign_Root_CA_-_G1.pem",
        "Entrust.net_Premium_2048_Secure_Server_CA.pem",
        "Entrust_Root_Certification_Authority.pem",
        "Entrust_Root_Certification_Authority_-_EC1.pem",
        "Entrust_Root_Certification_Authority_-_G2.pem",
        "Entrust_Root_Certification_Authority_-_G4.pem",
        "ePKI_Root_Certification_Authority.pem",
        "e-Szigno_Root_CA_2017.pem",
        "emSign_Root_CA_-_C1.pem",
        "emSign_ECC_Root_CA_-_G3.pem",
        "GLOBALTRUST_2020.pem",
        "GTS_Root_R1.pem",
        "GTS_Root_R2.pem",
        "GTS_Root_R3.pem",
        "GTS_Root_R4.pem",
        "GDCA_TrustAUTH_R5_ROOT.pem",
        "Go_Daddy_Class_2_CA.pem",
        "Go_Daddy_Root_Certificate_Authority_-_G2.pem",
        "GlobalSign_ECC_Root_CA_-_R4.pem",
        "GlobalSign_ECC_Root_CA_-_R5.pem",
        "GlobalSign_Root_CA.pem",
        "GlobalSign_Root_CA_-_R3.pem",
        "GlobalSign_Root_CA_-_R6.pem",
        "GlobalSign_Root_E46.pem",
        "GlobalSign_Root_R46.pem",
        "HARICA_TLS_ECC_Root_CA_2021.pem",
        "HARICA_TLS_RSA_Root_CA_2021.pem",
        "Hellenic_Academic_and_Research_Institutions_ECC_RootCA_2015.pem",
        "Hellenic_Academic_and_Research_Institutions_RootCA_2015.pem",
        "HiPKI_Root_CA_-_G1.pem",
        "Hongkong_Post_Root_CA_1.pem",
        "Hongkong_Post_Root_CA_3.pem",
        "IdenTrust_Commercial_Root_CA_1.pem",
        "IdenTrust_Public_Sector_Root_CA_1.pem",
        "ISRG_Root_X1.pem",
        "ISRG_Root_X2.pem",
        "Izenpe.com.pem",
        "Microsec_e-Szigno_Root_CA_2009.pem",
        "Microsoft_ECC_Root_Certificate_Authority_2017.pem",
        "Microsoft_RSA_Root_Certificate_Authority_2017.pem",
        "NAVER_Global_Root_Certification_Authority.pem",
        "NetLock_Arany_=Class_Gold=_Főtanúsítvány.pem",
        "OISTE_WISeKey_Global_Root_GB_CA.pem",
        "OISTE_WISeKey_Global_Root_GC_CA.pem",
        "QuoVadis_Root_CA_1_G3.pem",
        "QuoVadis_Root_CA_2_G3.pem",
        "QuoVadis_Root_CA_2.pem",
        "QuoVadis_Root_CA_3_G3.pem",
        "QuoVadis_Root_CA_3.pem",
        "Secure_Global_CA.pem",
        "SecureSign_RootCA11.pem",
        "SecureTrust_CA.pem",
        "Security_Communication_ECC_RootCA1.pem",
        "Security_Communication_Root_CA.pem",
        "Security_Communication_RootCA2.pem",
        "Security_Communication_RootCA3.pem",
        "SSL.com_EV_Root_Certification_Authority_ECC.pem",
        "SSL.com_EV_Root_Certification_Authority_RSA_R2.pem",
        "SSL.com_Root_Certification_Authority_ECC.pem",
        "SSL.com_Root_Certification_Authority_RSA.pem",
        "Starfield_Class_2_CA.pem",
        "Starfield_Root_Certificate_Authority_-_G2.pem",
        "Starfield_Services_Root_Certificate_Authority_-_G2.pem",
        "SwissSign_Gold_CA_-_G2.pem",
        "SwissSign_Silver_CA_-_G2.pem",
        "SZAFIR_ROOT_CA2.pem",
        "Telia_Root_CA_v2.pem",
        "TeliaSonera_Root_CA_v1.pem",
        "TrustCor_ECA-1.pem",
        "TrustCor_RootCert_CA-1.pem",
        "TrustCor_RootCert_CA-2.pem",
        "Trustwave_Global_Certification_Authority.pem",
        "Trustwave_Global_ECC_P384_Certification_Authority.pem",
        "Trustwave_Global_ECC_P256_Certification_Authority.pem",
        "T-TeleSec_GlobalRoot_Class_2.pem",
        "T-TeleSec_GlobalRoot_Class_3.pem",
        "TUBITAK_Kamu_SM_SSL_Kok_Sertifikasi_-_Surum_1.pem",
        "TunTrust_Root_CA.pem",
        "TWCA_Global_Root_CA.pem",
        "TWCA_Root_Certification_Authority.pem",
        "UCA_Extended_Validation_Root.pem",
        "UCA_Global_G2_Root.pem",
        "USERTrust_ECC_Certification_Authority.pem",
        "USERTrust_RSA_Certification_Authority.pem",
        "vTrus_ECC_Root_CA.pem",
        "vTrus_Root_CA.pem",
        "XRamp_Global_CA_Root.pem",
    ]

    # Extensions of certificate files to search for
    cert_extensions = [".crt", ".pem", ".cer"]

    # List to store user-installed certificates
    user_certificates = []

    # Helper function to check if a certificate name matches the list of pre-installed certificates
    def is_preinstalled_certificate(cert_name):
        for pattern in preinstalled_certificates:
            if fnmatch.fnmatch(cert_name, pattern):
                return True
        return False

    def is_user_installed_certificate(cert_name):
        return not (cert_name.endswith(".0") or cert_name.endswith(tuple(preinstalled_certificates)))

    # Traverse through each directory
    for cert_dir in cert_directories:
        if os.path.exists(cert_dir) and os.path.isdir(cert_dir):
            logger.info("Scanning directory: %s", cert_dir)
            for root, dirs, files in os.walk(cert_dir):
                logger.info("Checking directory: %s", root)
                for file in files:
                    cert_path = os.path.join(root, file)
                    if any(file.endswith(ext) for ext in cert_extensions):
                        if not is_preinstalled_certificate(file):
                            logger.info("Found user-installed certificate: %s", cert_path)
                            user_certificates.append(cert_path)

    if not user_certificates:
        logger.info("No user-installed certificates found.")
        return None

    logger.info("User-installed certificates found.")
    for cert in user_certificates:
        logger.info(f"{cert}")
        return cert


# Helper function to get certificate information from openssl x509 command
def get_certificate_info():
    # Ask the user for the path to the certificate file
#    cert_path = input("Please enter the path to the certificate file:")
#    cert_path = "/etc/ssl/certs/mail_noc_demokritos_gr_cert.cer"

    # Dynamic search of usual certificate locations in the host system
    logger.info("Dynamic search of usual certificate locations in the system.")
    cert_path = find_certificate()

    if not cert_path:
        logger.info("Certificate not found. Exiting.")
        return {}

    logger.info("Using certificate at: %s", cert_path)

    command = ["openssl", "x509", "-noout", "-text", "-in", cert_path]
    try:
       output = subprocess.check_output( command, text=True)
    except subprocess.CalledProcessError as e:
       logger.error(f"Error executing command: {e}")
       return {}

    certificate_data = {}
    # Define regex for each piece of data to extract
    issuer_regex = r"Issuer: (.*)"
    subject_regex = r"Subject: (.*)"
    validity_not_before_regex = r"Not Before: (.*)"
    validity_not_after_regex = r"Not After : (.*)"
    signature_algorithm_regex = r"Signature Algorithm: (.*)"
    public_key_algorithm_regex = r"Public Key Algorithm: (.*)"
    public_key_regex = r"Public-Key: (.*)"

    certificate_data['issuerName'] = re.search(issuer_regex, output).group(1)
    certificate_data['subjectName'] = re.search(subject_regex, output).group(1)
    certificate_data['notValidBefore'] = re.search(validity_not_before_regex, output).group(1)
    certificate_data['notValidAfter'] = re.search(validity_not_after_regex, output).group(1)
    certificate_data['signatureAlgorithm'] = re.search(signature_algorithm_regex, output).group(1)
    certificate_data['publicKeyAlgorithm'] = re.search(public_key_algorithm_regex, output).group(1)

    # Check if RSA public key exists in the certificate
    logger.info("Checking if RSA public key exists in the certificate.")
    rsa_match = re.search(public_key_regex, output)
    certificate_data['rsaPublicKey'] = rsa_match.group(1) if rsa_match else "Not Available"

    certificate_data['rsaPublicKey'] = re.search(public_key_regex, output).group(1)
    if rsa_match:
        rsa_public_key = rsa_match.group(1)
        logger.info("RSA public key found.")
        # Remove parentheses and spaces
        rsa_public_key_clean = rsa_public_key.replace('(', '').replace(')', '').strip()
        certificate_data['rsaPublicKey'] = rsa_public_key_clean

    logger.info("Return Certificate related data to the main program.")
    return certificate_data
