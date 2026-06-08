import os

from dotenv import load_dotenv


load_dotenv()


class Config:
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "./sboms")
    TMP_FOLDER = os.getenv("TMP_FOLDER", "./tmp")
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", 16 * 1024 * 1024))


MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017/")
MONGO_DB_NAME = os.getenv("MONGO_DB", "mydatabase")

LEDGER_BASE_URL = os.getenv("LEDGER_BASE_URL", "http://10.163.1.211:3000").rstrip("/")
FORWARD_URL = os.getenv("FORWARD_URL", "http://orchestrator:3000/toe/register")
LEDGER_SUBMIT_URL = f"{LEDGER_BASE_URL}/submit"

DRM_BASE_URL = os.getenv("DRM_BASE_URL", "")
DEPLOY_SDT_URL = os.getenv("DEPLOY_SDT")
DEPLOYMENTS_SDT_URL = os.getenv("DEPLOYMENTS_SDT")
CREATE_SDT_URL = os.getenv("CREATE_SDT")
DELETE_SDT_URL = os.getenv("DELETE_SDT")
LEDGER_HASH_URL = os.getenv("LEDGER_HASH")
SEND_SDT_URL = os.getenv("SEND_SDT")
ENDPOINTS = [url for url in [os.getenv("ENDPOINTS")] if url]
