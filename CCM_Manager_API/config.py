import os
from urllib.parse import urlsplit

from dotenv import load_dotenv


load_dotenv()


def _env_url(name):
    value = os.getenv(name, "").strip()
    return value.rstrip("/") if value else ""


def _join_url(base, suffix):
    if not base:
        return ""
    return f"{base}{suffix}"


def _origin_from_url(url):
    if not url:
        return ""
    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


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
DEPLOY_SDT_URL = _env_url("DEPLOY_SDT")
DEPLOYMENTS_SDT_URL = _env_url("DEPLOYMENTS_SDT")
CREATE_SDT_URL = _env_url("CREATE_SDT")
DELETE_SDT_URL = _env_url("DELETE_SDT")
SDTM_BASE_URL = (
    _env_url("SDTM_BASE_URL")
    or _env_url("SDT_BASE_URL")
    or _origin_from_url(DEPLOY_SDT_URL)
    or _origin_from_url(DEPLOYMENTS_SDT_URL)
    or _origin_from_url(CREATE_SDT_URL)
    or _origin_from_url(DELETE_SDT_URL)
)
SDT_BASE_URL = SDTM_BASE_URL
SDTM_DIGITAL_TWIN_URL = _env_url("SDTM_DIGITAL_TWIN_URL") or _join_url(SDTM_BASE_URL, "/api/SDTM/digital-twin")
SDTM_DEPLOYMENTS_URL = _env_url("SDTM_DEPLOYMENTS_URL") or _join_url(SDTM_BASE_URL, "/api/SDTM/deployments")
SDTM_AUTH_STATUS_URL = _env_url("SDTM_AUTH_STATUS_URL") or _join_url(SDTM_BASE_URL, "/api/SDTM/auth")
SDTM_ADAPT_URL = _env_url("SDTM_ADAPT_URL") or _join_url(SDTM_BASE_URL, "/api/SDTM/adapt")
SDTM_DEFAULT_PAYLOAD_TYPE = os.getenv("SDTM_PAYLOAD_TYPE", "BOMS").strip() or "BOMS"
SDTM_DEFAULT_TOE_ID = (
    os.getenv("SDTM_TOE_ID", "").strip()
    or os.getenv("SDT_TOE_ID", "").strip()
    or "00000000-0000-0000-0000-000000000000"
)
SDT_ID = os.getenv("SDT_ID", "").strip()
LEDGER_HASH_URL = os.getenv("LEDGER_HASH")
SEND_SDT_URL = os.getenv("SEND_SDT")
ENDPOINTS = [url for url in [os.getenv("ENDPOINTS")] if url]
