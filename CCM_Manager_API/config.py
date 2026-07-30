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


def _env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name, default):
    value = os.getenv(name)
    if value is None:
        return float(default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _env_int(name, default):
    value = os.getenv(name)
    if value is None:
        return int(default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


class Config:
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "./sboms")
    TMP_FOLDER = os.getenv("TMP_FOLDER", "./tmp")
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", 16 * 1024 * 1024))


MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017/")
MONGO_DB_NAME = os.getenv("MONGO_DB", "mydatabase")

LEDGER_BASE_URL = os.getenv("LEDGER_BASE_URL", "http://10.163.1.211:3000").rstrip("/")
FORWARD_URL = os.getenv("FORWARD_URL", "http://orchestrator:3000/toe/register")
LEDGER_SUBMIT_URL = f"{LEDGER_BASE_URL}/submit"
SCHEME_IMPORT_BASE_URL = _env_url("SCHEME_IMPORT_BASE_URL") or "http://10.163.1.127:8080"
SCHEME_IMPORT_URL = _env_url("SCHEME_IMPORT_URL") or _join_url(SCHEME_IMPORT_BASE_URL, "/scheme/import")
SCHEME_IMPORT_TIMEOUT = float(os.getenv("SCHEME_IMPORT_TIMEOUT", "10"))
SCHEME_IMPORT_PAYLOAD_MODE = os.getenv("SCHEME_IMPORT_PAYLOAD_MODE", "scheme_content").strip().lower()

CCM_INBOUND_AUTH_ENABLED = _env_bool("CCM_INBOUND_AUTH_ENABLED", False)
CCM_INBOUND_ISSUER = _env_url("CCM_INBOUND_ISSUER") or _env_url("AM_BASE_URL")
CCM_INBOUND_OPENID_CONFIG_URL = (
    _env_url("CCM_INBOUND_OPENID_CONFIG_URL")
    or _join_url(CCM_INBOUND_ISSUER, "/.well-known/openid-configuration")
)
CCM_INBOUND_JWKS_URL = (
    _env_url("CCM_INBOUND_JWKS_URL")
    or _join_url(CCM_INBOUND_ISSUER, "/oauth/jwks")
)
CCM_INBOUND_USERINFO_URL = (
    _env_url("CCM_INBOUND_USERINFO_URL")
    or _join_url(CCM_INBOUND_ISSUER, "/oauth/userinfo?schema=openid")
)
CCM_INBOUND_AUDIENCE = os.getenv("CCM_INBOUND_AUDIENCE", "").strip()
CCM_INBOUND_REQUIRED_SCOPE = os.getenv("CCM_INBOUND_REQUIRED_SCOPE", "").strip()
CCM_INBOUND_REQUIRE_TYPE = os.getenv("CCM_INBOUND_REQUIRE_TYPE", "").strip()
CCM_INBOUND_ALLOWED_CLIENT_IDS = os.getenv("CCM_INBOUND_ALLOWED_CLIENT_IDS", "").strip()
CCM_INBOUND_ALLOWED_ALGS = os.getenv("CCM_INBOUND_ALLOWED_ALGS", "RS256").strip()
CCM_INBOUND_VERIFY_TLS = _env_bool("CCM_INBOUND_VERIFY_TLS", _env_bool("AM_VERIFY_TLS", True))
CCM_INBOUND_TIMEOUT = float(os.getenv("CCM_INBOUND_TIMEOUT", "5"))
CCM_INBOUND_JWKS_TTL = float(os.getenv("CCM_INBOUND_JWKS_TTL", "3600"))
CCM_INBOUND_LEEWAY = int(os.getenv("CCM_INBOUND_LEEWAY", "30"))
CCM_INBOUND_PUBLIC_PATHS = os.getenv("CCM_INBOUND_PUBLIC_PATHS", "").strip()

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

TOE_ID_HANDOFF_ENABLED = _env_bool("TOE_ID_HANDOFF_ENABLED", False)
TOE_CONNECTOR_BASE_URL = (
    _env_url("TOE_CONNECTOR_BASE_URL")
    or "http://ai-target-of-evaluation.cobalt.local:8005"
)
TOE_CONNECTOR_HEALTH_URL = (
    _env_url("TOE_CONNECTOR_HEALTH_URL")
    or _join_url(TOE_CONNECTOR_BASE_URL, "/health")
)
TOE_CONNECTOR_ID_URL = (
    _env_url("TOE_CONNECTOR_ID_URL")
    or _join_url(TOE_CONNECTOR_BASE_URL, "/api/IDSconnector/TOE/id")
)
TOE_CONNECTOR_ID_FIELD = os.getenv("TOE_CONNECTOR_ID_FIELD", "toe_id").strip() or "toe_id"
TOE_CONNECTOR_TIMEOUT_SECONDS = _env_float("TOE_CONNECTOR_TIMEOUT_SECONDS", 15)
TOE_CONNECTOR_RETRY_SECONDS = _env_float("TOE_CONNECTOR_RETRY_SECONDS", 30)
TOE_CONNECTOR_RETRY_MAX_SECONDS = _env_float("TOE_CONNECTOR_RETRY_MAX_SECONDS", 600)

SDT_ID_SYNC_ENABLED = _env_bool("SDT_ID_SYNC_ENABLED", False)
SDT_ID_SYNC_URL = (
    _env_url("SDT_ID_SYNC_URL")
    or "http://sdtm.cobalt.local:30008/api/SDT/sync/ids"
)
SDT_ID_SYNC_INTERVAL_SECONDS = _env_float("SDT_ID_SYNC_INTERVAL_SECONDS", 300)
SDT_ID_SYNC_CATEGORY = os.getenv("SDT_ID_SYNC_CATEGORY", "AI").strip() or "AI"
SDT_ID_SYNC_DATA_PATH = os.getenv("SDT_ID_SYNC_DATA_PATH", "all").strip() or "all"
SDT_ID_SYNC_TIMEOUT_SECONDS = _env_float("SDT_ID_SYNC_TIMEOUT_SECONDS", 15)

TOE_WORKFLOW_POLL_SECONDS = _env_float("TOE_WORKFLOW_POLL_SECONDS", 5)
TOE_WORKFLOW_LEASE_SECONDS = _env_float("TOE_WORKFLOW_LEASE_SECONDS", 90)
TOE_WORKFLOW_RESPONSE_MAX_CHARS = _env_int("TOE_WORKFLOW_RESPONSE_MAX_CHARS", 4000)
