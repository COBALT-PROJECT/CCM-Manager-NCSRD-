from flask import Flask, g, jsonify, request, send_file
from pymongo.errors import PyMongoError
import os
import json
import logging
import time
import hashlib
import requests
from uuid import uuid4
from flask_cors import CORS
from werkzeug.utils import secure_filename

try:
    from flasgger import Swagger
except ImportError:
    Swagger = None

from auth import auth_context, auth_status_payload
from config import Config
from db import (
    cm_col,
    controls_col,
    metrics_col,
    risks_col,
    rtc_col,
    threats_col,
)
from inbound_auth import inbound_auth_status, require_inbound_auth
from services import assessment_service
from services import artifact_service
from services import catalogue_service
from services import cbom_workflow
from services import certificate_service
from services import chain_trigger
from services import certification_scheme_service as scheme_service
from services import sbom_workflow
from services import sdt_sender
from services import toe_service
from utils import hash_ip, is_valid_urn_uuid


def _env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


HTTP_LOGGING_ENABLED = _env_bool("CCM_HTTP_LOGGING_ENABLED", True)
HTTP_LOG_HEADERS_ENABLED = _env_bool("CCM_HTTP_LOG_HEADERS_ENABLED", True)
HTTP_LOG_BODY_ENABLED = _env_bool("CCM_HTTP_LOG_BODY_ENABLED", True)
HTTP_LOG_MAX_BODY_CHARS = _env_int("CCM_HTTP_LOG_MAX_BODY_CHARS", 4000)
SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
}
SENSITIVE_FIELD_MARKERS = (
    "authorization",
    "access_token",
    "refresh_token",
    "bearer",
    "client_secret",
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
)


logging.basicConfig(
    level=os.getenv("CCM_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("ccm.http")


def _is_sensitive_key(key):
    normalized = str(key or "").strip().lower()
    return any(marker in normalized for marker in SENSITIVE_FIELD_MARKERS)


def _redact_payload(value):
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _is_sensitive_key(key) else _redact_payload(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_payload(item) for item in value]
    return value


def _truncate_text(text, limit=HTTP_LOG_MAX_BODY_CHARS):
    text = str(text)
    if len(text) <= limit:
        return text
    return f"{text[:limit]}... [truncated {len(text) - limit} chars]"


def _compact_json(value):
    try:
        return json.dumps(value, default=str, ensure_ascii=False, separators=(",", ":"))
    except TypeError:
        return str(value)


def _selected_headers(headers):
    if not HTTP_LOG_HEADERS_ENABLED:
        return {}

    result = {}
    for key, value in headers.items():
        key_lower = key.lower()
        if key_lower in SENSITIVE_HEADER_NAMES:
            result[key] = "[REDACTED]"
        elif key_lower in {"accept", "content-type", "user-agent", "x-correlation-id", "x-request-id"}:
            result[key] = value
    return result


def _request_body_preview():
    if not HTTP_LOG_BODY_ENABLED:
        return None
    if request.content_length and request.content_length > HTTP_LOG_MAX_BODY_CHARS * 10:
        return f"[body omitted: {request.content_length} bytes]"
    if request.files:
        return {
            "form": dict(request.form),
            "files": {
                name: {
                    "filename": file.filename,
                    "content_type": file.content_type,
                }
                for name, file in request.files.items()
            },
        }
    if request.is_json:
        payload = request.get_json(silent=True)
        return _redact_payload(payload)
    if request.form:
        return _redact_payload(dict(request.form))
    raw_body = request.get_data(cache=True, as_text=True)
    if raw_body:
        return _truncate_text(raw_body)
    return None


def _response_body_preview(response):
    if not HTTP_LOG_BODY_ENABLED:
        return None
    if response.direct_passthrough:
        return "[streamed response]"
    content_length = response.calculate_content_length()
    if content_length and content_length > HTTP_LOG_MAX_BODY_CHARS * 10:
        return f"[body omitted: {content_length} bytes]"

    body = response.get_data(as_text=True)
    if not body:
        return None
    if response.is_json:
        try:
            return _redact_payload(json.loads(body))
        except ValueError:
            return _truncate_text(body)
    return _truncate_text(body)


app = Flask(__name__)
CORS(app)
app.config.from_object(Config)
app.config["SWAGGER"] = {
    "title": "CCM Manager API",
    "uiversion": 3,
}
swagger_template_path = os.path.join(
    os.path.dirname(__file__), "docs", "cobalt_2.json"
)
if Swagger is not None:
    Swagger(app, template_file=swagger_template_path)
else:
    logging.warning("flasgger is not installed; Swagger UI is disabled")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["TMP_FOLDER"], exist_ok=True)


@app.before_request
def log_http_request():
    if not HTTP_LOGGING_ENABLED:
        return None

    g.request_started_at = time.perf_counter()
    g.request_id = (
        request.headers.get("X-Request-ID")
        or request.headers.get("X-Correlation-ID")
        or str(uuid4())
    )
    body_preview = _request_body_preview()
    logger.info(
        "request id=%s method=%s path=%s query=%s remote=%s content_length=%s headers=%s body=%s",
        g.request_id,
        request.method,
        request.path,
        request.query_string.decode("utf-8", errors="replace"),
        request.remote_addr,
        request.content_length,
        _selected_headers(request.headers),
        _truncate_text(_compact_json(body_preview)) if body_preview is not None else None,
    )
    return None


@app.before_request
def authenticate_inbound_request():
    payload, status_code = require_inbound_auth(request)
    if status_code:
        return jsonify(payload), status_code


@app.after_request
def log_http_response(response):
    if not HTTP_LOGGING_ENABLED:
        return response

    request_id = getattr(g, "request_id", None) or str(uuid4())
    started_at = getattr(g, "request_started_at", None)
    duration_ms = None
    if started_at is not None:
        duration_ms = round((time.perf_counter() - started_at) * 1000, 2)

    body_preview = _response_body_preview(response)
    logger.info(
        "response id=%s method=%s path=%s status=%s duration_ms=%s content_length=%s headers=%s body=%s",
        request_id,
        request.method,
        request.path,
        response.status_code,
        duration_ms,
        response.calculate_content_length(),
        _selected_headers(response.headers),
        _truncate_text(_compact_json(body_preview)) if body_preview is not None else None,
    )
    response.headers.setdefault("X-Request-ID", request_id)
    return response


@app.route('/auth/status', methods=['GET'])
def auth_status():
    """Diagnostic endpoint — reports whether component auth is enabled and functional."""
    payload = auth_status_payload()
    payload["inbound"] = inbound_auth_status()
    return jsonify(payload), 200


@app.route('/')
def home():
    return jsonify({"message": "Flask API with MongoDB is running"})


@app.route('/data', methods=['POST'])
def insert_data():
    data = request.get_json()
    try:
        payload, status_code = artifact_service.insert_data(data)
        return jsonify(payload), status_code
    except PyMongoError as e:
        return jsonify({'error': 'Database error', 'details': str(e)}), 500


@app.route('/generate_sbom', methods=['POST'])
def generate_sbom():
    payload, status_code = sbom_workflow.generate_sbom_for_folder(request.form.get('folder'))
    return jsonify(payload), status_code


@app.route('/show_vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    try:
        payload, status_code = artifact_service.list_vulnerabilities()
        return jsonify(payload), status_code

    except Exception as e:
        logging.error(f"An error occurred while fetching vulnerabilities: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route('/generate_cbom', methods=['POST'])
def generate_cbom():
    payload, status_code = cbom_workflow.generate_cbom_from_request(
        request.files,
        request.form.get('hashed_ip'),
        app.config['UPLOAD_FOLDER'],
    )
    return jsonify(payload), status_code


@app.route('/receive_output', methods=['POST'])
def receive_output():
    try:
        client_ip = request.remote_addr
        hashed_ip = hash_ip(client_ip)
        print(f"Hashed IP: {hashed_ip}")

        if 'file' in request.files:
            file = request.files['file']
            filename = secure_filename(file.filename)
            if not filename or not filename.endswith('.json'):
                return jsonify({"error": "Invalid file format. Only .json files are allowed."}), 400

            temp_filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(temp_filepath)

            with open(temp_filepath, 'rb') as temp_file:
                with app.test_request_context(
                    '/generate_cbom',
                    method='POST',
                    data={'file': temp_file, 'hashed_ip': hashed_ip},
                ):
                    return generate_cbom()

        elif request.is_json:
            data = request.get_json()
            if not data:
                return jsonify({"error": "Invalid JSON data."}), 400

            temp_filename = "temp_data.json"
            temp_filepath = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
            with open(temp_filepath, 'w') as temp_file:
                json.dump(data, temp_file)

            with open(temp_filepath, 'rb') as temp_file:
                with app.test_request_context(
                    '/generate_cbom',
                    method='POST',
                    data={'file': temp_file, 'hashed_ip': hashed_ip},
                ):
                    return generate_cbom()

        else:
            return jsonify({"error": "No valid input provided."}), 400

    except Exception as e:
        logging.error(f"Error in receive_output: {str(e)}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


def generate_hash(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


# @app.route('/upload_oscal', methods=['POST'])
# def upload_oscal():
#     if request.is_json:
#         oscal_json = request.get_json()
#     elif 'file' in request.files:
#         file = request.files['file']
#         oscal_json = json.load(file)
#     else:
#         return jsonify({"error": "No JSON data or file provided."}), 400

#     oscal_type = None
#     if "component-definition" in oscal_json:
#         oscal_type = "component-definition"
#         doc_uuid = str(uuid4())  # generate new UUID for this type
#     elif "catalog" in oscal_json and "uuid" in oscal_json["catalog"]:
#         oscal_type = "catalog"
#         doc_uuid = oscal_json["catalog"]["uuid"]
#     elif "profile" in oscal_json and "uuid" in oscal_json["profile"]:
#         oscal_type = "profile"
#         doc_uuid = oscal_json["profile"]["uuid"]
#     else:
#         return jsonify({"error": "Unrecognized OSCAL type or missing UUID."}), 400

#     doc_hash = generate_hash(oscal_json)

#     if oscal_type in ["catalog", "profile"]:
#         existing = collection.find_one({"uuid": doc_uuid})
#         if existing:
#             if oscal_type in existing:
#                 return jsonify({
#                     "message": f"Duplicate {oscal_type} already exists for this UUID.",
#                     "uuid": doc_uuid
#                 }), 200

#             collection.update_one(
#                 {"uuid": doc_uuid},
#                 {"$set": {
#                     oscal_type: oscal_json,
#                     f"{oscal_type}_hash": doc_hash
#                 }}
#             )
#             return jsonify({
#                 "message": f"{oscal_type} added to existing UUID.",
#                 "uuid": doc_uuid
#             }), 200

#         new_doc = {
#             "uuid": doc_uuid,
#             oscal_type: oscal_json,
#             f"{oscal_type}_hash": doc_hash
#         }
#         collection.insert_one(new_doc)
#         return jsonify({
#             "message": f"{oscal_type} document saved successfully.",
#             "uuid": doc_uuid
#         }), 200

#     else:
#         existing = collection.find_one({"oscal_type": oscal_type, "hash": doc_hash})
#         if existing:
#             return jsonify({
#                 "message": "Duplicate document already exists.",
#                 "uuid": existing["uuid"]
#             }), 200

#         wrapped_doc = {
#             "uuid": doc_uuid,
#             "hash": doc_hash,
#             "oscal_type": oscal_type,
#             "content": oscal_json
#         }
#         collection.insert_one(wrapped_doc)
#         return jsonify({
#             "message": f"{oscal_type} document saved successfully.",
#             "uuid": doc_uuid
#         }), 200


@app.route('/upload_oscal', methods=['POST'])
def upload_oscal():
    if request.is_json:
        oscal_json = request.get_json(silent=True)
    elif 'file' in request.files:
        try:
            oscal_json = json.load(request.files['file'])
        except (json.JSONDecodeError, UnicodeDecodeError):
            return jsonify({"error": "Invalid JSON file."}), 400
    else:
        return jsonify({"error": "No JSON data or file provided."}), 400

    payload, status_code = artifact_service.upload_oscal(oscal_json)
    return jsonify(payload), status_code


@app.route('/oscal_ids/<doc_uuid>', methods=['GET'])
def get_oscal_ids_by_doc_uuid(doc_uuid):
    payload, status_code = artifact_service.get_oscal_control_ids(doc_uuid)
    return jsonify(payload), status_code


def is_valid_uuid(value):
    return is_valid_urn_uuid(value)


@app.route('/upload_saasbom', methods=['POST'])
def upload_saasbom():
    if not request.is_json:
        return jsonify({"error": "No JSON data provided."}), 400

    saasbom_json = request.get_json()
    payload, status_code = artifact_service.upload_saasbom(saasbom_json)
    return jsonify(payload), status_code


# @app.route("/upload_toe_descriptor", methods=["POST"])
# def upload_toe_descriptor():
#     data = request.get_json()

#     # Check for optional scheme linking parameter
#     # Can be passed in URL (?scheme_id=...) or body
#     scheme_id = request.args.get('scheme_id') or data.get('certification_scheme_id')

#     if not data or "component" not in data:
#         return jsonify({"error": "Missing 'component' in payload"}), 400

#     try:
#         comp_def = data["component"].get("component-definition", {})
#         components = comp_def.get("components", [])

#         if not components:
#             return jsonify({"error": "No components found"}), 400

#         toe_uuid = components[0].get("uuid")
#         toe_name = components[0].get("title")

#         if not toe_uuid:
#             return jsonify({"error": "Missing ToE UUID"}), 400

#         # 1. Validate Scheme Link if provided
#         linked_scheme = None
#         if scheme_id:
#             linked_scheme = schemes_col.find_one({"uuid": scheme_id})
#             if not linked_scheme:
#                 return jsonify({"error": f"Scheme {scheme_id} not found. Cannot link ToE."}), 404

#         # 2. Store ToE with Link
#         toe_entry = {
#             "type": "target_of_evaluation",
#             "uuid": toe_uuid,
#             "name": toe_name,
#             "content": data,
#             "linked_scheme_id": scheme_id, # <--- CRITICAL LINK
#             "timestamp": datetime.utcnow().isoformat()
#         }

#         toes_col.update_one(
#             {"uuid": toe_uuid},
#             {"$set": toe_entry},
#             upsert=True
#         )

#         # 3. Forward to Orchestrator/SDT (as per original logic)
#         try:
#             if FORWARD_URL:
#                 requests.post(FORWARD_URL, json=data, timeout=5)
#         except Exception as e:
#             logging.warning(f"Failed to forward ToE to Orchestrator: {e}")

#         return jsonify({
#             "message": "ToE registered and linked successfully",
#             "toe_uuid": toe_uuid,
#             "linked_scheme": scheme_id if scheme_id else "None (Warning: Scheme needed for certification)"
#         }), 200

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


@app.route("/upload_toe_descriptor", methods=["POST"])
def upload_toe_descriptor():
    data = request.get_json(silent=True)
    scheme_id = request.args.get('scheme_id') or (data or {}).get('certification_scheme_id')
    deploy_sdt = (data or {}).get("deploy_sdt")
    if deploy_sdt is None:
        deploy_sdt = request.args.get("deploy_sdt")

    sdt_bom_path = (
        request.args.get("sdt_bom_path")
        or request.args.get("bom_path")
        or (data or {}).get("sdt_bom_path")
        or (data or {}).get("bom_path")
    )
    sdt_payload_type = (
        request.args.get("payload_type")
        or request.args.get("sdt_payload_type")
        or (data or {}).get("payload_type")
        or (data or {}).get("sdt_payload_type")
        or (data or {}).get("category")
    )

    payload, status_code = toe_service.upload_toe_descriptor(
        data,
        scheme_id,
        deploy_sdt=deploy_sdt,
        sdt_bom_path=sdt_bom_path,
        sdt_payload_type=sdt_payload_type,
    )
    return jsonify(payload), status_code


@app.route("/upload_certification_scheme", methods=["POST"])
def upload_certification_scheme():
    if not request.is_json:
        return jsonify({"error": "No JSON data provided"}), 400

    data = request.get_json(silent=True)
    sync_drm_on_upload = request.args.get("sync_drm") or request.args.get("drm_sync")
    if sync_drm_on_upload is None and isinstance(data, dict):
        sync_drm_on_upload = data.get("sync_drm", data.get("drm_sync"))
    sync_scheme_import_on_upload = (
        request.args.get("sync_scheme_import")
        or request.args.get("scheme_import_sync")
        or request.args.get("import_scheme")
    )
    if sync_scheme_import_on_upload is None and isinstance(data, dict):
        sync_scheme_import_on_upload = data.get(
            "sync_scheme_import",
            data.get("scheme_import_sync", data.get("import_scheme")),
        )

    payload, status_code = scheme_service.upload_certification_scheme(
        data,
        sync_drm_on_upload=sync_drm_on_upload,
        sync_scheme_import_on_upload=sync_scheme_import_on_upload,
    )
    return jsonify(payload), status_code


# --- Scheme Mapping & Export Endpoints ---

@app.route('/schemes/<scheme_id>/mappings/rtc', methods=['GET'])
def get_rtc_mappings(scheme_id):
    """Get all Risk↔Threat↔Control triplets for a scheme."""
    try:
        payload, status_code = scheme_service.get_mappings(rtc_col, scheme_id)
        return jsonify(payload), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/schemes/<scheme_id>/mappings/rtc', methods=['POST'])
def set_rtc_mappings(scheme_id):
    """Bulk create/replace R↔T↔C triplets for a scheme. Replaces all existing."""
    data = request.get_json()
    try:
        payload, status_code = scheme_service.replace_mappings(
            rtc_col,
            scheme_id,
            data,
            "R↔T↔C",
            "{risk_id, threat_id, control_id}",
        )
        return jsonify(payload), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/schemes/<scheme_id>/mappings/cm', methods=['GET'])
def get_cm_mappings(scheme_id):
    """Get all Control↔Metric mappings for a scheme."""
    try:
        payload, status_code = scheme_service.get_mappings(cm_col, scheme_id)
        return jsonify(payload), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/schemes/<scheme_id>/mappings/cm', methods=['POST'])
def set_cm_mappings(scheme_id):
    """Bulk create/replace C↔M mappings for a scheme. Replaces all existing."""
    data = request.get_json()
    try:
        payload, status_code = scheme_service.replace_mappings(
            cm_col,
            scheme_id,
            data,
            "C↔M",
            "{control_id, metric_id}",
        )
        return jsonify(payload), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/schemes/<scheme_id>/export', methods=['GET'])
def export_scheme(scheme_id):
    """Full scheme export for DRM consumption — includes all entities and mappings."""
    try:
        payload, status_code = scheme_service.export_scheme(scheme_id)
        return jsonify(payload), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/schemes/<scheme_id>/sync-drm', methods=['POST'])
def sync_drm(scheme_id):
    """Forward the full scheme export to the DRM for ingestion."""
    try:
        payload, status_code = scheme_service.sync_drm(scheme_id)
        return jsonify(payload), status_code

    except Exception as e:
        logging.error(f"DRM sync failed for scheme {scheme_id}: {e}")
        return jsonify({
            "error": f"DRM sync failed: {str(e)}",
            "outbound_auth": [auth_context("drm")],
        }), 502


# --- CRUD Endpoints for Risk Catalogue Entities ---

# Metrics
@app.route('/metrics', methods=['GET'])
def get_all_metrics():
    try:
        payload, status_code = catalogue_service.list_documents(metrics_col)
        return jsonify(payload), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/metrics/<id>', methods=['GET'])
def get_metric(id):
    try:
        payload, status_code = catalogue_service.get_document(metrics_col, "id", id, "Metric")
        return jsonify(payload), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/metrics', methods=['POST', 'PUT'])
def upload_or_update_metric():
    if not request.is_json:
        return jsonify({"error": "No JSON data provided."}), 400
    data = request.get_json()
    try:
        payload, status_code = catalogue_service.upsert_documents(
            metrics_col,
            data,
            catalogue_service.metric_key,
            "Metric must have an 'id'.",
            "metrics",
            "id",
        )
        return jsonify(payload), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Risks
@app.route('/risks', methods=['GET'])
def get_all_risks():
    try:
        payload, status_code = catalogue_service.list_documents(risks_col)
        return jsonify(payload), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/risks/<risk_id>', methods=['GET'])
def get_risk(risk_id):
    try:
        payload, status_code = catalogue_service.get_document(risks_col, "risk_id", risk_id, "Risk")
        return jsonify(payload), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/risks', methods=['POST', 'PUT'])
def upload_or_update_risk():
    if not request.is_json:
        return jsonify({"error": "No JSON data provided."}), 400
    data = request.get_json()
    try:
        payload, status_code = catalogue_service.upsert_documents(
            risks_col,
            data,
            catalogue_service.risk_key,
            "Risk must have a 'risk_id'.",
            "risks",
            "risk_id",
        )
        return jsonify(payload), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Threats
@app.route('/threats', methods=['GET'])
def get_all_threats():
    try:
        payload, status_code = catalogue_service.list_documents(threats_col)
        return jsonify(payload), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/threats/<threat_id>', methods=['GET'])
def get_threat(threat_id):
    try:
        payload, status_code = catalogue_service.get_document(threats_col, "threat_id", threat_id, "Threat")
        return jsonify(payload), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/threats', methods=['POST', 'PUT'])
def upload_or_update_threat():
    if not request.is_json:
        return jsonify({"error": "No JSON data provided."}), 400
    data = request.get_json()
    try:
        payload, status_code = catalogue_service.upsert_documents(
            threats_col,
            data,
            catalogue_service.threat_key,
            "Threat must have a 'threat_id'.",
            "threats",
            "threat_id",
        )
        return jsonify(payload), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Controls
@app.route('/controls', methods=['GET'])
def get_all_controls():
    try:
        payload, status_code = catalogue_service.list_documents(controls_col)
        return jsonify(payload), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/controls/<control_id>', methods=['GET'])
def get_control(control_id):
    try:
        payload, status_code = catalogue_service.get_document(controls_col, "control_id", control_id, "Control")
        return jsonify(payload), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/controls', methods=['POST', 'PUT'])
def upload_or_update_control():
    if not request.is_json:
        return jsonify({"error": "No JSON data provided."}), 400
    data = request.get_json()
    try:
        payload, status_code = catalogue_service.upsert_documents(
            controls_col,
            data,
            catalogue_service.control_key,
            "Control must have a 'control_id' or equivalent.",
            "controls",
            "control_id",
        )
        return jsonify(payload), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/store-ledger', methods=['POST'])
def store_ledger_entry():
    oscal_json = request.get_json(force=True)
    payload, status_code = artifact_service.store_ledger_entry(oscal_json)
    return jsonify(payload), status_code


@app.route('/update-ledger/<uuid>', methods=['PUT'])
def update_ledger_entry(uuid):
    oscal_json = request.get_json(force=True)
    payload, status_code = artifact_service.update_ledger_entry(uuid, oscal_json)
    return jsonify(payload), status_code


@app.route("/send_sdt", methods=["POST"])
def send_std():
    try:
        data = request.get_json(silent=True) or {}
        bom_content = data.get("bom_content") or data.get("bom")
        if not (data.get("hash") or data.get("bom_path") or bom_content is not None):
            return jsonify({"error": "Missing 'hash', 'bom_path', or 'bom_content' in request body"}), 400

        payload, status_code = sdt_sender.send_sdt(
            data.get("hash"),
            bom_path=data.get("bom_path"),
            toe_id=data.get("toe_id"),
            category=data.get("category"),
            deployment_payload=data.get("payload"),
            bom_content=bom_content,
            bom_source=data.get("bom_source") or "request.bom_content",
        )
        return jsonify(payload), status_code

    except requests.RequestException as e:
        print(f"\nRequest error: {e}")
        return jsonify({
            "error": "Request failed",
            "details": str(e),
            "outbound_auth": [auth_context("sdt")],
        }), 502
    except Exception as ex:
        print(f"\nUnexpected error: {ex}")
        return jsonify({
            "error": "Unexpected error",
            "details": str(ex),
            "outbound_auth": [auth_context("sdt")],
        }), 500


@app.route('/trigger_delete', methods=['POST'])
def trigger_delete():
    data = request.get_json()
    if not data or "identifier" not in data:
        return jsonify({"error": "Missing 'identifier' in request body"}), 400

    try:
        payload, status_code = sdt_sender.trigger_delete(data["identifier"])
        return jsonify(payload), status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/send_records', methods=['POST'])
def receive_and_forward():
    try:
        incoming_data = request.get_json(silent=True)
        payload, status_code = artifact_service.receive_and_forward(incoming_data)
        return jsonify(payload), status_code

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/trigger-chain', methods=['POST'])
def trigger_chain_post():
    payload, status_code = chain_trigger.trigger_chain(request.get_json())
    return jsonify(payload), status_code


@app.route('/stop-sdt', methods=['GET'])
def stop_sdt():
    time.sleep(10)
    print("SDT manager has stopped")
    return "SDT manager stopped", 200


@app.route('/evidence', methods=['POST'])
def upload_evidence():
    try:
        evidence = request.get_json(force=True)
        payload, status_code = artifact_service.upload_evidence(evidence)
        return jsonify(payload), status_code
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route('/assessment-result', methods=['POST'])
def post_assessment_result():
    try:
        payload, status_code = assessment_service.process_assessment_result(request.get_json())
        return jsonify(payload), status_code

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/retrieve_toe/<toe_id>', methods=['GET'])
def retrieve_toe_data(toe_id):
    try:
        payload, status_code = toe_service.retrieve_toe_data(toe_id)
        return jsonify(payload), status_code

    except Exception as e:
        logging.error(f"Error retrieving ToE data: {e}")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route('/toes/search', methods=['GET'])
def search_toe_by_id():
    toe_id = request.args.get("toe_id") or request.args.get("id")
    payload, status_code = toe_service.search_toe_by_id(toe_id)
    return jsonify(payload), status_code


@app.route('/toes/<toe_id>', methods=['GET'])
def get_toe_by_id(toe_id):
    payload, status_code = toe_service.search_toe_by_id(toe_id)
    return jsonify(payload), status_code


@app.route('/sdts', methods=['GET'])
def get_sdts():
    try:
        payload, status_code = sdt_sender.get_sdt_ids()
        return jsonify(payload), status_code
    except requests.RequestException as e:
        return jsonify({
            "error": "Failed to fetch from SDT service",
            "details": str(e),
            "outbound_auth": [auth_context("sdt")],
        }), 502


@app.route('/sdts/<twin_id>', methods=['GET'])
def get_sdt(twin_id):
    try:
        payload, status_code = sdt_sender.get_sdt(twin_id)
        return jsonify(payload), status_code
    except requests.RequestException as e:
        return jsonify({
            "error": "Failed to fetch SDT instance",
            "details": str(e),
            "outbound_auth": [auth_context("sdt")],
        }), 502


@app.route('/retrieve_toes', methods=['GET'])
def retrieve_all_toes():
    try:
        payload, status_code = toe_service.retrieve_all_toes()
        return jsonify(payload), status_code

    except Exception as e:
        logging.error(f"Error retrieving all ToEs: {e}")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route('/certificates', methods=['GET'])
def get_all_certificates():
    try:
        payload, status_code = certificate_service.list_certificates()
        return jsonify(payload), status_code

    except Exception as e:
        logging.error(f"Error retrieving all certificates: {e}")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route('/certificates/<cert_uuid>', methods=['GET'])
def get_certificate(cert_uuid):
    try:
        payload, status_code = certificate_service.get_certificate(cert_uuid)
        return jsonify(payload), status_code

    except Exception as e:
        logging.error(f"Error retrieving certificate {cert_uuid}: {e}")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route('/certificates/<cert_uuid>/pdf', methods=['GET'])
def download_certificate_pdf(cert_uuid):
    try:
        regenerate = str(request.args.get("regenerate", "")).lower() in {"1", "true", "yes"}
        payload, status_code = certificate_service.get_certificate_pdf(
            cert_uuid,
            regenerate=regenerate,
        )
        if status_code != 200:
            return jsonify(payload), status_code

        return send_file(
            payload["pdf_path"],
            mimetype="application/pdf",
            as_attachment=True,
            download_name=payload["download_name"],
        )

    except Exception as e:
        logging.error(f"Error downloading certificate PDF {cert_uuid}: {e}")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route('/certificate-evaluation-result', methods=['POST'])
@app.route('/certificates/evaluation-result', methods=['POST'])
def post_certificate_evaluation_result():
    try:
        payload, status_code = certificate_service.update_certificate_evaluation_result(
            request.get_json(silent=True),
        )
        return jsonify(payload), status_code

    except Exception as e:
        logging.error(f"Error updating certificate from evaluation result: {e}")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route("/certification_scheme/<scheme_id>", methods=["GET"])
def get_certification_scheme(scheme_id):
    try:
        payload, status_code = certificate_service.get_certification_scheme(scheme_id)
        return jsonify(payload), status_code

    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route("/certification_scheme/<scheme_id>/catalog", methods=["GET"])
def get_certification_scheme_catalog(scheme_id):
    try:
        payload, status_code = certificate_service.get_certification_scheme_section(scheme_id, "catalog")
        return jsonify(payload), status_code

    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route("/certification_scheme/<scheme_id>/profile", methods=["GET"])
def get_certification_scheme_profile(scheme_id):
    try:
        payload, status_code = certificate_service.get_certification_scheme_section(scheme_id, "profile")
        return jsonify(payload), status_code

    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route("/certificates/<cert_uuid>/catalog", methods=["GET"])
def get_certificate_catalog(cert_uuid):
    try:
        payload, status_code = certificate_service.get_certificate_scheme_section(cert_uuid, "catalog")
        return jsonify(payload), status_code

    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route("/certificates/<cert_uuid>/profile", methods=["GET"])
def get_certificate_profile(cert_uuid):
    try:
        payload, status_code = certificate_service.get_certificate_scheme_section(cert_uuid, "profile")
        return jsonify(payload), status_code

    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route("/certification_scheme/<scheme_id>", methods=["DELETE"])
def delete_certification_scheme(scheme_id):
    try:
        payload, status_code = certificate_service.delete_certification_scheme(scheme_id)
        return jsonify(payload), status_code

    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route("/certification_schemes", methods=["GET"])
def get_all_certification_schemes():
    try:
        payload, status_code = certificate_service.list_certification_schemes()
        return jsonify(payload), status_code

    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route('/certificates/<cert_uuid>/withdraw', methods=['PUT'])
def withdraw_certificate(cert_uuid):
    try:
        payload, status_code = certificate_service.withdraw_certificate(cert_uuid)
        return jsonify(payload), status_code
    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


if __name__ == '__main__':
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    catalogue_sources = [
        (
            os.getenv(
                "AI_CATALOGUE_PATH",
                os.path.join(data_dir, "eucs", "global_certification_scheme_fully_mapped.json"),
            ),
            os.getenv(
                "EUCS_CONTROLS_CATALOGUE_PATH",
                os.path.join(data_dir, "eucs", "EUCS_controls_version_1.1_catalog_master.json"),
            ),
        ),
        (
            os.getenv(
                "QUANTUM_CATALOGUE_PATH",
                os.path.join(data_dir, "Quantum", "global_certification_scheme_quantum_fully_mapped.json"),
            ),
            os.getenv(
                "QUANTUM_CONTROLS_CATALOGUE_PATH",
                os.path.join(data_dir, "Quantum", "Quantum_controls_version_1.0_catalog_master.json"),
            ),
        ),
    ]
    for catalogue_path, controls_catalogue_path in catalogue_sources:
        try:
            catalogue_service.initialize_ai_catalogue(
                catalogue_path,
                controls_catalogue_path,
                force_upsert=True,
            )
        except Exception as e:
            logging.error(f"Failed to auto-initialize catalogue from {catalogue_path}: {e}")

    app.run(host='0.0.0.0', port=5001, debug=True)
    # DEV CCM MANAGER CODE BELOW THIS LINE IS FOR TESTING PURPOSES ONLY - NOT FOR PRODUCTION USE YET
