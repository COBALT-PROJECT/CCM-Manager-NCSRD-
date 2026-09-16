"""Best-effort MQTT publication for CCM operational failure alerts."""

import json
import logging
import re
import threading
from datetime import datetime, timezone
from uuid import uuid4

try:
    from flask import g, has_request_context, request
except ImportError:  # pragma: no cover - Flask is part of the CCM runtime
    g = None
    request = None

    def has_request_context():
        return False

try:
    from paho.mqtt import client as mqtt
    from paho.mqtt import publish
except ImportError:  # Allows a useful log message before dependencies are rebuilt.
    mqtt = None
    publish = None

from config import (
    MQTT_ALERT_TOPIC,
    MQTT_ALERTS_ENABLED,
    MQTT_BROKER_HOST,
    MQTT_BROKER_PORT,
    MQTT_DETAILS_MAX_CHARS,
    MQTT_KEEPALIVE_SECONDS,
    MQTT_PASSWORD,
    MQTT_QOS,
    MQTT_RETAIN,
    MQTT_TLS_ENABLED,
    MQTT_USERNAME,
)


LOGGER = logging.getLogger("ccm.mqtt_alerts")
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
_active_failure_keys = set()
_dedupe_lock = threading.Lock()
SENSITIVE_TEXT_PATTERN = re.compile(
    r"(?i)(authorization|access_token|refresh_token|client_secret|password|secret|api_key|apikey)"
    r"(\s*[:=]\s*)([^\s,;&]+)"
)
BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")


def _is_sensitive_key(key):
    normalized = str(key or "").strip().lower()
    return any(marker in normalized for marker in SENSITIVE_FIELD_MARKERS)


def _sanitize(value):
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if _is_sensitive_key(key) else _sanitize(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [_sanitize(item) for item in value]
    if isinstance(value, str):
        value = SENSITIVE_TEXT_PATTERN.sub(r"\1\2[REDACTED]", value)
        value = BEARER_PATTERN.sub("Bearer [REDACTED]", value)
        if len(value) > MQTT_DETAILS_MAX_CHARS:
            omitted = len(value) - MQTT_DETAILS_MAX_CHARS
            return f"{value[:MQTT_DETAILS_MAX_CHARS]}... [truncated {omitted} chars]"
        return value
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


def _request_details():
    if not has_request_context():
        return {}
    return {
        "request_id": getattr(g, "request_id", None),
        "method": request.method,
        "path": request.path,
    }


def _bounded_details(details):
    sanitized = _sanitize(details)
    encoded = json.dumps(sanitized, ensure_ascii=False, default=str)
    if len(encoded) <= MQTT_DETAILS_MAX_CHARS:
        return sanitized

    if isinstance(sanitized, dict):
        compact = {
            key: value
            for key, value in sanitized.items()
            if key not in {"response", "response_body", "body", "payload"}
        }
        compact["details_truncated"] = True
        compact_encoded = json.dumps(compact, ensure_ascii=False, default=str)
        if len(compact_encoded) <= MQTT_DETAILS_MAX_CHARS:
            return compact

    omitted = len(encoded) - MQTT_DETAILS_MAX_CHARS
    return {
        "summary": f"{encoded[:MQTT_DETAILS_MAX_CHARS]}... [truncated {omitted} chars]",
        "details_truncated": True,
    }


def _mark_request_alerted():
    if has_request_context():
        g.mqtt_failure_alert_emitted = True


def request_alert_was_emitted():
    return bool(
        has_request_context()
        and getattr(g, "mqtt_failure_alert_emitted", False)
    )


def clear_failure(dedupe_key):
    """Allow a future failure episode for a background operation to alert again."""
    if not dedupe_key:
        return
    with _dedupe_lock:
        _active_failure_keys.discard(str(dedupe_key))


def _is_duplicate(dedupe_key):
    if not dedupe_key:
        return False
    with _dedupe_lock:
        return str(dedupe_key) in _active_failure_keys


def _remember_failure(dedupe_key):
    if not dedupe_key:
        return
    with _dedupe_lock:
        _active_failure_keys.add(str(dedupe_key))


def build_failure_payload(operation, message, severity="critical", details=None, event_id=None):
    supplied_details = details if isinstance(details, dict) else {"context": details}
    merged_details = {**_request_details(), **(supplied_details or {})}
    merged_details = {key: value for key, value in merged_details.items() if value is not None}
    return {
        "event_id": event_id or f"failure-{uuid4()}",
        "state": "failed",
        "severity": severity,
        "operation": _sanitize(str(operation)),
        "message": _sanitize(str(message)),
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "details": _bounded_details(merged_details),
    }


def publish_failure(
    operation,
    message,
    severity="critical",
    details=None,
    event_id=None,
    dedupe_key=None,
):
    """Publish one failure without ever changing the caller's error handling."""
    _mark_request_alerted()

    if not MQTT_ALERTS_ENABLED:
        return {"status": "disabled"}
    if _is_duplicate(dedupe_key):
        return {"status": "duplicate"}

    try:
        payload = build_failure_payload(operation, message, severity, details, event_id)
    except Exception as exc:
        LOGGER.warning("Failed to build MQTT alert payload: %s", exc)
        return {"status": "failed", "error": str(exc)}
    if publish is None or mqtt is None:
        LOGGER.error(
            "MQTT alert %s could not be published because paho-mqtt is unavailable",
            payload["event_id"],
        )
        return {"status": "failed", "event_id": payload["event_id"]}

    auth = None
    if MQTT_USERNAME:
        auth = {"username": MQTT_USERNAME, "password": MQTT_PASSWORD or None}
    tls = {} if MQTT_TLS_ENABLED else None

    try:
        publish.single(
            topic=MQTT_ALERT_TOPIC,
            payload=json.dumps(payload, ensure_ascii=False, default=str),
            hostname=MQTT_BROKER_HOST,
            port=MQTT_BROKER_PORT,
            qos=MQTT_QOS,
            retain=MQTT_RETAIN,
            keepalive=MQTT_KEEPALIVE_SECONDS,
            auth=auth,
            tls=tls,
            protocol=mqtt.MQTTv311,
        )
        _remember_failure(dedupe_key)
        LOGGER.info(
            "Published MQTT failure alert event_id=%s operation=%s topic=%s",
            payload["event_id"],
            payload["operation"],
            MQTT_ALERT_TOPIC,
        )
        return {"status": "published", "event_id": payload["event_id"]}
    except Exception as exc:  # MQTT failure must never mask the original failure.
        LOGGER.warning(
            "Failed to publish MQTT alert event_id=%s topic=%s error=%s",
            payload["event_id"],
            MQTT_ALERT_TOPIC,
            exc,
        )
        return {
            "status": "failed",
            "event_id": payload["event_id"],
            "error": str(exc),
        }
