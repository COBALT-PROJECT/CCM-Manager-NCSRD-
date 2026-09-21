import json
import logging

import requests

from auth import auth_context, authed_request
from config import LEDGER_BASE_URL
from services.mqtt_alert_service import publish_failure


def send_to_ledger(
    endpoint,
    data,
    operation=None,
    details=None,
    content_as_object=False,
):
    url = f"{LEDGER_BASE_URL}{endpoint}"
    payload = {
        "content": data if content_as_object else json.dumps(data)
    }

    try:
        response = authed_request("POST", url, json=payload, timeout=10, service="ledger")
        response.raise_for_status()
        return response.json().get("hash")
    except requests.RequestException as exc:
        logging.error("Ledger Error (%s): %s", url, exc)
        publish_failure(
            operation=operation or "Send data to blockchain ledger",
            message="Blockchain ledger request failed",
            details={
                "service": "ledger",
                "endpoint": endpoint,
                "exception_type": type(exc).__name__,
                "error": str(exc),
                **(details or {}),
            },
        )
        raise


def ledger_auth_context():
    return auth_context("ledger")
