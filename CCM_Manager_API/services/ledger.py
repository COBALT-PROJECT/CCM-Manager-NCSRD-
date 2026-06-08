import json
import logging

import requests

from auth import auth_context, authed_request
from config import LEDGER_BASE_URL


def send_to_ledger(endpoint, data):
    url = f"{LEDGER_BASE_URL}{endpoint}"
    payload = {"content": json.dumps(data)}

    try:
        response = authed_request("POST", url, json=payload, timeout=10, service="ledger")
        response.raise_for_status()
        return response.json().get("hash")
    except requests.RequestException as exc:
        logging.error("Ledger Error (%s): %s", url, exc)
        raise


def ledger_auth_context():
    return auth_context("ledger")
