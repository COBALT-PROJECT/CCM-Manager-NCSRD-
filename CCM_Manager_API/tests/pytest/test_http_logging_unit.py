import pytest

import app


pytestmark = pytest.mark.unit


def test_http_logging_redacts_sensitive_payload_fields():
    payload = {
        "scheme_id": "example",
        "Authorization": "Bearer token",
        "nested": {
            "client_secret": "secret",
            "safe": "value",
        },
        "items": [
            {"access_token": "token"},
            {"name": "visible"},
        ],
    }

    redacted = app._redact_payload(payload)

    assert redacted["scheme_id"] == "example"
    assert redacted["Authorization"] == "[REDACTED]"
    assert redacted["nested"]["client_secret"] == "[REDACTED]"
    assert redacted["nested"]["safe"] == "value"
    assert redacted["items"][0]["access_token"] == "[REDACTED]"
    assert redacted["items"][1]["name"] == "visible"


def test_http_logging_redacts_sensitive_headers():
    headers = {
        "Authorization": "Bearer token",
        "Content-Type": "application/json",
        "X-Correlation-ID": "test-correlation",
        "User-Agent": "pytest",
        "X-Internal-Noise": "hidden",
    }

    selected = app._selected_headers(headers)

    assert selected == {
        "Authorization": "[REDACTED]",
        "Content-Type": "application/json",
        "X-Correlation-ID": "test-correlation",
        "User-Agent": "pytest",
    }
