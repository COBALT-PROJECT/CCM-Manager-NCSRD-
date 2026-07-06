import pytest

import inbound_auth


pytestmark = pytest.mark.unit


class DummyRequest:
    method = "GET"

    def __init__(self, path="/certification_schemes", authorization=None):
        self.path = path
        self.headers = {}
        if authorization:
            self.headers["Authorization"] = authorization


class DummyResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


def test_inbound_auth_disabled_allows_request(monkeypatch):
    monkeypatch.setattr(inbound_auth, "CCM_INBOUND_AUTH_ENABLED", False)

    payload, status_code = inbound_auth.require_inbound_auth(DummyRequest())

    assert payload is None
    assert status_code is None


def test_public_path_allows_request_when_auth_enabled(monkeypatch):
    monkeypatch.setattr(inbound_auth, "CCM_INBOUND_AUTH_ENABLED", True)

    payload, status_code = inbound_auth.require_inbound_auth(DummyRequest(path="/auth/status"))

    assert payload is None
    assert status_code is None


def test_missing_bearer_token_is_rejected(monkeypatch):
    monkeypatch.setattr(inbound_auth, "CCM_INBOUND_AUTH_ENABLED", True)

    payload, status_code = inbound_auth.require_inbound_auth(DummyRequest())

    assert status_code == 401
    assert payload["error"] == "Authentication required"


def test_userinfo_token_accepts_active_component(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return DummyResponse(
            payload={
                "client_id": "partner-component",
                "component_id": "partner-component",
                "type": "component",
                "status": "active",
                "scope": "openid profile",
                "sub": "component:abc",
            }
        )

    monkeypatch.setattr(inbound_auth, "CCM_INBOUND_USERINFO_URL", "http://iam.test/oauth/userinfo?schema=openid")
    monkeypatch.setattr(inbound_auth, "CCM_INBOUND_REQUIRED_SCOPE", "profile")
    monkeypatch.setattr(inbound_auth, "CCM_INBOUND_REQUIRE_TYPE", "component")
    monkeypatch.setattr(inbound_auth, "CCM_INBOUND_ALLOWED_CLIENT_IDS", "partner-component")
    monkeypatch.setattr(inbound_auth.requests, "get", fake_get)

    result = inbound_auth.validate_bearer_token("opaque-token")

    assert result["authenticated"] is True
    assert result["token_type"] == "userinfo"
    assert result["identity"]["client_id"] == "partner-component"
    assert calls[0][1]["headers"]["Authorization"] == "Bearer opaque-token"


def test_userinfo_token_rejects_missing_scope(monkeypatch):
    def fake_get(url, **kwargs):
        return DummyResponse(
            payload={
                "client_id": "partner-component",
                "type": "component",
                "status": "active",
                "scope": "openid",
                "sub": "component:abc",
            }
        )

    monkeypatch.setattr(inbound_auth, "CCM_INBOUND_USERINFO_URL", "http://iam.test/oauth/userinfo?schema=openid")
    monkeypatch.setattr(inbound_auth, "CCM_INBOUND_REQUIRED_SCOPE", "profile")
    monkeypatch.setattr(inbound_auth, "CCM_INBOUND_REQUIRE_TYPE", "")
    monkeypatch.setattr(inbound_auth, "CCM_INBOUND_ALLOWED_CLIENT_IDS", "")
    monkeypatch.setattr(inbound_auth.requests, "get", fake_get)

    with pytest.raises(inbound_auth.InboundAuthError, match="Missing required scope"):
        inbound_auth.validate_bearer_token("opaque-token")
