import pytest

import auth


pytestmark = pytest.mark.unit


class DummyResponse:
    status_code = 200


class DummyAuthClient:
    def __init__(self, token_error=None):
        self.calls = []
        self.token_error = token_error

    def authenticated_request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return DummyResponse()

    def get_token(self, scope=None):
        if self.token_error:
            raise self.token_error
        return "token"


def test_authed_request_uses_component_auth_client(monkeypatch):
    client = DummyAuthClient()
    monkeypatch.setattr(auth, "auth_client", client)

    response = auth.authed_request("POST", "http://example.test/resource", json={"ok": True})

    assert isinstance(response, DummyResponse)
    assert client.calls == [
        ("POST", "http://example.test/resource", {"json": {"ok": True}})
    ]


def test_authed_request_falls_back_to_requests(monkeypatch):
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return DummyResponse()

    monkeypatch.setattr(auth, "auth_client", None)
    monkeypatch.setattr(auth.requests, "request", fake_request)

    response = auth.authed_request("GET", "http://example.test/status", timeout=1)

    assert isinstance(response, DummyResponse)
    assert calls == [("GET", "http://example.test/status", {"timeout": 1})]


def test_authed_request_uses_service_bearer_token(monkeypatch):
    calls = []
    client = DummyAuthClient()

    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return DummyResponse()

    monkeypatch.setattr(auth, "auth_client", client)
    monkeypatch.setattr(auth.requests, "request", fake_request)
    monkeypatch.setenv("DRM_BEARER_TOKEN", "drm-token")

    response = auth.authed_request("POST", "http://drm.example.test/metrics", service="drm")

    assert isinstance(response, DummyResponse)
    assert client.calls == []
    assert calls == [
        (
            "POST",
            "http://drm.example.test/metrics",
            {"headers": {"Authorization": "Bearer drm-token"}},
        )
    ]


def test_authed_request_uses_service_specific_role(monkeypatch):
    client = DummyAuthClient()
    monkeypatch.setattr(auth, "auth_client", client)
    monkeypatch.setenv("DRM_AUTH_ROLE", "SchemeAdmin")
    monkeypatch.delenv("DRM_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("CCM_DRM_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("DRM_TOKEN", raising=False)

    response = auth.authed_request("POST", "http://drm.example.test/schemes", service="drm")

    assert isinstance(response, DummyResponse)
    assert client.calls == [
        ("POST", "http://drm.example.test/schemes", {"scope": "SchemeAdmin"})
    ]


def test_auth_context_reports_configured_role(monkeypatch):
    monkeypatch.setattr(auth, "auth_client", DummyAuthClient())
    monkeypatch.setenv("CCM_SDT_AUTH_ROLE", "component sdt profile")
    monkeypatch.setenv("SDT_AUTH_DISABLED", "false")

    assert auth.auth_context("sdt") == {
        "service": "sdt",
        "auth_enabled": True,
        "auth_role": "component sdt profile",
        "configured_role": "component sdt profile",
    }


def test_auth_context_reports_unauthenticated_when_auth_disabled(monkeypatch):
    monkeypatch.setattr(auth, "auth_client", None)
    monkeypatch.setenv("LEDGER_AUTH_ROLE", "manufacturer")

    assert auth.auth_context("ledger") == {
        "service": "ledger",
        "auth_enabled": False,
        "auth_role": "unauthenticated",
        "configured_role": "manufacturer",
    }


def test_auth_status_disabled(monkeypatch):
    monkeypatch.setattr(auth, "auth_client", None)

    assert auth.auth_status_payload() == {
        "auth_enabled": False,
        "status": "disabled",
    }


def test_auth_status_ok(monkeypatch):
    monkeypatch.setattr(auth, "auth_client", DummyAuthClient())

    assert auth.auth_status_payload() == {
        "auth_enabled": True,
        "status": "ok",
    }


def test_auth_status_token_error(monkeypatch):
    monkeypatch.setattr(auth, "auth_client", DummyAuthClient(token_error=RuntimeError("boom")))

    assert auth.auth_status_payload() == {
        "auth_enabled": True,
        "status": "token_error",
    }


def test_access_token_for_service_prefers_static_bearer_token(monkeypatch):
    monkeypatch.setattr(auth, "auth_client", None)
    monkeypatch.setenv("SDT_BEARER_TOKEN", "static-sdt-token")
    monkeypatch.setenv("SDT_AUTH_DISABLED", "false")

    assert auth.access_token_for_service("sdt") == "static-sdt-token"


def test_access_token_for_service_uses_component_auth_client(monkeypatch):
    client = DummyAuthClient()
    monkeypatch.setattr(auth, "auth_client", client)
    monkeypatch.delenv("SDT_BEARER_TOKEN", raising=False)
    monkeypatch.setenv("CCM_SDT_AUTH_ROLE", "digital_twins profile")
    monkeypatch.setenv("SDT_AUTH_DISABLED", "false")

    assert auth.access_token_for_service("sdt") == "token"


def test_build_auth_client_requires_configuration(monkeypatch):
    monkeypatch.setattr(auth, "ComponentAuthClient", object)
    monkeypatch.delenv("AM_BASE_URL", raising=False)
    monkeypatch.delenv("AM_CLIENT_ID", raising=False)
    monkeypatch.delenv("AM_CLIENT_SECRET", raising=False)

    assert auth._build_auth_client() is None


def test_build_auth_client_from_environment(monkeypatch):
    created = {}

    class FakeComponentAuthClient:
        def __init__(self, **kwargs):
            created.update(kwargs)

    monkeypatch.setattr(auth, "ComponentAuthClient", FakeComponentAuthClient)
    monkeypatch.setenv("AM_BASE_URL", "https://am.example.test")
    monkeypatch.setenv("AM_CLIENT_ID", "ccm-manager")
    monkeypatch.setenv("AM_CLIENT_SECRET", "secret")
    monkeypatch.setenv("AM_SCOPE", "digital_twins profile")
    monkeypatch.setenv("AM_VERIFY_TLS", "false")

    client = auth._build_auth_client()

    assert isinstance(client, FakeComponentAuthClient)
    assert created == {
        "base_url": "https://am.example.test",
        "client_id": "ccm-manager",
        "client_secret": "secret",
        "default_scope": "digital_twins profile",
        "verify_tls": False,
    }
