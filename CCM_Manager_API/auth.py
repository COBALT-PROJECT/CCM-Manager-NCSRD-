import logging
import os
import re

import requests

try:
    from IdentityManagement import ComponentAuthClient, AuthError
except ImportError:
    ComponentAuthClient = None
    AuthError = Exception
    logging.warning("IdentityManagement not available (missing PyJWT?); auth disabled")


def _build_auth_client():
    base_url = os.getenv("AM_BASE_URL", "")
    client_id = os.getenv("AM_CLIENT_ID", "")
    client_secret = os.getenv("AM_CLIENT_SECRET", "")
    scope = os.getenv("AM_SCOPE", "digital_twins profile")
    verify_tls = os.getenv("AM_VERIFY_TLS", "true").lower() in ("1", "true", "yes")

    if ComponentAuthClient is None or not (base_url and client_id and client_secret):
        logging.warning("AM_BASE_URL / AM_CLIENT_ID / AM_CLIENT_SECRET not set; running unauthenticated")
        return None

    try:
        client = ComponentAuthClient(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            default_scope=scope,
            verify_tls=verify_tls,
        )
        logging.info("ComponentAuthClient initialized for %s @ %s", client_id, base_url)
        return client
    except Exception as exc:
        logging.warning("ComponentAuthClient init failed (%s); running unauthenticated", exc)
        return None


auth_client = _build_auth_client()
_service_auth_clients = {}
_service_auth_client_settings = {}


AUTH_DISABLED_BY_DEFAULT = {"SDT", "SDTM", "SCHEME_IMPORT", "TOE_CONNECTOR_HEALTH"}
DEFAULT_AUTH_ROLES = {
    "MANUFACTURER": "openid profile",
    "TOE_CONNECTOR": "openid profile",
}


def _service_env_key(service):
    if not service:
        return "DEFAULT"
    return re.sub(r"[^A-Z0-9]+", "_", service.upper()).strip("_")


def _env_flag_enabled(value):
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _env_flag_disabled(value):
    return str(value).strip().lower() in ("0", "false", "no", "off")


def _auth_disabled_for_service(service):
    service_key = _service_env_key(service)
    configured = (
        os.getenv(f"{service_key}_AUTH_DISABLED")
        or os.getenv(f"CCM_{service_key}_AUTH_DISABLED")
        or os.getenv(f"{service_key}_SKIP_AUTH")
        or os.getenv(f"CCM_{service_key}_SKIP_AUTH")
    )
    if configured is not None:
        if _env_flag_disabled(configured):
            return False
        return _env_flag_enabled(configured)
    return service_key in AUTH_DISABLED_BY_DEFAULT


def _bearer_token_for_service(service):
    service_key = _service_env_key(service)
    for env_key in (
        f"{service_key}_BEARER_TOKEN",
        f"CCM_{service_key}_BEARER_TOKEN",
        f"{service_key}_TOKEN",
    ):
        token = os.getenv(env_key, "").strip()
        if token:
            return token
    return None


def _with_bearer_header(kwargs, token):
    headers = dict(kwargs.pop("headers", {}) or {})
    headers.setdefault("Authorization", f"Bearer {token}")
    kwargs["headers"] = headers
    return kwargs


def auth_role_for_service(service=None, scope=None):
    if scope:
        return scope

    service_key = _service_env_key(service)
    return (
        os.getenv(f"{service_key}_AUTH_ROLE")
        or os.getenv(f"CCM_{service_key}_AUTH_ROLE")
        or os.getenv("CCM_AUTH_ROLE")
        or DEFAULT_AUTH_ROLES.get(service_key)
        or os.getenv("AM_SCOPE", "digital_twins profile")
    )


def _auth_client_for_service(service):
    """Return a dedicated OAuth client when service credentials are configured."""
    service_key = _service_env_key(service)
    client_id = (
        os.getenv(f"{service_key}_CLIENT_ID")
        or os.getenv(f"CCM_{service_key}_CLIENT_ID")
        or ""
    ).strip()
    client_secret = (
        os.getenv(f"{service_key}_CLIENT_SECRET")
        or os.getenv(f"CCM_{service_key}_CLIENT_SECRET")
        or ""
    ).strip()

    if not client_id or not client_secret or ComponentAuthClient is None:
        return auth_client

    base_url = (
        os.getenv(f"{service_key}_AM_BASE_URL")
        or os.getenv(f"CCM_{service_key}_AM_BASE_URL")
        or os.getenv("AM_BASE_URL", "")
    ).rstrip("/")
    scope = auth_role_for_service(service)
    verify_tls_value = (
        os.getenv(f"{service_key}_AM_VERIFY_TLS")
        or os.getenv(f"CCM_{service_key}_AM_VERIFY_TLS")
        or os.getenv("AM_VERIFY_TLS", "true")
    )
    verify_tls = verify_tls_value.lower() in ("1", "true", "yes")
    settings = (base_url, client_id, client_secret, scope, verify_tls)

    if not base_url:
        logging.warning(
            "%s_CLIENT_ID / %s_CLIENT_SECRET are set but AM_BASE_URL is missing",
            service_key,
            service_key,
        )
        return auth_client

    if _service_auth_client_settings.get(service_key) == settings:
        return _service_auth_clients[service_key]

    try:
        client = ComponentAuthClient(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            default_scope=scope,
            verify_tls=verify_tls,
        )
        _service_auth_clients[service_key] = client
        _service_auth_client_settings[service_key] = settings
        logging.info(
            "Dedicated ComponentAuthClient initialized for service=%s client_id=%s",
            service or "default",
            client_id,
        )
        return client
    except Exception as exc:
        logging.warning(
            "Dedicated ComponentAuthClient init failed for service=%s: %s",
            service or "default",
            exc,
        )
        return auth_client


def auth_context(service=None, scope=None):
    role = auth_role_for_service(service, scope)
    service_auth_disabled = _auth_disabled_for_service(service)
    service_client = _auth_client_for_service(service)
    return {
        "service": service or "default",
        "auth_enabled": service_client is not None and not service_auth_disabled,
        "auth_role": role if service_client is not None and not service_auth_disabled else "unauthenticated",
        "configured_role": role,
    }


def authed_request(method, url, **kwargs):
    """Route outbound HTTP through ComponentAuthClient when available."""
    service = kwargs.pop("service", None)
    scope = kwargs.pop("scope", None)

    if _auth_disabled_for_service(service):
        return requests.request(method, url, **kwargs)

    if scope is None and service is not None:
        scope = auth_role_for_service(service)

    service_client = _auth_client_for_service(service)

    bearer_token = _bearer_token_for_service(service)
    if bearer_token:
        response = requests.request(
            method,
            url,
            **_with_bearer_header(kwargs, bearer_token),
        )
        if response.status_code != 401 or service_client is None:
            return response

        headers = dict(kwargs.get("headers", {}) or {})
        headers.pop("Authorization", None)
        if headers:
            kwargs["headers"] = headers
        else:
            kwargs.pop("headers", None)
        return service_client.authenticated_request(
            method,
            url,
            scope=scope,
            **kwargs,
        )

    if service_client is not None:
        if scope is None:
            return service_client.authenticated_request(method, url, **kwargs)
        return service_client.authenticated_request(method, url, scope=scope, **kwargs)
    return requests.request(method, url, **kwargs)


def access_token_for_service(service=None, scope=None):
    if _auth_disabled_for_service(service):
        return None

    if scope is None and service is not None:
        scope = auth_role_for_service(service)

    bearer_token = _bearer_token_for_service(service)
    if bearer_token:
        return bearer_token

    service_client = _auth_client_for_service(service)
    if service_client is None:
        return None

    return service_client.get_token(scope=scope)


def auth_status_payload():
    result = {"auth_enabled": auth_client is not None}
    if auth_client is None:
        result["status"] = "disabled"
        return result

    try:
        auth_client.get_token()
        result["status"] = "ok"
    except Exception:
        result["status"] = "token_error"
    return result
