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


def _service_env_key(service):
    if not service:
        return "DEFAULT"
    return re.sub(r"[^A-Z0-9]+", "_", service.upper()).strip("_")


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
        or os.getenv("AM_SCOPE", "digital_twins profile")
    )


def auth_context(service=None, scope=None):
    role = auth_role_for_service(service, scope)
    return {
        "service": service or "default",
        "auth_enabled": auth_client is not None,
        "auth_role": role if auth_client is not None else "unauthenticated",
        "configured_role": role,
    }


def authed_request(method, url, **kwargs):
    """Route outbound HTTP through ComponentAuthClient when available."""
    service = kwargs.pop("service", None)
    scope = kwargs.pop("scope", None)
    if scope is None and service is not None:
        scope = auth_role_for_service(service)

    bearer_token = _bearer_token_for_service(service)
    if bearer_token:
        return requests.request(method, url, **_with_bearer_header(kwargs, bearer_token))

    if auth_client is not None:
        if scope is None:
            return auth_client.authenticated_request(method, url, **kwargs)
        return auth_client.authenticated_request(method, url, scope=scope, **kwargs)
    return requests.request(method, url, **kwargs)


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
