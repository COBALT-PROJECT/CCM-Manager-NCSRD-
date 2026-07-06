import json
import logging
import re
import time

import jwt
import requests
from flask import g

from config import (
    CCM_INBOUND_ALLOWED_ALGS,
    CCM_INBOUND_ALLOWED_CLIENT_IDS,
    CCM_INBOUND_AUDIENCE,
    CCM_INBOUND_AUTH_ENABLED,
    CCM_INBOUND_ISSUER,
    CCM_INBOUND_JWKS_TTL,
    CCM_INBOUND_JWKS_URL,
    CCM_INBOUND_LEEWAY,
    CCM_INBOUND_OPENID_CONFIG_URL,
    CCM_INBOUND_PUBLIC_PATHS,
    CCM_INBOUND_REQUIRED_SCOPE,
    CCM_INBOUND_REQUIRE_TYPE,
    CCM_INBOUND_TIMEOUT,
    CCM_INBOUND_USERINFO_URL,
    CCM_INBOUND_VERIFY_TLS,
)


DEFAULT_PUBLIC_PATHS = {
    "/",
    "/auth/status",
    "/apidocs",
    "/apidocs/",
    "/apispec_1.json",
}
DEFAULT_PUBLIC_PREFIXES = (
    "/flasgger_static/",
    "/static/",
)

_jwks_cache = {
    "keys": [],
    "fetched_at": 0.0,
}
_discovery_cache = {
    "document": None,
    "fetched_at": 0.0,
}


class InboundAuthError(Exception):
    """Raised when an inbound bearer token cannot be accepted."""


def _split_config(value):
    if not value:
        return []
    return [item for item in re.split(r"[\s,]+", value.strip()) if item]


def _public_paths():
    return DEFAULT_PUBLIC_PATHS | set(_split_config(CCM_INBOUND_PUBLIC_PATHS))


def _is_public_path(path):
    if path in _public_paths():
        return True
    return any(path.startswith(prefix) for prefix in DEFAULT_PUBLIC_PREFIXES)


def _is_jwt_like(token):
    return isinstance(token, str) and token.count(".") == 2


def _extract_bearer_token(flask_request):
    auth_header = flask_request.headers.get("Authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return None
    return auth_header.split(None, 1)[1].strip()


def _get_openid_config():
    now = time.time()
    if _discovery_cache["document"] and now - _discovery_cache["fetched_at"] < CCM_INBOUND_JWKS_TTL:
        return _discovery_cache["document"]

    if not CCM_INBOUND_OPENID_CONFIG_URL:
        return {}

    response = requests.get(
        CCM_INBOUND_OPENID_CONFIG_URL,
        timeout=CCM_INBOUND_TIMEOUT,
        verify=CCM_INBOUND_VERIFY_TLS,
        headers={"Accept": "application/json"},
    )
    if response.status_code != 200:
        raise InboundAuthError(
            f"OpenID configuration returned {response.status_code}"
        )

    try:
        document = response.json()
    except ValueError as exc:
        raise InboundAuthError("OpenID configuration is not JSON") from exc

    _discovery_cache["document"] = document
    _discovery_cache["fetched_at"] = now
    return document


def _jwks_url():
    if CCM_INBOUND_JWKS_URL:
        return CCM_INBOUND_JWKS_URL
    return _get_openid_config().get("jwks_uri")


def _get_jwks(force=False):
    now = time.time()
    if not force and _jwks_cache["keys"] and now - _jwks_cache["fetched_at"] < CCM_INBOUND_JWKS_TTL:
        return _jwks_cache["keys"]

    jwks_url = _jwks_url()
    if not jwks_url:
        raise InboundAuthError("JWKS URL is not configured")

    response = requests.get(
        jwks_url,
        timeout=CCM_INBOUND_TIMEOUT,
        verify=CCM_INBOUND_VERIFY_TLS,
        headers={"Accept": "application/json"},
    )
    if response.status_code != 200:
        raise InboundAuthError(f"JWKS endpoint returned {response.status_code}")

    try:
        keys = response.json()["keys"]
    except (ValueError, KeyError, TypeError) as exc:
        raise InboundAuthError("JWKS document is malformed") from exc

    if not isinstance(keys, list):
        raise InboundAuthError("JWKS keys field is not a list")

    _jwks_cache["keys"] = keys
    _jwks_cache["fetched_at"] = now
    return keys


def _select_jwk(header):
    kid = header.get("kid")
    keys = _get_jwks()

    if kid:
        for key in keys:
            if key.get("kid") == kid:
                return key
        for key in _get_jwks(force=True):
            if key.get("kid") == kid:
                return key
        raise InboundAuthError(f"No JWKS key matches kid={kid!r}")

    if len(keys) == 1:
        return keys[0]
    raise InboundAuthError("Token has no kid and JWKS has multiple keys")


def _check_scope(identity):
    required = set(_split_config(CCM_INBOUND_REQUIRED_SCOPE))
    if not required:
        return

    token_scope = identity.get("scope") or ""
    available = set(str(token_scope).split())
    missing = required - available
    if missing:
        raise InboundAuthError(f"Missing required scope(s): {sorted(missing)}")


def _check_type(identity):
    required_type = CCM_INBOUND_REQUIRE_TYPE.strip()
    if required_type and identity.get("type") != required_type:
        raise InboundAuthError(
            f"Token type {identity.get('type')!r} does not match {required_type!r}"
        )


def _check_allowed_client(identity):
    allowed = set(_split_config(CCM_INBOUND_ALLOWED_CLIENT_IDS))
    if not allowed:
        return

    candidate_ids = set()
    for value in (
        identity.get("client_id"),
        identity.get("component_id"),
        identity.get("azp"),
        identity.get("aud"),
    ):
        if isinstance(value, list):
            candidate_ids.update(str(item) for item in value if item)
        elif value:
            candidate_ids.add(str(value))

    if not candidate_ids & allowed:
        raise InboundAuthError("Bearer token client is not allowed")


def _check_active_status(identity):
    status = identity.get("status")
    if status and str(status).lower() != "active":
        raise InboundAuthError(f"Bearer token subject is {status!r}")


def _check_identity(identity):
    _check_scope(identity)
    _check_type(identity)
    _check_allowed_client(identity)
    _check_active_status(identity)


def _verify_jwt_token(token):
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise InboundAuthError("Bearer token has an invalid JWT header") from exc

    alg = header.get("alg")
    allowed_algs = set(_split_config(CCM_INBOUND_ALLOWED_ALGS))
    if not alg or alg not in allowed_algs:
        raise InboundAuthError(f"JWT alg {alg!r} is not allowed")

    jwk = _select_jwk(header)
    algorithms = jwt.algorithms.get_default_algorithms()
    if alg not in algorithms:
        raise InboundAuthError(f"JWT alg {alg!r} is not supported")
    public_key = algorithms[alg].from_jwk(json.dumps(jwk))
    issuer = CCM_INBOUND_ISSUER or _get_openid_config().get("issuer")
    audience = CCM_INBOUND_AUDIENCE or None

    try:
        claims = jwt.decode(
            token,
            public_key,
            algorithms=[alg],
            issuer=issuer,
            audience=audience,
            leeway=CCM_INBOUND_LEEWAY,
            options={
                "verify_aud": audience is not None,
                "require": ["exp", "iat", "iss", "sub"],
            },
        )
    except jwt.InvalidTokenError as exc:
        raise InboundAuthError("Bearer token signature or claims are invalid") from exc

    _check_identity(claims)
    return {
        "authenticated": True,
        "token_type": "jwt",
        "identity": claims,
    }


def _verify_userinfo_token(token):
    if not CCM_INBOUND_USERINFO_URL:
        raise InboundAuthError("Userinfo URL is not configured")

    response = requests.get(
        CCM_INBOUND_USERINFO_URL,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        timeout=CCM_INBOUND_TIMEOUT,
        verify=CCM_INBOUND_VERIFY_TLS,
    )
    if response.status_code != 200:
        raise InboundAuthError(f"Userinfo endpoint returned {response.status_code}")

    try:
        identity = response.json()
    except ValueError as exc:
        raise InboundAuthError("Userinfo response is not JSON") from exc

    _check_identity(identity)
    return {
        "authenticated": True,
        "token_type": "userinfo",
        "identity": identity,
    }


def validate_bearer_token(token):
    if _is_jwt_like(token):
        try:
            return _verify_jwt_token(token)
        except InboundAuthError as jwt_error:
            logging.debug("JWT inbound auth failed, trying userinfo: %s", jwt_error)

    return _verify_userinfo_token(token)


def require_inbound_auth(flask_request):
    if flask_request.method == "OPTIONS":
        return None, None
    if not CCM_INBOUND_AUTH_ENABLED:
        return None, None
    if _is_public_path(flask_request.path):
        return None, None

    token = _extract_bearer_token(flask_request)
    if not token:
        return {
            "error": "Authentication required",
            "message": "Send Authorization: Bearer <token>.",
        }, 401

    try:
        auth_result = validate_bearer_token(token)
        g.inbound_auth = auth_result
        return None, None
    except InboundAuthError as exc:
        logging.warning("Inbound authentication failed for %s: %s", flask_request.path, exc)
        return {"error": "Invalid bearer token"}, 401


def inbound_auth_status():
    return {
        "auth_enabled": CCM_INBOUND_AUTH_ENABLED,
        "issuer": CCM_INBOUND_ISSUER,
        "openid_config_url": CCM_INBOUND_OPENID_CONFIG_URL,
        "jwks_configured": bool(CCM_INBOUND_JWKS_URL),
        "userinfo_configured": bool(CCM_INBOUND_USERINFO_URL),
        "audience": CCM_INBOUND_AUDIENCE or None,
        "required_scope": _split_config(CCM_INBOUND_REQUIRED_SCOPE),
        "required_type": CCM_INBOUND_REQUIRE_TYPE or None,
        "allowed_client_ids": _split_config(CCM_INBOUND_ALLOWED_CLIENT_IDS),
        "public_paths": sorted(_public_paths()),
    }
