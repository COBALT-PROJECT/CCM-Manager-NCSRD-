"""
    pip install "PyJWT[crypto]" requests
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional

import jwt  # PyJWT
import requests
from requests.auth import HTTPBasicAuth


class AuthError(Exception):
    """Base class for all authentication errors raised by this module."""


class TokenRequestError(AuthError):
    """`/oauth/token` returned a non-2xx response or a malformed body."""


class TokenVerificationError(AuthError):
    """Token failed signature, claim, scope, or allowlist verification."""


class JWKSError(AuthError):
    """Discovery or JWKS retrieval failed, or the document was malformed."""

@dataclass
class CachedToken:
    access_token: str
    token_type: str
    scope: str
    issued_at: float
    expires_at: float

    def is_valid(self, safety_margin: float = 30.0) -> bool:

        return time.time() + safety_margin < self.expires_at

class ComponentAuthClient:
    """
    Headless OAuth2 client for the AM `component` grant.

    Example
    -------
    >>> with ComponentAuthClient(
    ...     base_url="http://192.168.1.100:3100",
    ...     client_id="ids-component",
    ...     client_secret="...",
    ...     default_scope="digital_twins profile",
    ... ) as ac:
    ...     token  = ac.get_token()                       # Step 3
    ...     info   = ac.get_userinfo()                    # Step 4
    ...     claims = ac.verify_token(                     # Step 5
    ...         token,
    ...         required_scopes=["digital_twins"],
    ...         allowed_client_ids=["ids-component"],
    ...     )
    """

    DISCOVERY_PATH = "/.well-known/openid-configuration"
    TOKEN_PATH     = "/oauth/token"
    USERINFO_PATH  = "/oauth/userinfo"
    JWKS_FALLBACK  = "/oauth/jwks"

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        *,
        default_scope: Optional[str] = None,
        verify_tls: bool = True,
        timeout: float = 5.0,
        jwks_ttl: float = 3600.0,
        leeway: float = 30.0,
        token_safety_margin: float = 30.0,
    ):
        if "://" not in base_url:
            raise ValueError(
                "base_url must include a scheme (http:// or https://); "
                f"got {base_url!r}"
            )

        self.base_url            = base_url.rstrip("/")
        self.client_id           = client_id
        self.client_secret       = client_secret
        self.default_scope       = default_scope
        self.verify_tls          = verify_tls
        self.timeout             = timeout
        self.jwks_ttl            = jwks_ttl
        self.leeway              = leeway
        self.token_safety_margin = token_safety_margin

        self._session = requests.Session()
        self._lock    = threading.RLock()

        self._cached_token: Optional[CachedToken] = None
        self._discovery:    Optional[dict[str, Any]] = None
        self._jwks_keys:    list[dict[str, Any]] = []
        self._jwks_fetched: float = 0.0

    def get_token(
        self,
        scope: Optional[str] = None,
        *,
        force_refresh: bool = False,
    ) -> str:

        requested_scope = scope or self.default_scope

        with self._lock:
            if (
                not force_refresh
                and self._cached_token is not None
                and self._cached_token.is_valid(self.token_safety_margin)
            ):
                return self._cached_token.access_token

            form: dict[str, str] = {"grant_type": "client_credentials"}

            if requested_scope:
                form["scope"] = requested_scope

            resp = self._session.post(
                self.base_url + self.TOKEN_PATH,
                data=form,
                auth=HTTPBasicAuth(self.client_id, self.client_secret),
                headers={"Accept": "application/json"},
                timeout=self.timeout,
                verify=self.verify_tls,
            )


            if resp.status_code != 200:
                raise TokenRequestError(
                    f"/oauth/token returned {resp.status_code}: {resp.text}"
                )

            try:
                payload      = resp.json()
                access_token = payload["access_token"]
                expires_in   = float(payload.get("expires_in", 0.0))

            except (ValueError, KeyError, TypeError) as exc:

                raise TokenRequestError(
                    f"malformed token response: {resp.text!r}"
                ) from exc

            now = time.time()

            self._cached_token = CachedToken(
                access_token=access_token,
                token_type=payload.get("token_type", "Bearer"),
                scope=payload.get("scope", requested_scope or ""),
                issued_at=now,
                expires_at=now + expires_in,
            )
            return access_token


    def get_userinfo(self, token: Optional[str] = None) -> dict[str, Any]:

        token = token or self.get_token()
        resp = self._session.get(
            self.base_url + self.USERINFO_PATH,
            headers={"Authorization": f"Bearer {token}"},
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        if resp.status_code != 200:
            raise AuthError(
                f"/oauth/userinfo returned {resp.status_code}: {resp.text}"
            )
        return resp.json()

    def authenticated_request(
        self,
        method: str,
        url: str,
        *,
        scope: Optional[str] = None,
        **kwargs,
    ) -> requests.Response:


        headers = dict(kwargs.pop("headers", {}) or {})

        token = self.get_token(scope=scope)
        headers["Authorization"] = f"Bearer {token}"
        resp = self._session.request(
            method, url, headers=headers,
            timeout=kwargs.pop("timeout", self.timeout),
            verify=self.verify_tls,
            **kwargs,
        )
        if resp.status_code == 401:
            token = self.get_token(scope=scope, force_refresh=True)
            headers["Authorization"] = f"Bearer {token}"
            resp = self._session.request(
                method, url, headers=headers,
                timeout=kwargs.pop("timeout", self.timeout),
                verify=self.verify_tls,
                **kwargs,
            )
        return resp


    def _get_discovery(self) -> dict[str, Any]:

        with self._lock:
            if self._discovery is not None:
                return self._discovery

            resp = self._session.get(
                self.base_url + self.DISCOVERY_PATH,
                timeout=self.timeout,
                verify=self.verify_tls,
            )
            if resp.status_code != 200:
                raise JWKSError(
                    f"OIDC discovery failed: {resp.status_code} {resp.text}"
                )
            try:
                self._discovery = resp.json()
            except ValueError as exc:
                raise JWKSError(f"discovery body not JSON: {resp.text!r}") from exc
            return self._discovery

    def _get_jwks(self, *, force: bool = False) -> list[dict[str, Any]]:

        with self._lock:
            now = time.time()
            if (
                not force
                and self._jwks_keys
                and (now - self._jwks_fetched) < self.jwks_ttl
            ):
                return self._jwks_keys

            jwks_uri = None
            try:
                jwks_uri = self._get_discovery().get("jwks_uri")
            except JWKSError:
                pass
            if not jwks_uri:
                jwks_uri = self.base_url + self.JWKS_FALLBACK

            resp = self._session.get(
                jwks_uri, timeout=self.timeout, verify=self.verify_tls,
            )
            if resp.status_code != 200:
                raise JWKSError(
                    f"JWKS fetch failed: {resp.status_code} {resp.text}"
                )

            try:
                doc = resp.json()
                keys = doc["keys"]
            except (ValueError, KeyError, TypeError) as exc:
                raise JWKSError(f"malformed JWKS document: {resp.text!r}") from exc
            if not isinstance(keys, list):
                raise JWKSError(f"JWKS `keys` is not a list: {keys!r}")

            self._jwks_keys    = keys
            self._jwks_fetched = now
            return keys

    def _select_key(self, header: Mapping[str, Any]) -> dict[str, Any]:

        kid = header.get("kid")
        keys = self._get_jwks()

        if kid is not None:
            for k in keys:
                if k.get("kid") == kid:
                    return k
            keys = self._get_jwks(force=True)
            for k in keys:
                if k.get("kid") == kid:
                    return k
            raise TokenVerificationError(
                f"JWKS has no key matching kid={kid!r}"
            )

        if len(keys) == 1:
            return keys[0]
        raise TokenVerificationError(
            "token has no `kid` and JWKS has multiple keys; cannot disambiguate"
        )

    def verify_token(
        self,
        token: str,
        *,
        required_scopes: Optional[Iterable[str]] = None,
        allowed_client_ids: Optional[Iterable[str]] = None,
        allowed_subs: Optional[Iterable[str]] = None,
        audience: Optional[str] = None,
        require_component_type: bool = True,
    ) -> dict[str, Any]:

        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise TokenVerificationError(f"unparseable JWT header: {exc}") from exc

        jwk_data = self._select_key(header)
        alg = header.get("alg") or jwk_data.get("alg") or "RS256"

        algorithms = jwt.algorithms.get_default_algorithms()

        if alg not in algorithms:
            raise TokenVerificationError(f"unsupported alg: {alg!r}")

        public_key = algorithms[alg].from_jwk(json.dumps(jwk_data))

        issuer = self._get_discovery().get("issuer", self.base_url)
        try:
            claims = jwt.decode(
                token,
                public_key,
                algorithms=[alg],
                issuer=issuer,
                audience=audience,
                leeway=self.leeway,
                options={
                    "verify_aud": audience is not None,
                    "require": ["exp", "iat", "iss", "sub"],
                },
            )
        except jwt.InvalidTokenError as exc:
            raise TokenVerificationError(
                f"signature/claim verification failed: {exc}"
            ) from exc

        if require_component_type and claims.get("type") != "component":
            raise TokenVerificationError(
                f"token type is {claims.get('type')!r}, expected 'component'"
            )

        if required_scopes:

            token_scopes = set((claims.get("scope") or "").split())
            missing = set(required_scopes) - token_scopes

            if missing:

                raise TokenVerificationError(
                    f"token missing required scopes: {sorted(missing)}"
                )

        if allowed_client_ids is not None and \
                claims.get("client_id") not in set(allowed_client_ids):

            raise TokenVerificationError(
                f"client_id {claims.get('client_id')!r} not in allowlist"
            )

        if allowed_subs is not None and claims.get("sub") not in set(allowed_subs):

            raise TokenVerificationError(
                f"sub {claims.get('sub')!r} not in allowlist"
            )

        return claims

    def invalidate_token(self) -> None:
        with self._lock:
            self._cached_token = None

    def invalidate_jwks(self) -> None:
        with self._lock:
            self._jwks_keys    = []
            self._jwks_fetched = 0.0

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "ComponentAuthClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


if __name__ == "__main__":
    import os
    import sys

    base = os.environ.get("AM_BASE_URL", "http://iam.cobalt.local:3100")
    cid  = os.environ.get("AM_CLIENT_ID", "ccm-component")
    sec  = os.environ.get("AM_CLIENT_SECRET", "bc124e5b2ef986120f5d92d00493f15d21604abb4dfe78edb26b8738bdb5d092")

    if not (cid and sec):
        sys.exit("set AM_CLIENT_ID and AM_CLIENT_SECRET in the environment")

    with ComponentAuthClient(
        base_url=base,
        client_id=cid,
        client_secret=sec,
        default_scope=os.environ.get("AM_SCOPE", "digital_twins profile"),
    ) as ac:
        tok    = ac.get_token()
        info   = ac.get_userinfo()
        claims = ac.verify_token(
            tok,
            required_scopes=os.environ.get("AM_REQUIRED_SCOPES", "").split() or None,
            allowed_client_ids=[cid],
        )
        print(json.dumps(
                {"userinfo": info, "verified_claims": claims},
            indent=2, sort_keys=True,
        ))