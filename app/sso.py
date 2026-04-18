"""OIDC SSO integration against an Authentik-compatible provider.

Stdlib + ``httpx`` + ``itsdangerous`` + ``PyJWT`` (all already in
requirements). No ``authlib`` dep — one less moving part to pin and a
smaller attack surface for a handful of endpoints that never touch
OAuth flows beyond the plain authorization-code + PKCE path.

Protocol summary (per-login):

1. ``GET /auth/sso/login`` — ``build_authorize_url(request, response)``
   generates a random state + PKCE verifier, signs them into a short
   cookie, returns the Authentik authorize URL. State-cookie is the
   CSRF equivalent; the route is therefore exempt from the local CSRF
   middleware.
2. Authentik flow completes, redirects to ``/auth/sso/callback`` with
   ``code`` + ``state``.
3. ``exchange_code(request, code, state)`` verifies state cookie,
   POSTs to the token endpoint with PKCE verifier, validates the id
   token against the JWKS, returns the claims dict.

Feature-flag: when ``NKS_WDC_SSO_CLIENT_ID`` is empty, ``sso_enabled()``
returns False and the /auth/sso/* routes return 404. Makes local dev
trivially safe without touching env files.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import urllib.parse
from dataclasses import dataclass

import httpx
import jwt
from fastapi import Request, Response
from itsdangerous import BadSignature, SignatureExpired, TimestampSigner

from .auth import _secret_key

log = logging.getLogger(__name__)

STATE_COOKIE = "nks_wdc_sso_state"
STATE_MAX_AGE = 10 * 60  # 10 minutes — long enough to log in at the IdP
SCOPES = "openid email profile groups"  # Authentik wants space-separated


class SSOError(RuntimeError):
    """Any failure in the SSO exchange — state mismatch, token error,
    JWT verification, missing claims. Caller redirects to /login with
    a generic flash; the detail lands in the server log only."""


@dataclass(frozen=True)
class SSOClaims:
    email: str
    preferred_username: str
    groups: list[str]
    sub: str
    name: str
    raw: dict


def _env(key: str, default: str = "") -> str:
    v = os.environ.get(key, default)
    return v.strip() if v else default


def client_id() -> str:
    return _env("NKS_WDC_SSO_CLIENT_ID")


def _client_secret() -> str:
    return _env("NKS_WDC_SSO_CLIENT_SECRET")


def authority() -> str:
    return _env("NKS_WDC_SSO_AUTHORITY", "https://sso.nks-hub.cz").rstrip("/")


def app_slug() -> str:
    return _env("NKS_WDC_SSO_APP_SLUG", "wdc-catalog")


def admin_groups() -> frozenset[str]:
    raw = _env(
        "NKS_WDC_SSO_ADMIN_GROUPS",
        "admin,superadmin,superadmin-webs,authentik admins",
    )
    return frozenset(g.strip().lower() for g in raw.split(",") if g.strip())


def sso_enabled() -> bool:
    """Feature flag. True when both client id + secret are set.

    We intentionally require the secret too so a half-configured env
    (client id but no secret) doesn't render the Login button and then
    500 on /auth/sso/callback with a confused user.
    """
    return bool(client_id() and _client_secret())


# --- URLs --------------------------------------------------------------


def authorize_url() -> str:
    return f"{authority()}/application/o/authorize/"


def token_url() -> str:
    return f"{authority()}/application/o/token/"


def jwks_url() -> str:
    return f"{authority()}/application/o/{app_slug()}/jwks/"


def userinfo_url() -> str:
    return f"{authority()}/application/o/userinfo/"


# --- State + PKCE signing ----------------------------------------------


def _signer() -> TimestampSigner:
    return TimestampSigner(_secret_key(), salt="nks-wdc-sso-state-v1")


def _pack_state(state: str, verifier: str, return_to: str) -> str:
    payload = json.dumps({"s": state, "v": verifier, "r": return_to}).encode()
    return base64.urlsafe_b64encode(_signer().sign(payload)).decode("ascii")


def _unpack_state(cookie: str) -> tuple[str, str, str] | None:
    try:
        padded = cookie + "=" * (-len(cookie) % 4)
        raw = _signer().unsign(
            base64.urlsafe_b64decode(padded.encode("ascii")),
            max_age=STATE_MAX_AGE,
        )
        d = json.loads(raw)
        return str(d["s"]), str(d["v"]), str(d.get("r", "/admin"))
    except (BadSignature, SignatureExpired, ValueError, KeyError, UnicodeDecodeError):
        return None


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def redirect_uri(request: Request) -> str:
    """Build absolute callback URI the caller registered in Authentik.

    Uses the incoming ``Host`` header so localhost dev + production
    share the same handler. Authentik needs EACH of these in its
    redirect-URI allowlist on the provider — handled at provisioning
    time; this function just reflects the request.
    """
    scheme = "https" if request.url.scheme in ("https", "wss") else "http"
    # X-Forwarded-Proto support so terminating proxy doesn't flip to http
    fwd = request.headers.get("x-forwarded-proto")
    if fwd in ("http", "https"):
        scheme = fwd
    host = request.headers.get("host", "localhost")
    return f"{scheme}://{host}/auth/sso/callback"


# --- Public API ---------------------------------------------------------


def build_authorize_url(
    request: Request,
    response: Response,
    return_to: str = "/admin",
) -> str:
    """Generate authorize URL + set signed state cookie on ``response``.

    Caller pattern:
    ::
        url = build_authorize_url(request, response)
        response.headers["Location"] = url
        response.status_code = 302
        return response
    """
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    cookie_val = _pack_state(state, verifier, return_to)
    response.set_cookie(
        key=STATE_COOKIE,
        value=cookie_val,
        max_age=STATE_MAX_AGE,
        httponly=True,
        samesite="lax",  # 'lax' needed — user is returning from IdP (cross-site)
        secure=request.url.scheme == "https",
    )
    params = {
        "client_id": client_id(),
        "response_type": "code",
        "redirect_uri": redirect_uri(request),
        "scope": SCOPES,
        "state": state,
        "code_challenge": _pkce_challenge(verifier),
        "code_challenge_method": "S256",
    }
    return f"{authorize_url()}?{urllib.parse.urlencode(params)}"


def exchange_code(
    request: Request,
    code: str,
    state_param: str,
    state_cookie: str | None,
) -> tuple[SSOClaims, str]:
    """Verify state, exchange code for tokens, return claims + return_to.

    Raises :class:`SSOError` on any failure.
    """
    if not state_cookie:
        raise SSOError("missing state cookie")
    unpacked = _unpack_state(state_cookie)
    if unpacked is None:
        raise SSOError("state cookie invalid or expired")
    stored_state, verifier, return_to = unpacked
    if not secrets.compare_digest(stored_state, state_param):
        raise SSOError("state mismatch")

    # POST to token endpoint with Basic auth + PKCE verifier.
    # Authentik confidential clients require HTTP Basic Auth
    # (`client_secret_basic`), NOT body-param credentials — sending
    # client_id/client_secret in the form body triggers HTTP 400
    # `invalid_client` with the misleading "no client authentication
    # included" message (verified against sso.nks-hub.cz 2026-04-18).
    try:
        with httpx.Client(timeout=15.0, verify=True) as client:
            resp = client.post(
                token_url(),
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri(request),
                    "code_verifier": verifier,
                },
                auth=(client_id(), _client_secret()),
            )
    except httpx.HTTPError as exc:  # network, tls, etc.
        raise SSOError(f"token endpoint unreachable: {exc}") from exc
    if resp.status_code != 200:
        raise SSOError(f"token endpoint {resp.status_code}: {resp.text[:200]}")
    tok = resp.json()
    id_token = tok.get("id_token")
    if not id_token:
        raise SSOError("id_token missing from token response")

    # Verify id_token. Authentik's default for confidential OIDC
    # providers is ``HS256`` (HMAC-SHA256, shared secret = client_secret) —
    # confirmed via GET /application/o/<slug>/.well-known/openid-configuration
    # returning ``id_token_signing_alg_values_supported: ["HS256"]``. The
    # JWKS endpoint is still exposed but carries no usable public key, so
    # RS256 verification fails at the JWKS-lookup step. HMAC secret doubles
    # as signing key + client auth; fine for our single-tenant setup.
    try:
        # First peek at the header to honor whatever alg Authentik uses
        # (future-proof if an admin flips to RS256).
        header = jwt.get_unverified_header(id_token)
        alg = header.get("alg", "HS256")
        if alg.startswith("HS"):
            key = _client_secret()
        else:
            # RS/ES path — fetch the public key from JWKS
            jwks_client = jwt.PyJWKClient(jwks_url(), cache_keys=True)
            key = jwks_client.get_signing_key_from_jwt(id_token).key
        claims = jwt.decode(
            id_token,
            key,
            algorithms=[alg],
            audience=client_id(),
            issuer=f"{authority()}/application/o/{app_slug()}/",
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        log.warning("SSO id_token verification failed: %s", exc)
        raise SSOError(f"id_token verification failed: {exc}") from exc

    email = str(claims.get("email", "")).strip().lower()
    if not email:
        raise SSOError("id_token has no email claim")

    return (
        SSOClaims(
            email=email,
            preferred_username=str(claims.get("preferred_username", email)).strip(),
            groups=[str(g) for g in claims.get("groups", [])],
            sub=str(claims.get("sub", "")),
            name=str(claims.get("name", "")),
            raw=claims,
        ),
        return_to,
    )


def clear_state_cookie(response: Response, secure: bool) -> None:
    """Wipe the state cookie after callback (single-use)."""
    response.delete_cookie(
        key=STATE_COOKIE,
        httponly=True,
        samesite="lax",
        secure=secure,
    )


def is_admin_group(groups: list[str]) -> bool:
    """Whether ANY of the user's groups grants admin role."""
    normalized = {g.lower().strip() for g in groups if g}
    return bool(normalized & admin_groups())
