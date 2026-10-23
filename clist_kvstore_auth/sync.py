# Flask / requests variant of local kvstore JWT verification ("Pattern B").
#
# Design (see README.md for the full rationale):
#   - Signature verification is OPEN — any issuer. A JWT's `iss` claim names
#     the kvstore instance that signed it; we fetch *that* instance's own
#     `/.well-known/jwks.json` and verify against it. No allowlist gates
#     whether a token is accepted at all — that would silently turn "bring
#     your own kvstore" into a walled garden.
#   - A verified `sub` (bare username) is never a complete identity once any
#     instance can mint one. `qualified_id` — `did:web:<host>:users:<username>`
#     — is the only safe key for ownership/authorship checks. `username` is
#     display-only.
#   - Opaque (non-JWT) tokens are a backward-compatible fallback: kvstore
#     holds the hash and can't be verified locally, so we fall back to the
#     callback (`GET {default_kvstore_url}/auth/verify`) and treat the
#     result as issued by the app's own default kvstore — true by
#     construction, since no other instance could have minted a
#     pre-migration session.
#   - ADMIN_USERNAMES-style admin checks are the one place an issuer
#     allowlist belongs: `is_admin()` reads it from the standardized
#     `ALLOWED_KVSTORE_URLS` env var (comma-separated), falling back to the
#     app's own `KVSTORE_URL` if unset. This is the one env var name for
#     "which issuers are trusted" across every app — also the intended
#     convention for future global params of this kind, not just this one.
#
# Contract:
#   Identity(username, iss, qualified_id)        — returned on success
#   verify_token(authorization, default_kvstore_url, timeout=5.0)
#       -> (Identity, None) | (None, (body: dict, status: int))
#   qualified_id(iss, username) -> str           — "did:web:<host>:users:<username>"
#   owns(stored_value, identity, default_kvstore_url) -> bool
#       — True for an exact qualified_id match, OR a legacy bare-username
#         match where the token's issuer is the app's own default kvstore
#         (i.e. a pre-migration row, implicitly scoped to the only instance
#         that existed when it was written). No data backfill needed.
#   is_admin(identity) -> bool
#       — identity.username in ADMIN_USERNAMES (env, comma-separated) AND
#         identity.iss in ALLOWED_KVSTORE_URLS (env, comma-separated;
#         falls back to KVSTORE_URL if unset).
#
# Adopting an app (replacing a callback-only verify_token()):
#   1. pip install this package with the [sync] extra (see README.md for
#      the pinned-commit install line).
#   2. Replace the body of the app's verify_token() with a call to this
#      module's verify_token(), passing the app's existing default
#      KVSTORE_URL (resolved however the app already resolves it, e.g. via
#      get_setting() for apps with the admin-settings override pattern).
#   3. Everywhere the app currently does `if row["owner"] != username`,
#      switch to `if not owns(row["owner"], identity, default_kvstore_url)`.
#      Everywhere it currently stores a bare username as owner/creator,
#      store `identity.qualified_id` instead.
#   4. Set ADMIN_USERNAMES / ALLOWED_KVSTORE_URLS in the app's env (the
#      latter can be omitted if the app only ever trusts its own
#      KVSTORE_URL) and call is_admin(identity) in place of any bare
#      `username in ADMIN_USERNAMES` check.
#   5. Update that app's CLAUDE.md "Auth" / "Owner enforcement" sections.

import os
from dataclasses import dataclass
from urllib.parse import urlparse

import jwt
import requests
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError, PyJWTError


@dataclass(frozen=True)
class Identity:
    username: str      # bare `sub` claim — display only, never an ownership key
    iss: str            # issuer URL that actually signed/vouched for this token
    qualified_id: str   # "did:web:<host-from-iss>:users:<username>" — THE
                         # ownership/authorship key


_jwks_clients: dict[str, PyJWKClient] = {}  # iss -> cached client, no allowlist gate


def _get_jwks_client(iss: str) -> PyJWKClient:
    client = _jwks_clients.get(iss)
    if client is None:
        client = PyJWKClient(f"{iss.rstrip('/')}/.well-known/jwks.json")
        _jwks_clients[iss] = client
    return client


def qualified_id(iss: str, username: str) -> str:
    host = urlparse(iss).hostname or iss
    return f"did:web:{host}:users:{username}"


def _is_jwt(token: str) -> bool:
    return token.count(".") == 2


def _extract_bearer(authorization):
    if not authorization:
        return None
    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def verify_token(authorization, default_kvstore_url, timeout=5.0):
    """(Identity, None) on success, (None, (body, status)) on failure —
    same shape apps already use for their own verify_token()."""
    token = _extract_bearer(authorization)
    if not token:
        return None, ({"error": "Authorization header required"}, 401)

    if _is_jwt(token):
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
        except PyJWTError:
            return None, ({"error": "Invalid or expired token"}, 401)
        iss = unverified.get("iss")
        if not iss:
            return None, ({"error": "Invalid or expired token"}, 401)
        try:
            jwks_client = _get_jwks_client(iss)
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            payload = jwt.decode(token, signing_key.key, algorithms=["ES256"], issuer=iss)
        except (PyJWTError, PyJWKClientError):
            return None, ({"error": "Invalid or expired token"}, 401)
        username = payload.get("sub")
        if not username:
            return None, ({"error": "Invalid or expired token"}, 401)
        return Identity(username, iss, qualified_id(iss, username)), None

    # Opaque/legacy token — kvstore holds the hash, can't verify locally.
    try:
        resp = requests.get(
            f"{default_kvstore_url.rstrip('/')}/auth/verify",
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        )
    except requests.RequestException:
        return None, ({"error": "KVStore unreachable"}, 502)
    if resp.status_code != 200:
        return None, ({"error": "Invalid or expired token"}, 401)
    username = (resp.json() or {}).get("username") or ""
    if not username:
        return None, ({"error": "Invalid or expired token"}, 401)
    return Identity(username, default_kvstore_url, qualified_id(default_kvstore_url, username)), None


def owns(stored_value, identity: Identity, default_kvstore_url: str) -> bool:
    if stored_value == identity.qualified_id:
        return True
    return stored_value == identity.username and identity.iss == default_kvstore_url


def is_admin(identity: Identity) -> bool:
    if not identity:
        return False
    admin_usernames = set(os.environ.get("ADMIN_USERNAMES", "").split(","))
    if identity.username not in admin_usernames:
        return False
    trusted_issuers_raw = os.environ.get("ALLOWED_KVSTORE_URLS") or os.environ.get("KVSTORE_URL", "")
    trusted_issuers = set(trusted_issuers_raw.split(","))
    return identity.iss in trusted_issuers
