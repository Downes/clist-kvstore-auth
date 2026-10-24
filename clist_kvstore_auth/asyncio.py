# FastAPI / httpx variant of local kvstore JWT verification ("Pattern B").
# Same contract and design rationale as clist_kvstore_auth.sync — see that
# module's header for the full writeup. This module exists only because the
# opaque-token fallback and the two FastAPI apps adopting it (annotations,
# opml2json) are async; PyJWKClient's JWKS fetch is a blocking network call
# (it uses `urllib` under the hood, not `httpx`), so it's wrapped in
# `asyncio.to_thread` here rather than reimplemented.
#
# Contract (identical to clist_kvstore_auth.sync):
#   Identity(username, iss, qualified_id)
#   await verify_token(authorization, default_kvstore_url, timeout=5.0)
#       -> (Identity, None) | (None, (body: dict, status: int))
#   qualified_id(iss, username) -> str
#   owns(stored_value, identity, default_kvstore_url) -> bool
#   is_admin(identity) -> bool
#       — identity.username in ADMIN_USERNAMES (env, comma-separated) AND
#         identity.iss in ALLOWED_KVSTORE_URLS (env, comma-separated;
#         falls back to KVSTORE_URL if unset) — the standardized env var
#         for "which issuers are trusted" across every app.
#
# Adopting an app: same five steps as clist_kvstore_auth.sync's header,
# except install with the [asyncio] extra and `await` verify_token().

import asyncio
import os
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx
import jwt
from jwt import PyJWKClient
from jwt.exceptions import ExpiredSignatureError, PyJWKClientError, PyJWTError

# See clist_kvstore_auth.sync's header comment for the rationale — same
# per-failure-mode messages, kept in sync by hand between the two variants.
_MSG_KEY_MISMATCH = (
    "Your session can't be verified against the current signing key. "
    "Please log out and log back in."
)
_MSG_EXPIRED = "Your session has expired. Please log in again."
_MSG_INVALID = "Invalid or expired token. Please log in again."


@dataclass(frozen=True)
class Identity:
    username: str
    iss: str
    qualified_id: str


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


def _verify_jwt_blocking(token: str, iss: str):
    """Runs in a worker thread via asyncio.to_thread — PyJWKClient's JWKS
    fetch is a blocking network call."""
    jwks_client = _get_jwks_client(iss)
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    return jwt.decode(token, signing_key.key, algorithms=["ES256"], issuer=iss)


async def verify_token(authorization, default_kvstore_url, timeout=5.0):
    """(Identity, None) on success, (None, (body, status)) on failure —
    same shape apps already use for their own verify_token()."""
    token = _extract_bearer(authorization)
    if not token:
        return None, ({"error": "Authorization header required"}, 401)

    if _is_jwt(token):
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
        except PyJWTError:
            return None, ({"error": _MSG_INVALID}, 401)
        iss = unverified.get("iss")
        if not iss:
            return None, ({"error": _MSG_INVALID}, 401)
        try:
            payload = await asyncio.to_thread(_verify_jwt_blocking, token, iss)
        except PyJWKClientError:
            return None, ({"error": _MSG_KEY_MISMATCH}, 401)
        except ExpiredSignatureError:
            return None, ({"error": _MSG_EXPIRED}, 401)
        except PyJWTError:
            return None, ({"error": _MSG_INVALID}, 401)
        username = payload.get("sub")
        if not username:
            return None, ({"error": _MSG_INVALID}, 401)
        return Identity(username, iss, qualified_id(iss, username)), None

    # Opaque/legacy token — kvstore holds the hash, can't verify locally.
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{default_kvstore_url.rstrip('/')}/auth/verify",
                headers={"Authorization": f"Bearer {token}"},
                timeout=timeout,
            )
    except httpx.RequestError:
        return None, ({"error": "KVStore unreachable"}, 502)
    if resp.status_code != 200:
        # Relay kvstore's own message (e.g. "Token expired") when it gave
        # one, rather than flattening every opaque-token failure to the
        # same generic text.
        detail = None
        try:
            detail = (resp.json() or {}).get("error")
        except ValueError:
            pass
        return None, ({"error": detail or _MSG_INVALID}, 401)
    username = (resp.json() or {}).get("username") or ""
    if not username:
        return None, ({"error": _MSG_INVALID}, 401)
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
