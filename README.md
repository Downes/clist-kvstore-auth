# clist-kvstore-auth

Local JWT/JWKS verification of kvstore login tokens ("Pattern B"), shared
across the `/srv/apps` backends. Replaces the round-trip callback
(`GET {KVSTORE_URL}/auth/verify`) with local signature verification against
the issuing kvstore's own `/.well-known/jwks.json` — the method kvstore's
`AUTH.md` already documents as correct, which no app currently implements.

## Design

Two independent pieces — keep them separate, don't conflate them:

1. **Signature verification is open — no allowlist.** A JWT's `iss` claim
   names the kvstore instance that signed it. We fetch *that* instance's
   JWKS and verify against it — any instance, no pre-registration. This is
   what makes "bring your own kvstore" (`AUTH.md` §7) actually true instead
   of aspirational. An allowlist here would silently turn open federation
   into a walled garden.
2. **A bare username is not a complete identity once any instance can mint
   one.** `alice@kvstore.mooc.ca` and `alice@someone-elses-kvstore.com` are
   different people. Every ownership/authorship check must use
   `qualified_id` (`did:web:<host-from-iss>:users:<username>`), never the
   bare `username`, which is display-only.

Opaque (non-JWT) tokens are a backward-compatible fallback for
pre-migration sessions: kvstore holds the hash and we can't verify it
locally, so we fall back to the callback and treat the result as issued by
the app's own `default_kvstore_url` — true by construction, since no other
instance could have minted that token.

`ADMIN_USERNAMES`-style checks are the one place an issuer allowlist
belongs: admin rights are an operator's own grant, scoped to issuer(s) the
operator trusts, not a general-federation feature. `is_admin()` reads that
allowlist from a standardized env var — `ALLOWED_KVSTORE_URLS`
(comma-separated), falling back to the app's own `KVSTORE_URL` if unset —
rather than open-verifying. This is the one env var name for "which
issuers are trusted" across every app; it's also the intended convention
for other global, cross-app config going forward, not just this one case.

## Modules / stack / used by

| Module                        | Stack            | Used by |
|--------------------------------|-------------------|---------|
| `clist_kvstore_auth.sync`      | Flask + requests  | pastebin, survey, localrss_reader, discussions |
| `clist_kvstore_auth.asyncio`   | FastAPI + httpx   | annotations, opml2json |

(`collab` is Node/Hocuspocus — out of scope for this package; it gets a
hand-mirrored JS implementation of the same contract in its own `auth.js`,
per the migration plan.)

A module literally named `clist_kvstore_auth/asyncio.py` is safe: Python
3's default absolute-import resolves a bare `import asyncio` inside it to
the stdlib module, not to itself.

## Installing (pinned to a commit)

Same discipline as `clist-server-admin` — pin to a commit SHA via the
GitHub archive-tarball URL, not `git+https://` (tarball URLs are
content-addressed by commit; a branch ref can change under you). Add to
`requirements.txt` with the extra matching your variant:

```
# Flask apps:
clist-kvstore-auth[sync] @ https://github.com/Downes/clist-kvstore-auth/archive/<sha>.tar.gz

# FastAPI apps:
clist-kvstore-auth[asyncio] @ https://github.com/Downes/clist-kvstore-auth/archive/<sha>.tar.gz
```

`PyJWT[crypto]` is a direct dependency of the package itself (needed for
ES256 verification), so adopting apps don't need to add it separately.

## Contract (shared across variants)

```python
@dataclass(frozen=True)
class Identity:
    username: str      # bare `sub` claim — display only, never an ownership key
    iss: str            # issuer that actually signed/vouched for this token
    qualified_id: str   # "did:web:<host-from-iss>:users:<username>" — THE
                         # ownership/authorship key

verify_token(authorization, default_kvstore_url, timeout=5.0)
    -> (Identity, None) | (None, (body: dict, status: int))
    # asyncio variant: same signature, `await` it.

qualified_id(iss, username) -> str

owns(stored_value, identity, default_kvstore_url) -> bool
    # True for an exact qualified_id match, OR a legacy bare-username match
    # where the token's issuer is the app's own default kvstore (i.e. a
    # pre-migration row, implicitly scoped to the only instance that
    # existed when it was written). No data backfill needed — old rows
    # keep working as-is under this rule.

is_admin(identity) -> bool
    # identity.username in ADMIN_USERNAMES (env, comma-separated) AND
    # identity.iss in ALLOWED_KVSTORE_URLS (env, comma-separated; falls
    # back to KVSTORE_URL if unset).
```

See each module's header comment for the full adoption checklist (5 steps:
install, swap verify_token's body, switch ownership comparisons to
`owns()`, switch storage writes to `identity.qualified_id`, set
`ADMIN_USERNAMES`/`ALLOWED_KVSTORE_URLS` and call `is_admin()`).

## Standardized env var: `ALLOWED_KVSTORE_URLS`

`is_admin()` is self-contained, matching the sibling `clist-server-admin`
package's `is_admin(username)` convention (reads env, takes no
collections as arguments) — it reads `ADMIN_USERNAMES` and
`ALLOWED_KVSTORE_URLS` directly.

`ALLOWED_KVSTORE_URLS` (comma-separated kvstore URLs) is now the one
standardized env var name for "which issuers are trusted," used the same
way in every app, not picked per app. Apps that don't need multiple
trusted issuers can omit it entirely — `is_admin()` falls back to the
app's own `KVSTORE_URL` in that case, so single-instance ops need zero new
config.

Three apps (opml2json, survey, localrss_reader) already had
`ALLOWED_KVSTORE_URLS` for an unrelated purpose (opml2json's: an SSRF
guard gating which kvstore *any* caller's token could be verified against
at all). Under Pattern B that older, broader meaning narrows everywhere to
just "which issuer(s) to trust for admin rights" — verification itself is
now open to any issuer regardless of this var. Each app's CLAUDE.md should
call out that narrowing explicitly when Pattern B lands there.

This is also meant as the standing convention for future global,
cross-app config of this shape — not a one-off for this package.
