"""Personal Access Token issuance + verification.

Tokens look like ``nks_pat_<40 url-safe chars>``. The prefix (first 10
chars including ``nks_pat_``) is stored in clear so the admin UI can
show "nks_pat_AbC…" in the revocation list. The tail is bcrypt-hashed.

Authentication flow:
1. Client sends ``Authorization: Bearer nks_pat_abc…``.
2. ``try_authenticate_pat`` reads the prefix to narrow the DB query to
   candidate rows (no full-table bcrypt scan).
3. For each candidate, ``bcrypt.checkpw`` compares against the stored
   hash. Matching row → return its ``Account``.
4. Updates ``last_used_at`` for auditability (best-effort, never
   blocks the auth decision).
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Optional

import bcrypt
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import BCRYPT_ROUNDS
from .db import Account, PersonalAccessToken


TOKEN_PREFIX = "nks_pat_"
PREFIX_PERSISTED_LEN = 10  # "nks_pat_Ab" stored for UI lookup


def generate_token() -> str:
    """Return a fresh plaintext token. Never persisted beyond this scope."""
    return TOKEN_PREFIX + secrets.token_urlsafe(30)


def issue(
    db: Session,
    *,
    account_id: int,
    name: str,
    expires_at: Optional[datetime] = None,
) -> tuple[PersonalAccessToken, str]:
    """Mint a new token for ``account_id``.

    Returns ``(row, plaintext)``. Plaintext is shown to the caller
    exactly once — never readable again after this call returns.
    """
    plaintext = generate_token()
    hashed = bcrypt.hashpw(
        plaintext.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    ).decode("ascii")
    row = PersonalAccessToken(
        account_id=account_id,
        name=name.strip()[:128] or "unnamed",
        token_hash=hashed,
        token_prefix=plaintext[:PREFIX_PERSISTED_LEN],
        expires_at=expires_at.replace(tzinfo=None) if expires_at else None,
    )
    db.add(row)
    db.flush()
    return row, plaintext


def revoke(db: Session, *, account_id: int, token_id: int) -> bool:
    row = db.get(PersonalAccessToken, token_id)
    if row is None or row.account_id != account_id:
        return False
    if row.revoked_at is not None:
        return True  # already revoked, idempotent
    row.revoked_at = datetime.now(timezone.utc).replace(tzinfo=None)
    return True


def list_for(db: Session, *, account_id: int) -> list[PersonalAccessToken]:
    return list(
        db.scalars(
            select(PersonalAccessToken)
            .where(PersonalAccessToken.account_id == account_id)
            .order_by(PersonalAccessToken.created_at.desc())
        ).all()
    )


def try_authenticate_pat(db: Session, bearer_value: str) -> Optional[Account]:
    """Resolve a bearer token to an ``Account`` if it matches an active
    PAT. Returns ``None`` on any failure (invalid format, expired,
    revoked, wrong bcrypt).

    Best-effort: updates ``last_used_at`` on success but doesn't raise
    if the DB write fails — auth decision already made.
    """
    if not bearer_value or not bearer_value.startswith(TOKEN_PREFIX):
        return None
    prefix = bearer_value[:PREFIX_PERSISTED_LEN]
    # Narrow candidate set by the persisted prefix so we don't bcrypt
    # every row in the table on every request.
    candidates = db.scalars(
        select(PersonalAccessToken).where(
            PersonalAccessToken.token_prefix == prefix,
            PersonalAccessToken.revoked_at.is_(None),
        )
    ).all()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for row in candidates:
        if row.expires_at is not None and row.expires_at <= now:
            continue
        try:
            if not bcrypt.checkpw(
                bearer_value.encode("utf-8"),
                row.token_hash.encode("ascii"),
            ):
                continue
        except Exception:  # noqa: BLE001
            continue
        # Match. Look up account + stamp last-used.
        account = db.get(Account, row.account_id)
        if account is None or account.suspended_at is not None:
            return None
        try:
            row.last_used_at = now
            db.flush()
        except Exception:  # noqa: BLE001
            pass
        return account
    return None


__all__ = [
    "TOKEN_PREFIX",
    "generate_token",
    "issue",
    "revoke",
    "list_for",
    "try_authenticate_pat",
]
