"""RFC 6238 TOTP helpers for admin UI two-factor auth.

Implemented inline rather than via ``pyotp`` to keep the dep tree tight —
TOTP is a 30-line HMAC-SHA1 truncation over a 30 s Unix-time step. The
helpers below cover every piece the admin UI + login flow need:

- ``new_secret()`` — cryptographically random base32 secret, no padding
- ``otpauth_uri(secret, account, issuer)`` — the URI an authenticator
  app consumes (via QR scan or manual paste)
- ``verify(secret, code, drift=1)`` — constant-time verify with optional
  step drift window so a slightly-slow clock doesn't lock the user out
- ``generate_recovery_codes(n=8)`` — human-readable one-time fallback
  codes when the authenticator device is lost
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

TOTP_STEP = 30  # seconds per window (RFC 6238 §5.2)
TOTP_DIGITS = 6  # what every major authenticator renders
TOTP_DRIFT = 1  # accept previous + next window too (clock skew tolerance)
RECOVERY_CODE_GROUPS = 2
RECOVERY_CODE_GROUP_LEN = 5  # → "abcde-fghij", 10 chars of entropy


def new_secret() -> str:
    """Return a 160-bit base32 secret (no padding) — matches the size
    Google Authenticator, Authy, 1Password, etc. generate themselves."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _decode(secret_b32: str) -> bytes:
    """Pad + decode a user-supplied base32 secret (mixed case tolerated)."""
    s = secret_b32.strip().replace(" ", "").upper()
    # Pad to multiple of 8 so `b32decode` accepts it.
    return base64.b32decode(s + "=" * (-len(s) % 8), casefold=True)


def _hotp(key: bytes, counter: int) -> str:
    """RFC 4226 HOTP — 6-digit truncation of HMAC-SHA1(key, counter)."""
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    word = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{word % (10 ** TOTP_DIGITS):0{TOTP_DIGITS}d}"


def now_counter(at: float | None = None) -> int:
    """Current TOTP step counter (Unix seconds / 30)."""
    return int((at if at is not None else time.time()) // TOTP_STEP)


def verify(
    secret_b32: str,
    code: str,
    *,
    drift: int = TOTP_DRIFT,
    at: float | None = None,
) -> bool:
    """Return True iff ``code`` matches the current TOTP of ``secret_b32``
    within ±``drift`` 30-second windows. Constant-time code comparison."""
    code = code.replace(" ", "").replace("-", "").strip()
    if not code.isdigit() or len(code) != TOTP_DIGITS:
        return False
    try:
        key = _decode(secret_b32)
    except (ValueError, TypeError, base64.binascii.Error):
        return False
    if not key:
        return False
    counter = now_counter(at)
    # Combine all candidate codes and check in constant time so we don't
    # leak which window matched via timing — the observable behavior is
    # match/no-match, nothing else.
    matched = False
    for delta in range(-drift, drift + 1):
        candidate = _hotp(key, counter + delta)
        # hmac.compare_digest works on strings of equal length → safe.
        if hmac.compare_digest(candidate, code):
            matched = True
    return matched


def otpauth_uri(secret_b32: str, *, account: str, issuer: str = "NKS WDC") -> str:
    """Build the ``otpauth://totp/...`` URI authenticator apps consume.

    Per the de-facto Google Authenticator spec the label is
    ``Issuer:account``, and the ``issuer`` query param is set for good
    measure so older apps that ignore the label prefix still render it.
    """
    label = quote(f"{issuer}:{account}", safe="")
    params = (
        f"secret={secret_b32}"
        f"&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1"
        f"&digits={TOTP_DIGITS}"
        f"&period={TOTP_STEP}"
    )
    return f"otpauth://totp/{label}?{params}"


# Recovery codes are stored server-side as bcrypt hashes (like PATs) so
# a DB leak never surfaces usable fallback codes. The human-facing form
# is lowercase a-z-2-7 (base32 alphabet minus 0/1/O/I confusables) in
# 5-5 groups so they read out cleanly over voice or paper.
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # 31 chars, no 0/1/i/l/o


def generate_recovery_codes(n: int = 8) -> list[str]:
    """Return ``n`` human-readable one-time recovery codes.

    Format: ``abcde-fghij`` (2 × 5-char groups drawn from a confusable-
    free alphabet). The caller is responsible for showing these once and
    persisting only their hashes.
    """
    out: list[str] = []
    for _ in range(n):
        groups = [
            "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(RECOVERY_CODE_GROUP_LEN))
            for _ in range(RECOVERY_CODE_GROUPS)
        ]
        out.append("-".join(groups))
    return out


def normalize_recovery_code(raw: str) -> str:
    """Lowercase + strip whitespace/dashes so the user can paste the
    code in whatever shape they remember. Matches what we store."""
    return raw.strip().lower().replace(" ", "").replace("-", "")


__all__ = [
    "new_secret",
    "verify",
    "otpauth_uri",
    "generate_recovery_codes",
    "normalize_recovery_code",
    "now_counter",
    "TOTP_STEP",
    "TOTP_DIGITS",
]
