"""Tests for the RFC 6238 TOTP helpers (app/totp.py)."""

from __future__ import annotations

import base64
import time


from app.totp import (
    TOTP_DIGITS,
    TOTP_STEP,
    _hotp,
    generate_recovery_codes,
    new_secret,
    normalize_recovery_code,
    now_counter,
    otpauth_uri,
    verify,
)


def test_new_secret_is_base32_and_160_bits():
    s = new_secret()
    # 160 bits = 20 bytes → base32 w/out padding = 32 chars.
    assert len(s) == 32
    # Re-decoding must round-trip.
    pad = "=" * (-len(s) % 8)
    decoded = base64.b32decode(s + pad)
    assert len(decoded) == 20
    assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in s)


def test_two_new_secrets_are_different():
    assert new_secret() != new_secret()


def test_rfc6238_reference_values():
    """Spot-check against RFC 6238 Appendix B reference vector.

    RFC uses a 20-byte ASCII key ``"12345678901234567890"`` as the SHA1
    shared secret; at Unix time 59 (counter 1) the TOTP is 287082 and
    at Unix time 1111111109 (counter 37037036) it is 081804.
    """
    # Convert the ASCII reference key to base32 the way our API expects.
    key_ascii = b"12345678901234567890"
    secret = base64.b32encode(key_ascii).decode().rstrip("=")

    assert verify(secret, "287082", at=59) is True
    assert verify(secret, "081804", at=1111111109) is True


def test_verify_rejects_wrong_code():
    s = new_secret()
    # "000000" is extremely unlikely to be the right code for any secret
    # at any moment, but assert it doesn't match at least the next 2 windows.
    for delta in range(5):
        assert verify(s, "000000", at=time.time() + delta * TOTP_STEP) is False


def test_verify_tolerates_drift_one_step():
    s = new_secret()
    # Current code must match at the previous and next window too.
    now = time.time()
    from app.totp import _decode
    key = _decode(s)
    counter = now_counter(now)
    code_prev = _hotp(key, counter - 1)
    code_next = _hotp(key, counter + 1)

    assert verify(s, code_prev, at=now) is True
    assert verify(s, code_next, at=now) is True


def test_verify_rejects_drift_two_steps():
    s = new_secret()
    from app.totp import _decode
    key = _decode(s)
    counter = now_counter()
    code_way_off = _hotp(key, counter - 3)
    # Default drift=1 rejects code from counter-3.
    assert verify(s, code_way_off) is False


def test_verify_tolerates_spaces_and_dashes():
    s = new_secret()
    from app.totp import _decode
    c = _hotp(_decode(s), now_counter())
    formatted = c[:3] + " " + c[3:]
    dashed = c[:3] + "-" + c[3:]
    assert verify(s, formatted) is True
    assert verify(s, dashed) is True


def test_verify_rejects_non_digit_or_wrong_length():
    s = new_secret()
    assert verify(s, "") is False
    assert verify(s, "abc123") is False
    assert verify(s, "1234567") is False
    assert verify(s, "12345") is False


def test_verify_rejects_invalid_secret():
    # Not a valid base32 alphabet string.
    assert verify("NOTBASE32!", "123456") is False


def test_otpauth_uri_is_properly_encoded():
    uri = otpauth_uri("JBSWY3DPEHPK3PXP", account="alice@example.com", issuer="NKS WDC")
    assert uri.startswith("otpauth://totp/NKS%20WDC%3Aalice%40example.com?")
    assert "secret=JBSWY3DPEHPK3PXP" in uri
    assert "issuer=NKS%20WDC" in uri
    assert "algorithm=SHA1" in uri
    assert f"digits={TOTP_DIGITS}" in uri
    assert f"period={TOTP_STEP}" in uri


def test_recovery_codes_format_and_uniqueness():
    codes = generate_recovery_codes(8)
    assert len(codes) == 8
    # Every code is ``xxxxx-xxxxx`` drawn from confusable-free alphabet.
    for c in codes:
        assert len(c) == 11 and c[5] == "-"
        for ch in c.replace("-", ""):
            assert ch in "abcdefghjkmnpqrstuvwxyz23456789"
            assert ch not in "0lo1i"  # confusable check
    # Collision within 8 draws from ~32**10 is astronomically unlikely.
    assert len(set(codes)) == 8


def test_recovery_code_normalize_forgives_noise():
    assert normalize_recovery_code("  ABCDE-FGHIJ  ") == "abcdefghij"
    assert normalize_recovery_code("abcde fghij") == "abcdefghij"
    assert normalize_recovery_code("abcdefghij") == "abcdefghij"
