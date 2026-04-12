"""Tests for auth utilities — password hashing + verification + JWT."""

from app.auth import hash_password, verify_password, ensure_admin_user
from app.devices import create_token, decode_token


class TestPasswordHashing:
    def test_hash_returns_bcrypt_string(self):
        h = hash_password("testpassword123")
        assert h.startswith("$2b$") or h.startswith("$2a$")
        assert len(h) == 60

    def test_verify_correct_password(self):
        h = hash_password("mySecret!")
        assert verify_password("mySecret!", h) is True

    def test_verify_wrong_password(self):
        h = hash_password("correct")
        assert verify_password("wrong", h) is False

    def test_different_hashes_for_same_password(self):
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2  # bcrypt uses random salt

    def test_empty_password_hashes(self):
        h = hash_password("")
        assert verify_password("", h) is True
        assert verify_password("notempty", h) is False


class TestJWT:
    def test_create_and_decode_roundtrip(self):
        token = create_token(42, "user@test.com")
        payload = decode_token(token)
        assert payload["sub"] == "42"
        assert payload["email"] == "user@test.com"
        assert "exp" in payload

    def test_token_is_string(self):
        token = create_token(1, "a@b.com")
        assert isinstance(token, str)
        assert len(token) > 20

    def test_decode_invalid_token_raises(self):
        import pytest
        with pytest.raises(Exception):
            decode_token("not.a.valid.token")


class TestEnsureAdminUser:
    def test_ensure_admin_does_not_raise(self):
        ensure_admin_user()

    def test_ensure_admin_is_idempotent(self):
        ensure_admin_user()
        ensure_admin_user()
