"""Tests for auth utilities — password hashing + verification."""

from app.auth import hash_password, verify_password


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
