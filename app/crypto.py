"""Envelope encryption for snapshot payloads (AES-256-GCM).

Model
=====

Two keys per account:

- **KEK** (Key Encryption Key) — derived once from the master key +
  per-account salt via HKDF-SHA256. The master key comes from
  ``NKS_WDC_MASTER_KEY`` (32+ bytes random) and never hits the DB.
- **DEK** (Data Encryption Key) — fresh 32 bytes generated per
  ``AccountEncryptionKey`` row, wrapped with the KEK via AES-256-GCM
  and stored in ``wrapped_dek``.

A snapshot is encrypted by packing the payload, then AES-256-GCM
encrypting the resulting bytes with the current DEK. ``encryption_kid``
on ``DeviceSnapshot`` pins which DEK unwraps it.

Rotation
========

Create a new ``AccountEncryptionKey`` (with ``kek_source='master'``),
mark the previous one ``retired_at=now``. New snapshots pick up the new
kid automatically; old snapshots remain decryptable until the retired
row is purged.

Dev mode (``NKS_WDC_CATALOG_DEV=1``) generates an ephemeral master key
cached in-process — all encrypted data is lost on restart.
"""

from __future__ import annotations

import os
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


_HKDF_INFO = b"nks-wdc-catalog-kek/v1"
_AES_KEY_BYTES = 32
_NONCE_BYTES = 12


# ── Master key management ──────────────────────────────────────────────

_EPHEMERAL_MASTER_KEY: Optional[bytes] = None


class MasterKeyMissing(RuntimeError):
    """Raised when encryption is requested but no master key is configured."""


def master_key() -> bytes:
    """Return the master key (bytes). Honours env + DEV ephemeral fallback."""
    global _EPHEMERAL_MASTER_KEY
    env = os.environ.get("NKS_WDC_MASTER_KEY")
    if env:
        key = env.encode("utf-8") if isinstance(env, str) else env
        if len(key) < _AES_KEY_BYTES:
            import hashlib
            key = hashlib.sha256(key).digest()
        return key[:_AES_KEY_BYTES]
    if os.environ.get("NKS_WDC_CATALOG_DEV") == "1":
        if _EPHEMERAL_MASTER_KEY is None:
            _EPHEMERAL_MASTER_KEY = AESGCM.generate_key(bit_length=256)
        return _EPHEMERAL_MASTER_KEY
    raise MasterKeyMissing(
        "NKS_WDC_MASTER_KEY must be set for snapshot encryption."
    )


def _derive_kek(account_id: int, salt: bytes) -> bytes:
    """HKDF(master_key, salt=account_salt, info='nks-wdc-catalog-kek/v1')."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_AES_KEY_BYTES,
        salt=salt,
        info=_HKDF_INFO + f"|account={account_id}".encode("ascii"),
    )
    return hkdf.derive(master_key())


# ── DEK lifecycle ──────────────────────────────────────────────────────

def generate_dek() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def wrap_dek(dek: bytes, account_id: int, salt: bytes) -> bytes:
    """Encrypt DEK under the per-account KEK. Returns nonce||ciphertext."""
    kek = _derive_kek(account_id, salt)
    nonce = os.urandom(_NONCE_BYTES)
    ct = AESGCM(kek).encrypt(nonce, dek, _aad(account_id))
    return nonce + ct


def unwrap_dek(wrapped: bytes, account_id: int, salt: bytes) -> bytes:
    kek = _derive_kek(account_id, salt)
    nonce, ct = wrapped[:_NONCE_BYTES], wrapped[_NONCE_BYTES:]
    return AESGCM(kek).decrypt(nonce, ct, _aad(account_id))


def _aad(account_id: int) -> bytes:
    return f"nks-wdc-account-{account_id}".encode("ascii")


# ── Payload encryption ─────────────────────────────────────────────────

def encrypt_payload(
    plaintext: bytes, dek: bytes, *, aad: Optional[bytes] = None
) -> bytes:
    nonce = os.urandom(_NONCE_BYTES)
    ct = AESGCM(dek).encrypt(nonce, plaintext, aad)
    return nonce + ct


def decrypt_payload(
    ciphertext: bytes, dek: bytes, *, aad: Optional[bytes] = None
) -> bytes:
    nonce, ct = ciphertext[:_NONCE_BYTES], ciphertext[_NONCE_BYTES:]
    return AESGCM(dek).decrypt(nonce, ct, aad)


__all__ = [
    "MasterKeyMissing",
    "master_key",
    "generate_dek",
    "wrap_dek",
    "unwrap_dek",
    "encrypt_payload",
    "decrypt_payload",
]
