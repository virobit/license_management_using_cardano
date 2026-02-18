"""Password-based AES-256-GCM encryption for wallet key files.

Replaces the machine-bound key_manager.py with a portable, password-derived
approach so encrypted wallets can move between machines.

Interface:
    encrypt_key(plaintext) -> str   (base64 of salt+nonce+ciphertext)
    decrypt_key(encrypted) -> str
"""

import base64
import getpass
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from cardano_license.config import CARDANO_LICENSE_PASSWORD

# ── Key derivation ───────────────────────────────────────────────

_KDF_ITERATIONS = 100_000
_SALT_BYTES = 16
_KEY_BYTES = 32
_NONCE_BYTES = 12

_cached_password: str | None = None


def _get_password() -> str:
    """Return the encryption password (env var, cache, or interactive prompt)."""
    global _cached_password

    if CARDANO_LICENSE_PASSWORD:
        return CARDANO_LICENSE_PASSWORD

    if _cached_password is not None:
        return _cached_password

    _cached_password = getpass.getpass("Cardano License encryption password: ")
    return _cached_password


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from password + salt via PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_BYTES,
        salt=salt,
        iterations=_KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


# ── Public API ───────────────────────────────────────────────────

def encrypt_key(plaintext: str) -> str:
    """Encrypt a string with AES-256-GCM using a password-derived key.

    Output format (base64): salt(16) || nonce(12) || ciphertext+tag
    Each call generates a fresh salt and nonce — safe for multiple values.

    Returns:
        Base64-encoded string of salt + nonce + ciphertext.
    """
    password = _get_password()
    salt = secrets.token_bytes(_SALT_BYTES)
    key = _derive_key(password, salt)
    nonce = secrets.token_bytes(_NONCE_BYTES)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(salt + nonce + ct).decode("ascii")


def decrypt_key(encrypted: str) -> str:
    """Decrypt a value produced by encrypt_key().

    Args:
        encrypted: Base64-encoded salt + nonce + ciphertext.

    Returns:
        Decrypted plaintext string.

    Raises:
        cryptography.exceptions.InvalidTag: Wrong password or corrupted data.
    """
    password = _get_password()
    raw = base64.b64decode(encrypted)
    salt = raw[:_SALT_BYTES]
    nonce = raw[_SALT_BYTES : _SALT_BYTES + _NONCE_BYTES]
    ct = raw[_SALT_BYTES + _NONCE_BYTES :]
    key = _derive_key(password, salt)
    plaintext = AESGCM(key).decrypt(nonce, ct, None)
    return plaintext.decode("utf-8")
