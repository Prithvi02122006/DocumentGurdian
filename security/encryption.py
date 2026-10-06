"""
AES-256-GCM Envelope Encryption and Key Derivation for Document Guardian.
Ensures authenticated encryption at rest with tamper resistance.
"""

import base64
import hashlib
import hmac
import os
import secrets
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

try:
    from argon2.low_level import hash_secret_raw, Type
    HAS_ARGON2_LOW_LEVEL = True
except ImportError:
    HAS_ARGON2_LOW_LEVEL = False

PBKDF2_ROUNDS = 600000


def derive_kek(password: str, salt: bytes) -> bytes:
    """
    Derives a 256-bit Key Encrypting Key (KEK) from password and salt.
    Uses Argon2id low-level if available, else PBKDF2-HMAC-SHA256.
    """
    if HAS_ARGON2_LOW_LEVEL:
        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)


def generate_dek() -> bytes:
    """Generates a cryptographically secure 256-bit Data Encryption Key (DEK)."""
    return os.urandom(32)


def encrypt_aes_gcm(
    plaintext: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """
    Encrypts plaintext bytes with AES-256-GCM.
    Returns (ciphertext_with_tag, 12_byte_nonce).
    """
    if len(key) != 32:
        raise ValueError("Encryption key must be exactly 32 bytes (256 bits).")
    nonce = os.urandom(12)  # Standard 96-bit nonce for AES-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return ciphertext, nonce


def decrypt_aes_gcm(
    ciphertext: bytes,
    nonce: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None
) -> bytes:
    """
    Decrypts AES-256-GCM ciphertext bytes.
    Raises InvalidTag if ciphertext/tag has been altered or key is invalid.
    """
    if len(key) != 32:
        raise ValueError("Decryption key must be exactly 32 bytes (256 bits).")
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


def wrap_dek(dek: bytes, kek: bytes) -> Tuple[str, str]:
    """
    Encrypts (wraps) the user's DEK with their KEK.
    Returns (encrypted_dek_b64, nonce_b64).
    """
    ciphertext, nonce = encrypt_aes_gcm(dek, kek)
    return (
        base64.b64encode(ciphertext).decode("ascii"),
        base64.b64encode(nonce).decode("ascii")
    )


def unwrap_dek(encrypted_dek_b64: str, nonce_b64: str, kek: bytes) -> bytes:
    """
    Decrypts (unwraps) the stored DEK using the derived KEK.
    Returns the raw 32-byte DEK.
    """
    ciphertext = base64.b64decode(encrypted_dek_b64.encode("ascii"))
    nonce = base64.b64decode(nonce_b64.encode("ascii"))
    return decrypt_aes_gcm(ciphertext, nonce, kek)


def encrypt_string(plaintext_str: str, key: bytes) -> Tuple[str, str]:
    """Encrypts a string and returns base64 (ciphertext, nonce)."""
    cipher_bytes, nonce_bytes = encrypt_aes_gcm(plaintext_str.encode("utf-8"), key)
    return (
        base64.b64encode(cipher_bytes).decode("ascii"),
        base64.b64encode(nonce_bytes).decode("ascii")
    )


def decrypt_string(ciphertext_b64: str, nonce_b64: str, key: bytes) -> str:
    """Decrypts base64 (ciphertext, nonce) and returns string."""
    cipher_bytes = base64.b64decode(ciphertext_b64.encode("ascii"))
    nonce_bytes = base64.b64decode(nonce_b64.encode("ascii"))
    decrypted_bytes = decrypt_aes_gcm(cipher_bytes, nonce_bytes, key)
    return decrypted_bytes.decode("utf-8")


def generate_document_hash(raw_number: str, user_salt_hex: str) -> str:
    """
    Generates a per-user HMAC-SHA256 hash of a document number for duplicate detection
    without exposing or storing plaintext document numbers.
    """
    cleaned = raw_number.strip().replace(" ", "").replace("-", "").upper()
    salt = bytes.fromhex(user_salt_hex)
    return hmac.new(salt, cleaned.encode("utf-8"), hashlib.sha256).hexdigest()
