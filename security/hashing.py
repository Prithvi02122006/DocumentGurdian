"""
Secure password hashing and verification module for Document Guardian.
Uses Argon2id with PBKDF2-HMAC-SHA256 fallback and timing-attack-safe comparison.
"""

import hashlib
import os
import secrets
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

# Check if argon2-cffi is available
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, VerificationError
    # Recommended RFC 9106 Argon2id parameters
    _hasher = PasswordHasher(
        time_cost=3,
        memory_cost=65536,  # 64 MB
        parallelism=4,
        hash_len=32,
        salt_len=16
    )
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False
    logger.warning("argon2-cffi not found, falling back to PBKDF2-HMAC-SHA256.")

PBKDF2_ITERATIONS = 600000  # OWASP recommendation for PBKDF2-HMAC-SHA256


def hash_password(password: str) -> Tuple[str, str]:
    """
    Hashes a plaintext password using Argon2id (or PBKDF2 if Argon2 is unavailable).
    Returns a tuple of (password_hash, salt_hex).
    """
    salt = secrets.token_bytes(16)
    salt_hex = salt.hex()

    if HAS_ARGON2:
        # Argon2 embeds its own salt, but we also retain salt_hex for the schema
        password_hash = _hasher.hash(password)
        return password_hash, salt_hex
    else:
        # PBKDF2-HMAC-SHA256 fallback
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PBKDF2_ITERATIONS
        )
        password_hash = f"pbkdf2:sha256:{PBKDF2_ITERATIONS}${salt_hex}${derived.hex()}"
        return password_hash, salt_hex


def verify_password(password: str, password_hash: str, salt_hex: str) -> bool:
    """
    Verifies a password against the stored hash and salt.
    Protects against timing attacks.
    """
    if not password or not password_hash:
        return False

    if password_hash.startswith("$argon2id$") or password_hash.startswith("$argon2"):
        if not HAS_ARGON2:
            logger.error("Stored password requires Argon2id, but argon2 library is unavailable.")
            return False
        try:
            return _hasher.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError):
            return False
        except Exception as e:
            logger.error(f"Argon2 verification error: {e}")
            return False

    elif password_hash.startswith("pbkdf2:sha256:"):
        try:
            parts = password_hash.split("$")
            if len(parts) != 3:
                return False
            iterations = int(parts[0].split(":")[-1])
            stored_salt = bytes.fromhex(parts[1])
            stored_hash = parts[2]

            derived = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                stored_salt,
                iterations
            )
            return secrets.compare_digest(derived.hex(), stored_hash)
        except Exception as e:
            logger.error(f"PBKDF2 verification error: {e}")
            return False

    # Generic PBKDF2 using separate salt_hex column
    try:
        salt = bytes.fromhex(salt_hex)
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PBKDF2_ITERATIONS
        )
        return secrets.compare_digest(derived.hex(), password_hash)
    except Exception:
        return False
