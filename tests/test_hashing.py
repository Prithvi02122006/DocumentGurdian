"""
Unit tests for password hashing and verification.
"""

from security.hashing import hash_password, verify_password, HAS_ARGON2


def test_password_hash_and_verify():
    """Verifies that a password hashes and verifies accurately."""
    password = "StrongPassword#2026"
    pwd_hash, salt_hex = hash_password(password)

    assert pwd_hash is not None
    assert len(salt_hex) == 32  # 16 bytes hex

    # Verification with correct password
    assert verify_password(password, pwd_hash, salt_hex) is True

    # Verification with incorrect password
    assert verify_password("WrongPassword#2026", pwd_hash, salt_hex) is False
    assert verify_password("", pwd_hash, salt_hex) is False
    assert verify_password(password, "", salt_hex) is False


def test_salt_uniqueness():
    """Verifies that hashing the same password twice yields different salts and ciphertexts."""
    password = "MySecurePassword@123"
    hash1, salt1 = hash_password(password)
    hash2, salt2 = hash_password(password)

    assert salt1 != salt2
    assert hash1 != hash2
    assert verify_password(password, hash1, salt1) is True
    assert verify_password(password, hash2, salt2) is True


def test_argon2_presence():
    """Confirms Argon2id is active as preferred hashing engine."""
    assert HAS_ARGON2 is True
    pwd_hash, _ = hash_password("TestArgon#1")
    assert pwd_hash.startswith("$argon2id$")
