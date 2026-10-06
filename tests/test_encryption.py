"""
Unit tests for AES-256-GCM envelope encryption, KEK derivation, and DEK wrapping.
"""

import os
import pytest
from cryptography.exceptions import InvalidTag
from security.encryption import (
    derive_kek, generate_dek, encrypt_aes_gcm, decrypt_aes_gcm,
    wrap_dek, unwrap_dek, encrypt_string, decrypt_string,
    generate_document_hash
)


def test_kek_derivation():
    """Verifies deterministic KEK derivation given identical password and salt."""
    salt = os.urandom(32)
    kek1 = derive_kek("MasterSecret!99", salt)
    kek2 = derive_kek("MasterSecret!99", salt)

    assert len(kek1) == 32
    assert kek1 == kek2

    # Different salt yields different KEK
    other_salt = os.urandom(32)
    kek3 = derive_kek("MasterSecret!99", other_salt)
    assert kek1 != kek3


def test_aes_gcm_bytes_roundtrip():
    """Verifies AES-256-GCM byte encryption and decryption roundtrip."""
    key = generate_dek()
    plaintext = b"CONFIDENTIAL_AADHAAR_NUMBER_1234_5678"

    ciphertext, nonce = encrypt_aes_gcm(plaintext, key)
    assert len(nonce) == 12
    assert ciphertext != plaintext

    decrypted = decrypt_aes_gcm(ciphertext, nonce, key)
    assert decrypted == plaintext


def test_aes_gcm_tamper_detection():
    """Verifies that modifying ciphertext bytes triggers InvalidTag tamper failure."""
    key = generate_dek()
    plaintext = b"Sensitive Passport Data"
    ciphertext, nonce = encrypt_aes_gcm(plaintext, key)

    # Tamper with the last byte
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 0x01

    with pytest.raises(InvalidTag):
        decrypt_aes_gcm(bytes(tampered), nonce, key)


def test_aes_gcm_wrong_key_fails():
    """Verifies that decrypting with the wrong key triggers InvalidTag."""
    key1 = generate_dek()
    key2 = generate_dek()
    plaintext = b"Secure Document Info"

    ciphertext, nonce = encrypt_aes_gcm(plaintext, key1)

    with pytest.raises(InvalidTag):
        decrypt_aes_gcm(ciphertext, nonce, key2)


def test_envelope_dek_wrapping():
    """Verifies wrapping and unwrapping the DEK using a KEK."""
    master_password = "MasterPassword!2026"
    salt = os.urandom(32)
    kek = derive_kek(master_password, salt)

    dek = generate_dek()
    enc_dek_b64, nonce_b64 = wrap_dek(dek, kek)

    assert isinstance(enc_dek_b64, str)
    assert isinstance(nonce_b64, str)

    unwrapped_dek = unwrap_dek(enc_dek_b64, nonce_b64, kek)
    assert unwrapped_dek == dek


def test_string_encryption_roundtrip():
    """Verifies encrypt_string and decrypt_string helpers."""
    key = generate_dek()
    original_text = "5234 8901 2345"  # Sample document number

    cipher_b64, nonce_b64 = encrypt_string(original_text, key)
    assert original_text not in cipher_b64

    decrypted_text = decrypt_string(cipher_b64, nonce_b64, key)
    assert decrypted_text == original_text


def test_document_hash_duplicate_detection():
    """Verifies HMAC document hash generation for duplicate checks."""
    user_salt_hex = os.urandom(32).hex()
    doc_num1 = "ABCDE1234F"
    doc_num2 = "abcde 1234 f "  # Normalized should match

    hash1 = generate_document_hash(doc_num1, user_salt_hex)
    hash2 = generate_document_hash(doc_num2, user_salt_hex)
    assert hash1 == hash2

    other_user_salt_hex = os.urandom(32).hex()
    hash3 = generate_document_hash(doc_num1, other_user_salt_hex)
    assert hash1 != hash3  # Different salt across users
