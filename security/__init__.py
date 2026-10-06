"""Security package exports for Document Guardian."""
from security.hashing import hash_password, verify_password
from security.encryption import (
    derive_kek, generate_dek, encrypt_aes_gcm, decrypt_aes_gcm,
    wrap_dek, unwrap_dek, encrypt_string, decrypt_string,
    generate_document_hash
)
from security.authentication import (
    AuthenticationService, AuthResult, validate_password_strength,
    MAX_FAILED_ATTEMPTS, LOCKOUT_MINUTES
)
from security.session import SessionManager, get_session, reset_session

__all__ = [
    "hash_password",
    "verify_password",
    "derive_kek",
    "generate_dek",
    "encrypt_aes_gcm",
    "decrypt_aes_gcm",
    "wrap_dek",
    "unwrap_dek",
    "encrypt_string",
    "decrypt_string",
    "generate_document_hash",
    "AuthenticationService",
    "AuthResult",
    "validate_password_strength",
    "MAX_FAILED_ATTEMPTS",
    "LOCKOUT_MINUTES",
    "SessionManager",
    "get_session",
    "reset_session",
]
