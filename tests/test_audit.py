"""
Unit tests for audit logging service.
"""

from services.audit_service import AuditService
from models.audit import AuditAction


def test_audit_logging_and_retrieval(memory_db):
    """Verifies that audit actions are recorded and queryable."""
    audit = AuditService(memory_db)

    # Insert user to associate logs
    with memory_db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (
                username, password_hash, password_salt, kek_salt,
                encrypted_dek, dek_nonce, created_at, updated_at
            ) VALUES ('audit_user', 'hash', 'salt', 'kek_salt', 'dek', 'nonce', '2026-09-22', '2026-09-22')
            """
        )
        user_id = cursor.lastrowid

    audit.log(AuditAction.LOGIN_SUCCESS, user_id=user_id, details="User logged in from desktop")
    audit.log(AuditAction.DOCUMENT_ADDED, user_id=user_id, details="Added Passport record")

    user_logs = audit.get_logs_for_user(user_id)
    assert len(user_logs) == 2
    actions = [log.action for log in user_logs]
    assert "LOGIN_SUCCESS" in actions
    assert "DOCUMENT_ADDED" in actions


def test_audit_log_password_redaction(memory_db):
    """Verifies that accidental password inclusion in details is redacted."""
    audit = AuditService(memory_db)
    audit.log(AuditAction.LOGIN_FAILED, details="Failed password=SuperSecretPassword123!")

    logs = audit.get_all_logs()
    assert len(logs) >= 1
    assert "SuperSecretPassword123!" not in logs[0].details
    assert "***REDACTED***" in logs[0].details
