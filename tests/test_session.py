"""
Unit tests for SessionManager:
Session lifecycle, inactivity tracking, DEK memory security, locking, unlocking, and logout.
"""

import time
import pytest
from security.session import SessionManager
from security.authentication import AuthenticationService
from services.audit_service import AuditService


def test_session_start_and_access(memory_db):
    """Verifies that an active session grants access to DEK and user profile."""
    audit = AuditService(memory_db)
    auth = AuthenticationService(memory_db, audit)
    reg_res = auth.register("session_user", "ValidMasterPassword#2026", "ValidMasterPassword#2026")
    assert reg_res.success

    session = SessionManager(audit_service=audit)
    session.start_session(reg_res.user, reg_res.dek)

    assert session.is_authenticated is True
    assert session.is_locked is False
    assert session.current_user.username == "session_user"
    assert session.get_dek() == reg_res.dek


def test_session_manual_lock_and_unlock(memory_db):
    """Verifies manual session locking, key dereferencing, and unlocking with master password."""
    audit = AuditService(memory_db)
    auth = AuthenticationService(memory_db, audit)
    reg_res = auth.register("lock_user", "LockPassword#2026", "LockPassword#2026")
    original_dek = reg_res.dek

    session = SessionManager(audit_service=audit)
    session.start_session(reg_res.user, original_dek)

    # 1. Lock session
    session.lock_session(reason="User manual lock")
    assert session.is_locked is True
    assert session.is_authenticated is True  # Still authenticated, but locked

    # DEK must not be accessible while locked
    with pytest.raises(PermissionError):
        session.get_dek()

    # 2. Attempt unlock with incorrect password
    unlock_fail = session.unlock_session("WrongPassword#9999")
    assert unlock_fail is False
    assert session.is_locked is True

    # 3. Attempt unlock with correct password
    unlock_success = session.unlock_session("LockPassword#2026")
    assert unlock_success is True
    assert session.is_locked is False
    assert session.get_dek() == original_dek


def test_session_inactivity_timeout(memory_db):
    """Verifies automatic session locking when inactivity exceeds threshold."""
    audit = AuditService(memory_db)
    auth = AuthenticationService(memory_db, audit)
    reg_res = auth.register("timeout_user", "TimeoutPassword#2026", "TimeoutPassword#2026")

    locked_called = []
    session = SessionManager(audit_service=audit, default_timeout_minutes=1)
    session.add_on_lock_listener(lambda: locked_called.append(True))
    session.start_session(reg_res.user, reg_res.dek)

    # Fast-forward inactivity: simulate 65 seconds elapsed
    session._last_activity = time.monotonic() - 65

    # Check inactivity
    is_locked = session.check_inactivity()
    assert is_locked is True
    assert session.is_locked is True
    assert len(locked_called) == 1

    # Verify audit log contains inactivity lock
    logs = audit.get_logs_for_user(reg_res.user.user_id)
    assert any("Inactivity timeout" in (l.details or "") for l in logs)


def test_session_logout(memory_db):
    """Verifies that logout clears user and DEK completely and fires listener."""
    audit = AuditService(memory_db)
    auth = AuthenticationService(memory_db, audit)
    reg_res = auth.register("logout_user", "LogoutPassword#2026", "LogoutPassword#2026")

    logout_called = []
    session = SessionManager(audit_service=audit)
    session.add_on_logout_listener(lambda: logout_called.append(True))
    session.start_session(reg_res.user, reg_res.dek)

    session.logout()

    assert session.is_authenticated is False
    assert session.is_locked is False
    assert session.current_user is None
    assert len(logout_called) == 1

    with pytest.raises(PermissionError):
        session.get_dek()

    # Verify LOGOUT action logged in audit trail
    logs = audit.get_logs_for_user(reg_res.user.user_id)
    assert any(l.action == "LOGOUT" for l in logs)
