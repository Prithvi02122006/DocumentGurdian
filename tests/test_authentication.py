"""
Unit and integration tests for AuthenticationService:
Registration, validation, login, lockout, and password change with DEK re-wrapping.
"""

from security.authentication import (
    AuthenticationService, validate_password_strength, MAX_FAILED_ATTEMPTS
)
from services.audit_service import AuditService


def test_password_strength_rules():
    """Verifies that all password complexity criteria are enforced."""
    # Too short
    ok, issues = validate_password_strength("Short1!")
    assert not ok
    assert any("at least 10 characters" in i for i in issues)

    # Missing uppercase
    ok, issues = validate_password_strength("lowercaseonly123!")
    assert not ok
    assert any("uppercase" in i for i in issues)

    # Missing lowercase
    ok, issues = validate_password_strength("UPPERCASEONLY123!")
    assert not ok
    assert any("lowercase" in i for i in issues)

    # Missing digit
    ok, issues = validate_password_strength("NoDigitsInPassword!")
    assert not ok
    assert any("numerical digit" in i for i in issues)

    # Missing special character
    ok, issues = validate_password_strength("NoSpecialCharPassword123")
    assert not ok
    assert any("special symbol" in i for i in issues)

    # Valid strong password
    ok, issues = validate_password_strength("ValidStrongPassword#2026")
    assert ok
    assert len(issues) == 0


def test_user_registration_success(memory_db):
    """Verifies user registration creates user and initializes envelope DEK."""
    auth = AuthenticationService(memory_db)
    res = auth.register("test_citizen", "SecurePass#2026", "SecurePass#2026")

    assert res.success is True
    assert res.user is not None
    assert res.user.username == "test_citizen"
    assert res.dek is not None
    assert len(res.dek) == 32


def test_user_registration_validations(memory_db):
    """Verifies registration error handling for invalid inputs."""
    auth = AuthenticationService(memory_db)

    # Short username
    res = auth.register("ab", "SecurePass#2026", "SecurePass#2026")
    assert not res.success
    assert "between 3 and 30" in res.error_message

    # Password mismatch
    res = auth.register("user_one", "SecurePass#2026", "Different#2026")
    assert not res.success
    assert "Passwords do not match" in res.error_message

    # Weak password
    res = auth.register("user_one", "weak", "weak")
    assert not res.success
    assert "at least 10 characters" in res.error_message

    # Register first user
    res1 = auth.register("unique_user", "SecurePass#2026", "SecurePass#2026")
    assert res1.success

    # Duplicate username (case-insensitive)
    res2 = auth.register("UNIQUE_USER", "SecurePass#2026", "SecurePass#2026")
    assert not res2.success
    assert "already registered" in res2.error_message


def test_login_success(memory_db):
    """Verifies that login authenticates and unwraps the exact same DEK."""
    auth = AuthenticationService(memory_db)
    reg_res = auth.register("login_user", "CorrectPassword#123", "CorrectPassword#123")
    assert reg_res.success
    original_dek = reg_res.dek

    # Perform login
    login_res = auth.login("login_user", "CorrectPassword#123")
    assert login_res.success is True
    assert login_res.user is not None
    assert login_res.user.username == "login_user"
    assert login_res.dek == original_dek
    assert login_res.user.failed_attempts == 0


def test_login_invalid_credentials_and_lockout(memory_db):
    """Verifies tracking of failed attempts and triggers 15-minute temporary lockout."""
    auth = AuthenticationService(memory_db)
    auth.register("target_account", "CorrectPassword#123", "CorrectPassword#123")

    # 1. Non-existent user
    non_user_res = auth.login("unknown_user", "AnyPassword#123")
    assert not non_user_res.success
    assert "Invalid username or password" in non_user_res.error_message

    # 2. Wrong password attempts (1 through 4)
    for attempt in range(1, MAX_FAILED_ATTEMPTS):
        res = auth.login("target_account", "WrongPassword#123")
        assert not res.success
        assert not res.is_locked
        assert f"{MAX_FAILED_ATTEMPTS - attempt} attempt(s) remaining" in res.error_message

    # 3. 5th failed attempt triggers lockout
    lock_res = auth.login("target_account", "WrongPassword#123")
    assert not lock_res.success
    assert lock_res.is_locked is True
    assert "temporarily locked" in lock_res.error_message

    # 4. Immediate attempt even with CORRECT password while locked is rejected
    blocked_res = auth.login("target_account", "CorrectPassword#123")
    assert not blocked_res.success
    assert blocked_res.is_locked is True
    assert "temporarily locked" in blocked_res.error_message


def test_change_password_rewraps_dek(memory_db):
    """Verifies that changing password re-wraps DEK and updates credentials."""
    auth = AuthenticationService(memory_db)
    reg_res = auth.register("pwd_change_user", "InitialPassword#2026", "InitialPassword#2026")
    assert reg_res.success
    original_dek = reg_res.dek
    user_id = reg_res.user.user_id

    # 1. Fail on wrong current password
    fail_res = auth.change_password(
        user_id=user_id,
        current_password="WrongCurrentPassword#123",
        new_password="NewSecurePassword#2026",
        confirm_password="NewSecurePassword#2026"
    )
    assert not fail_res.success
    assert "Current password is incorrect" in fail_res.error_message

    # 2. Fail if new password is same as current
    same_res = auth.change_password(
        user_id=user_id,
        current_password="InitialPassword#2026",
        new_password="InitialPassword#2026",
        confirm_password="InitialPassword#2026"
    )
    assert not same_res.success
    assert "different from current" in same_res.error_message

    # 3. Success change password
    change_res = auth.change_password(
        user_id=user_id,
        current_password="InitialPassword#2026",
        new_password="BrandNewPassword#9999",
        confirm_password="BrandNewPassword#9999"
    )
    assert change_res.success is True
    assert change_res.dek == original_dek

    # 4. Verify login with old password fails
    old_login = auth.login("pwd_change_user", "InitialPassword#2026")
    assert not old_login.success

    # 5. Verify login with new password succeeds and returns the same DEK
    new_login = auth.login("pwd_change_user", "BrandNewPassword#9999")
    assert new_login.success is True
    assert new_login.dek == original_dek
