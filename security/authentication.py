"""
Authentication service for Document Guardian.
Handles user registration, password strength validation, login with lockout protection,
and master password modification with DEK re-wrapping.
"""

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import re
import secrets
from typing import Optional, Tuple, List
import logging

from database.database import DatabaseManager, get_db
from models.user import User
from models.audit import AuditAction
from security.hashing import hash_password, verify_password
from security.encryption import (
    derive_kek, generate_dek, wrap_dek, unwrap_dek
)
from services.audit_service import AuditService

logger = logging.getLogger(__name__)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


@dataclass
class AuthResult:
    """Result of an authentication or account action."""
    success: bool
    user: Optional[User] = None
    dek: Optional[bytes] = None
    error_message: Optional[str] = None
    is_locked: bool = False
    lockout_remaining_seconds: int = 0


def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
    """
    Validates that password meets strict public-service grade security criteria:
    - Minimum 10 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 digit
    - At least 1 special character
    """
    issues = []
    if len(password) < 10:
        issues.append("Password must be at least 10 characters long.")
    if not re.search(r"[A-Z]", password):
        issues.append("Password must include at least one uppercase letter (A-Z).")
    if not re.search(r"[a-z]", password):
        issues.append("Password must include at least one lowercase letter (a-z).")
    if not re.search(r"[0-9]", password):
        issues.append("Password must include at least one numerical digit (0-9).")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?~`]", password):
        issues.append("Password must include at least one special symbol (!@#$%^&*...).")

    return (len(issues) == 0, issues)


class AuthenticationService:
    """Core service for user credentials, lockout policies, and session envelope keys."""

    def __init__(self, db: Optional[DatabaseManager] = None, audit_service: Optional[AuditService] = None):
        self.db = db or get_db()
        self.audit = audit_service or AuditService(self.db)

    def register(
        self,
        username: str,
        password: str,
        confirm_password: str
    ) -> AuthResult:
        """
        Creates a new user account with secure Argon2/PBKDF2 hashing
        and envelope-encrypted Data Encryption Key (DEK).
        """
        cleaned_username = username.strip()
        if not cleaned_username or len(cleaned_username) < 3 or len(cleaned_username) > 30:
            return AuthResult(
                success=False,
                error_message="Username must be between 3 and 30 characters."
            )

        if not re.match(r"^[a-zA-Z0-9_.-]+$", cleaned_username):
            return AuthResult(
                success=False,
                error_message="Username may only contain alphanumeric characters, underscores, dots, or hyphens."
            )

        if password != confirm_password:
            return AuthResult(
                success=False,
                error_message="Passwords do not match."
            )

        is_valid_pwd, pwd_issues = validate_password_strength(password)
        if not is_valid_pwd:
            return AuthResult(
                success=False,
                error_message=" ".join(pwd_issues)
            )

        # Check existing user
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id FROM users WHERE username = ? COLLATE NOCASE", (cleaned_username,))
            if cursor.fetchone():
                return AuthResult(
                    success=False,
                    error_message=f"Username '{cleaned_username}' is already registered."
                )

        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Hash password
        pwd_hash, pwd_salt = hash_password(password)

        # 2. Derive KEK
        kek_salt = secrets.token_bytes(32).hex()
        kek = derive_kek(password, bytes.fromhex(kek_salt))

        # 3. Generate DEK & wrap with KEK
        dek = generate_dek()
        encrypted_dek, dek_nonce = wrap_dek(dek, kek)

        # 4. Insert user record
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO users (
                    username, password_hash, password_salt, kek_salt,
                    encrypted_dek, dek_nonce, failed_attempts, locked_until,
                    last_login, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, ?)
                """,
                (
                    cleaned_username, pwd_hash, pwd_salt, kek_salt,
                    encrypted_dek, dek_nonce, now_iso, now_iso, now_iso
                )
            )
            user_id = cursor.lastrowid

            cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
            user_row = cursor.fetchone()
            user = User.from_row(user_row)

        self.audit.log(
            action=AuditAction.LOGIN_SUCCESS,
            user_id=user.user_id,
            details="Account created and initial session initialized"
        )

        return AuthResult(success=True, user=user, dek=dek)

    def login(self, username: str, password: str) -> AuthResult:
        """
        Authenticates a user, tracks failed attempts, enforces temporary lockout,
        and unwraps the Data Encryption Key (DEK) into memory.
        """
        cleaned_username = username.strip()
        if not cleaned_username or not password:
            return AuthResult(
                success=False,
                error_message="Please enter both username and password."
            )

        now = datetime.now(timezone.utc)

        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (cleaned_username,))
            user_row = cursor.fetchone()

        if not user_row:
            # Generic error to prevent username enumeration
            self.audit.log(
                action=AuditAction.LOGIN_FAILED,
                details=f"Login attempt failed for non-existent or invalid user: {cleaned_username[:3]}***"
            )
            return AuthResult(
                success=False,
                error_message="Invalid username or password."
            )

        user = User.from_row(user_row)

        # Check Lockout status
        if user.locked_until:
            try:
                locked_until_dt = datetime.fromisoformat(user.locked_until)
                if locked_until_dt.tzinfo is None:
                    locked_until_dt = locked_until_dt.replace(tzinfo=timezone.utc)

                if now < locked_until_dt:
                    remaining_sec = int((locked_until_dt - now).total_seconds())
                    remaining_min = (remaining_sec // 60) + 1
                    self.audit.log(
                        action=AuditAction.LOGIN_FAILED,
                        user_id=user.user_id,
                        details=f"Login attempted while account locked ({remaining_sec}s remaining)"
                    )
                    return AuthResult(
                        success=False,
                        error_message=(
                            f"Account is temporarily locked due to multiple failed login attempts. "
                            f"Please try again in approximately {remaining_min} minute(s)."
                        ),
                        is_locked=True,
                        lockout_remaining_seconds=remaining_sec
                    )
                else:
                    # Lockout period expired: auto-reset
                    with self.db.get_connection() as conn:
                        conn.execute(
                            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE user_id = ?",
                            (user.user_id,)
                        )
                    user.failed_attempts = 0
                    user.locked_until = None
            except Exception as e:
                logger.error(f"Error parsing locked_until timestamp: {e}")

        # Verify password
        is_pwd_valid = verify_password(password, user.password_hash, user.password_salt)

        if not is_pwd_valid:
            new_failed = user.failed_attempts + 1
            if new_failed >= MAX_FAILED_ATTEMPTS:
                locked_until_iso = (now + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
                with self.db.get_connection() as conn:
                    conn.execute(
                        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE user_id = ?",
                        (new_failed, locked_until_iso, user.user_id)
                    )
                self.audit.log(
                    action=AuditAction.ACCOUNT_LOCKED,
                    user_id=user.user_id,
                    details=f"Account locked after {new_failed} consecutive failed login attempts"
                )
                return AuthResult(
                    success=False,
                    error_message=(
                        f"Account has been temporarily locked for {LOCKOUT_MINUTES} minutes "
                        f"due to {MAX_FAILED_ATTEMPTS} consecutive failed attempts."
                    ),
                    is_locked=True,
                    lockout_remaining_seconds=LOCKOUT_MINUTES * 60
                )
            else:
                with self.db.get_connection() as conn:
                    conn.execute(
                        "UPDATE users SET failed_attempts = ? WHERE user_id = ?",
                        (new_failed, user.user_id)
                    )
                remaining_attempts = MAX_FAILED_ATTEMPTS - new_failed
                self.audit.log(
                    action=AuditAction.LOGIN_FAILED,
                    user_id=user.user_id,
                    details=f"Failed login attempt ({new_failed}/{MAX_FAILED_ATTEMPTS})"
                )
                return AuthResult(
                    success=False,
                    error_message=(
                        f"Invalid username or password. "
                        f"You have {remaining_attempts} attempt(s) remaining before temporary lockout."
                    )
                )

        # Successful Login
        now_iso = now.isoformat()
        with self.db.get_connection() as conn:
            conn.execute(
                """
                UPDATE users
                SET failed_attempts = 0, locked_until = NULL, last_login = ?
                WHERE user_id = ?
                """,
                (now_iso, user.user_id)
            )

        # Derive KEK and unwrap DEK
        try:
            kek = derive_kek(password, bytes.fromhex(user.kek_salt))
            dek = unwrap_dek(user.encrypted_dek, user.dek_nonce, kek)
        except Exception as e:
            logger.critical(f"Failed to unwrap DEK for authenticated user {user.user_id}: {e}")
            return AuthResult(
                success=False,
                error_message="Security error: Unable to unlock encryption vault. Key material corrupted."
            )

        user.failed_attempts = 0
        user.locked_until = None
        user.last_login = now_iso

        self.audit.log(
            action=AuditAction.LOGIN_SUCCESS,
            user_id=user.user_id,
            details="User logged in successfully"
        )

        return AuthResult(success=True, user=user, dek=dek)

    def change_password(
        self,
        user_id: int,
        current_password: str,
        new_password: str,
        confirm_password: str
    ) -> AuthResult:
        """
        Changes user master password, re-wrapping the existing Data Encryption Key (DEK)
        with a freshly derived KEK. Stored documents and files do not need re-encryption.
        """
        if not current_password or not new_password:
            return AuthResult(success=False, error_message="All password fields are required.")

        if new_password != confirm_password:
            return AuthResult(success=False, error_message="New passwords do not match.")

        if current_password == new_password:
            return AuthResult(success=False, error_message="New password must be different from current password.")

        is_valid_pwd, issues = validate_password_strength(new_password)
        if not is_valid_pwd:
            return AuthResult(success=False, error_message=" ".join(issues))

        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()

        if not row:
            return AuthResult(success=False, error_message="User not found.")

        user = User.from_row(row)

        # Verify current password
        if not verify_password(current_password, user.password_hash, user.password_salt):
            self.audit.log(
                action=AuditAction.PASSWORD_CHANGED,
                user_id=user_id,
                details="Password change rejected: Incorrect current password provided"
            )
            return AuthResult(success=False, error_message="Current password is incorrect.")

        # Unwrap DEK with old KEK
        try:
            old_kek = derive_kek(current_password, bytes.fromhex(user.kek_salt))
            dek = unwrap_dek(user.encrypted_dek, user.dek_nonce, old_kek)
        except Exception as e:
            logger.error(f"Error unwrapping DEK during password change: {e}")
            return AuthResult(success=False, error_message="Failed to decrypt vault key.")

        # Generate new password hash and new KEK
        new_pwd_hash, new_pwd_salt = hash_password(new_password)
        new_kek_salt = secrets.token_bytes(32).hex()
        new_kek = derive_kek(new_password, bytes.fromhex(new_kek_salt))

        # Re-wrap DEK with new KEK
        new_encrypted_dek, new_dek_nonce = wrap_dek(dek, new_kek)
        now_iso = datetime.now(timezone.utc).isoformat()

        # Update users table
        with self.db.get_connection() as conn:
            conn.execute(
                """
                UPDATE users
                SET password_hash = ?, password_salt = ?, kek_salt = ?,
                    encrypted_dek = ?, dek_nonce = ?, updated_at = ?
                WHERE user_id = ?
                """,
                (
                    new_pwd_hash, new_pwd_salt, new_kek_salt,
                    new_encrypted_dek, new_dek_nonce, now_iso,
                    user_id
                )
            )

        self.audit.log(
            action=AuditAction.PASSWORD_CHANGED,
            user_id=user_id,
            details="User password changed successfully; vault key re-wrapped"
        )

        # Refresh user object
        user.password_hash = new_pwd_hash
        user.password_salt = new_pwd_salt
        user.kek_salt = new_kek_salt
        user.encrypted_dek = new_encrypted_dek
        user.dek_nonce = new_dek_nonce
        user.updated_at = now_iso

        return AuthResult(success=True, user=user, dek=dek)
