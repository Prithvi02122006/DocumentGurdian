"""
Session management module for Document Guardian.
Handles active user state, Data Encryption Key (DEK) lifecycle,
inactivity timeouts, session locking/unlocking, and secure logout.
"""

import time
import threading
import logging
from typing import Optional, Callable, List
from models.user import User
from models.audit import AuditAction
from security.hashing import verify_password
from security.encryption import derive_kek, unwrap_dek
from services.audit_service import AuditService

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_MINUTES = 10


class SessionManager:
    """
    Manages in-memory authenticated session state, DEK security,
    and automatic inactivity locking.
    """

    def __init__(self, audit_service: Optional[AuditService] = None, default_timeout_minutes: int = DEFAULT_TIMEOUT_MINUTES):
        self.audit = audit_service
        self.timeout_minutes = default_timeout_minutes

        self._lock = threading.Lock()
        self._user: Optional[User] = None
        self._dek: Optional[bytes] = None
        self._is_authenticated: bool = False
        self._is_locked: bool = False
        self._last_activity: float = 0.0

        # Event callbacks
        self._on_lock_listeners: List[Callable[[], None]] = []
        self._on_unlock_listeners: List[Callable[[], None]] = []
        self._on_logout_listeners: List[Callable[[], None]] = []

    def start_session(self, user: User, dek: bytes, timeout_minutes: Optional[int] = None) -> None:
        """Starts an active, unlocked user session."""
        with self._lock:
            self._user = user
            self._dek = dek
            self._is_authenticated = True
            self._is_locked = False
            self._last_activity = time.monotonic()
            if timeout_minutes is not None:
                self.timeout_minutes = max(1, timeout_minutes)
        logger.info(f"Session started for user {user.username} (timeout: {self.timeout_minutes}m)")

    @property
    def is_authenticated(self) -> bool:
        with self._lock:
            return self._is_authenticated

    @property
    def is_locked(self) -> bool:
        with self._lock:
            return self._is_locked

    @property
    def current_user(self) -> Optional[User]:
        with self._lock:
            return self._user

    def get_dek(self) -> bytes:
        """
        Retrieves the Data Encryption Key.
        Raises PermissionError if session is not authenticated or is locked.
        """
        with self._lock:
            if not self._is_authenticated or self._user is None:
                raise PermissionError("No active authenticated session.")
            if self._is_locked or self._dek is None:
                raise PermissionError("Session is locked. Unlock with master password to access encryption keys.")
            return self._dek

    def record_activity(self) -> None:
        """Refreshes the inactivity countdown."""
        with self._lock:
            if self._is_authenticated and not self._is_locked:
                self._last_activity = time.monotonic()

    def check_inactivity(self) -> bool:
        """
        Checks if the session has exceeded the inactivity threshold.
        If timed out, locks the session and triggers listeners.
        Returns True if session is currently locked.
        """
        should_lock = False
        with self._lock:
            if self._is_authenticated and not self._is_locked:
                elapsed_seconds = time.monotonic() - self._last_activity
                if elapsed_seconds >= (self.timeout_minutes * 60):
                    should_lock = True

        if should_lock:
            self.lock_session(reason="Inactivity timeout")
            return True

        with self._lock:
            return self._is_locked

    def lock_session(self, reason: str = "Manual lock") -> None:
        """
        Locks the session, removing the DEK from active access
        while retaining the user context for the lock screen.
        """
        listeners_to_call = []
        with self._lock:
            if not self._is_authenticated or self._is_locked:
                return
            self._is_locked = True
            # Dereference DEK from active access
            self._dek = None
            listeners_to_call = list(self._on_lock_listeners)
            user_id = self._user.user_id if self._user else None

        if self.audit and user_id:
            self.audit.log(
                action=AuditAction.SESSION_LOCKED,
                user_id=user_id,
                details=f"Session locked: {reason}"
            )

        logger.info(f"Session locked ({reason}) for user {user_id}")
        for listener in listeners_to_call:
            try:
                listener()
            except Exception as e:
                logger.error(f"Error in on_lock listener: {e}")

    def unlock_session(self, password: str) -> bool:
        """
        Unlocks a locked session by verifying the master password
        and unwrapping the DEK.
        """
        with self._lock:
            if not self._is_authenticated or not self._is_locked or not self._user:
                return False
            user = self._user

        # Verify password
        if not verify_password(password, user.password_hash, user.password_salt):
            if self.audit:
                self.audit.log(
                    action=AuditAction.LOGIN_FAILED,
                    user_id=user.user_id,
                    details="Session unlock attempt failed: Invalid password"
                )
            return False

        # Unwrap DEK
        try:
            kek = derive_kek(password, bytes.fromhex(user.kek_salt))
            unwrapped_dek = unwrap_dek(user.encrypted_dek, user.dek_nonce, kek)
        except Exception as e:
            logger.critical(f"Failed to unwrap DEK during session unlock: {e}")
            return False

        listeners_to_call = []
        with self._lock:
            self._dek = unwrapped_dek
            self._is_locked = False
            self._last_activity = time.monotonic()
            listeners_to_call = list(self._on_unlock_listeners)

        if self.audit:
            self.audit.log(
                action=AuditAction.SESSION_UNLOCKED,
                user_id=user.user_id,
                details="Session unlocked successfully"
            )

        for listener in listeners_to_call:
            try:
                listener()
            except Exception as e:
                logger.error(f"Error in on_unlock listener: {e}")

        return True

    def logout(self) -> None:
        """
        Completely terminates the authenticated session,
        wipes keys, resets user state, and logs the event.
        """
        listeners_to_call = []
        user_id = None
        with self._lock:
            if not self._is_authenticated:
                return
            user_id = self._user.user_id if self._user else None
            self._user = None
            self._dek = None
            self._is_authenticated = False
            self._is_locked = False
            self._last_activity = 0.0
            listeners_to_call = list(self._on_logout_listeners)

        if self.audit and user_id:
            self.audit.log(
                action=AuditAction.LOGOUT,
                user_id=user_id,
                details="User logged out securely"
            )

        logger.info(f"User {user_id} logged out. Session destroyed.")
        for listener in listeners_to_call:
            try:
                listener()
            except Exception as e:
                logger.error(f"Error in on_logout listener: {e}")

    def add_on_lock_listener(self, callback: Callable[[], None]) -> None:
        self._on_lock_listeners.append(callback)

    def add_on_unlock_listener(self, callback: Callable[[], None]) -> None:
        self._on_unlock_listeners.append(callback)

    def add_on_logout_listener(self, callback: Callable[[], None]) -> None:
        self._on_logout_listeners.append(callback)


_global_session: Optional[SessionManager] = None
_session_lock = threading.Lock()


def get_session(audit_service: Optional[AuditService] = None) -> SessionManager:
    """Returns singleton SessionManager instance."""
    global _global_session
    with _session_lock:
        if _global_session is None:
            _global_session = SessionManager(audit_service=audit_service)
        elif audit_service and _global_session.audit is None:
            _global_session.audit = audit_service
        return _global_session


def reset_session() -> None:
    """Resets global session for testing."""
    global _global_session
    with _session_lock:
        if _global_session:
            _global_session.logout()
        _global_session = None
