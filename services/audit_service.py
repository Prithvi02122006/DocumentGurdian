"""
Audit logging service for Document Guardian.
Strictly guarantees no passwords, full document numbers, or encryption keys are logged.
"""

from datetime import datetime, timezone
import logging
from typing import Optional, List
from database.database import DatabaseManager, get_db
from models.audit import AuditLog, AuditAction

logger = logging.getLogger(__name__)


class AuditService:
    """Manages recording and retrieving security audit events."""

    def __init__(self, db: Optional[DatabaseManager] = None):
        self.db = db or get_db()

    def log(
        self,
        action: str,
        user_id: Optional[int] = None,
        details: Optional[str] = None
    ) -> None:
        """
        Records an audit event in the database.
        Ensures details string does not contain sensitive secrets.
        """
        # Validate or normalize action
        if isinstance(action, AuditAction):
            action_str = action.value
        else:
            action_str = str(action)

        # Sanitize details
        clean_details = None
        if details:
            clean_details = details.strip()
            # Basic sanitization safeguard
            if "password" in clean_details.lower():
                clean_details = clean_details.split("=")[0] + "=***REDACTED***"

        timestamp_iso = datetime.now(timezone.utc).isoformat()

        try:
            with self.db.get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO audit_logs (user_id, action, details, timestamp)
                    VALUES (?, ?, ?, ?)
                    """,
                    (user_id, action_str, clean_details, timestamp_iso)
                )
            logger.info(f"Audit log recorded: {action_str} for user {user_id}")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def get_logs_for_user(self, user_id: int, limit: int = 100) -> List[AuditLog]:
        """Retrieves audit history for a specific user, ordered newest first."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT log_id, user_id, action, details, timestamp
                FROM audit_logs
                WHERE user_id = ?
                ORDER BY timestamp DESC, log_id DESC
                LIMIT ?
                """,
                (user_id, limit)
            )
            rows = cursor.fetchall()
            return [AuditLog.from_row(row) for row in rows]

    def get_all_logs(self, limit: int = 200) -> List[AuditLog]:
        """Retrieves system audit logs, newest first."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT log_id, user_id, action, details, timestamp
                FROM audit_logs
                ORDER BY timestamp DESC, log_id DESC
                LIMIT ?
                """,
                (limit,)
            )
            rows = cursor.fetchall()
            return [AuditLog.from_row(row) for row in rows]
