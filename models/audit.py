"""
Audit log model and actions for Document Guardian.
Strict security rule: Never log passwords, raw document numbers, or encryption keys.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional
import sqlite3


class AuditAction(str, Enum):
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    LOGOUT = "LOGOUT"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    DOCUMENT_ADDED = "DOCUMENT_ADDED"
    DOCUMENT_UPDATED = "DOCUMENT_UPDATED"
    DOCUMENT_DELETED = "DOCUMENT_DELETED"
    FILE_UPLOADED = "FILE_UPLOADED"
    FILE_VIEWED = "FILE_VIEWED"
    FILE_DELETED = "FILE_DELETED"
    RECORDS_EXPORTED = "RECORDS_EXPORTED"
    SESSION_LOCKED = "SESSION_LOCKED"
    SESSION_UNLOCKED = "SESSION_UNLOCKED"


@dataclass
class AuditLog:
    log_id: Optional[int]
    user_id: Optional[int]
    action: str
    details: Optional[str]
    timestamp: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "AuditLog":
        """Instantiates AuditLog from SQLite Row."""
        return cls(
            log_id=row["log_id"],
            user_id=row["user_id"],
            action=row["action"],
            details=row["details"],
            timestamp=row["timestamp"]
        )

    def to_dict(self) -> dict:
        return {
            "log_id": self.log_id,
            "user_id": self.user_id,
            "action": self.action,
            "details": self.details,
            "timestamp": self.timestamp
        }
