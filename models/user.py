"""
User entity model for Document Guardian.
"""

from dataclasses import dataclass
from typing import Optional
import sqlite3


@dataclass
class User:
    user_id: Optional[int]
    username: str
    password_hash: str
    password_salt: str
    kek_salt: str
    encrypted_dek: str
    dek_nonce: str
    failed_attempts: int = 0
    locked_until: Optional[str] = None
    last_login: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "User":
        """Instantiates a User from an SQLite Row."""
        return cls(
            user_id=row["user_id"],
            username=row["username"],
            password_hash=row["password_hash"],
            password_salt=row["password_salt"],
            kek_salt=row["kek_salt"],
            encrypted_dek=row["encrypted_dek"],
            dek_nonce=row["dek_nonce"],
            failed_attempts=row["failed_attempts"],
            locked_until=row["locked_until"],
            last_login=row["last_login"],
            created_at=row["created_at"],
            updated_at=row["updated_at"]
        )

    def to_dict(self) -> dict:
        """Serializes user fields for safe internal representation (excluding raw hash/salt where needed)."""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "failed_attempts": self.failed_attempts,
            "locked_until": self.locked_until,
            "last_login": self.last_login,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }
