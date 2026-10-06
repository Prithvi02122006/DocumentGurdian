"""
Unit tests for DatabaseManager connection handling, transactions, and pragma configuration.
"""

import sqlite3
import pytest
from database.database import DatabaseManager


def test_pragma_foreign_keys_always_on(memory_db, temp_disk_db):
    """Verifies that foreign_keys pragma is enabled on all connections."""
    for db in (memory_db, temp_disk_db):
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_keys;")
            fk_state = cursor.fetchone()[0]
            assert fk_state == 1, "Foreign keys must be enabled (1)"


def test_transaction_rollback_on_error(temp_disk_db, sample_user_dict):
    """Verifies that an exception inside get_connection context rolls back uncommitted writes."""
    with pytest.raises(ValueError):
        with temp_disk_db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO users (
                    username, password_hash, password_salt, kek_salt,
                    encrypted_dek, dek_nonce, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "rollback_user",
                    sample_user_dict["password_hash"],
                    sample_user_dict["password_salt"],
                    sample_user_dict["kek_salt"],
                    sample_user_dict["encrypted_dek"],
                    sample_user_dict["dek_nonce"],
                    sample_user_dict["created_at"],
                    sample_user_dict["updated_at"]
                )
            )
            raise ValueError("Intentional error to trigger rollback")

    # Verify user was NOT inserted
    with temp_disk_db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'rollback_user';")
        count = cursor.fetchone()[0]
        assert count == 0


def test_transaction_commit_on_success(temp_disk_db, sample_user_dict):
    """Verifies that clean exit from get_connection context automatically commits writes."""
    with temp_disk_db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO users (
                username, password_hash, password_salt, kek_salt,
                encrypted_dek, dek_nonce, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "committed_user",
                sample_user_dict["password_hash"],
                sample_user_dict["password_salt"],
                sample_user_dict["kek_salt"],
                sample_user_dict["encrypted_dek"],
                sample_user_dict["dek_nonce"],
                sample_user_dict["created_at"],
                sample_user_dict["updated_at"]
            )
        )

    # Verify user was committed
    with temp_disk_db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'committed_user';")
        count = cursor.fetchone()[0]
        assert count == 1
