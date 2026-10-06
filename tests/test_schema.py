"""
Unit tests for SQLite schema, constraints, foreign keys, and indexes.
"""

import sqlite3
import pytest
from database.schema import verify_schema


def test_schema_initialization(memory_db):
    """Verifies that all required tables and columns are created."""
    with memory_db.get_connection() as conn:
        schema = verify_schema(conn)

    assert "users" in schema
    assert "documents" in schema
    assert "audit_logs" in schema

    # Verify users columns
    user_cols = schema["users"]
    expected_user_cols = [
        "user_id", "username", "password_hash", "password_salt",
        "kek_salt", "encrypted_dek", "dek_nonce", "failed_attempts",
        "locked_until", "last_login", "created_at", "updated_at"
    ]
    for col in expected_user_cols:
        assert col in user_cols, f"Missing column {col} in users table"

    # Verify documents columns
    doc_cols = schema["documents"]
    expected_doc_cols = [
        "document_id", "user_id", "document_type", "document_number",
        "document_number_nonce", "document_number_masked", "document_number_hash",
        "issue_date", "expiry_date", "reminder_date", "reminder_days",
        "file_reference", "file_original_name", "file_size", "file_mime_type",
        "created_at", "updated_at"
    ]
    for col in expected_doc_cols:
        assert col in doc_cols, f"Missing column {col} in documents table"

    # Verify audit_logs columns
    audit_cols = schema["audit_logs"]
    expected_audit_cols = ["log_id", "user_id", "action", "details", "timestamp"]
    for col in expected_audit_cols:
        assert col in audit_cols, f"Missing column {col} in audit_logs table"


def test_indexes_created(memory_db):
    """Verifies that expected indexes are created."""
    with memory_db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index';")
        indexes = [row[0] for row in cursor.fetchall()]

    assert "idx_users_username" in indexes
    assert "idx_documents_user_type" in indexes
    assert "idx_documents_user_hash" in indexes
    assert "idx_documents_expiry" in indexes
    assert "idx_documents_reminder" in indexes
    assert "idx_audit_user_time" in indexes
    assert "idx_audit_action" in indexes


def test_foreign_key_enforcement(memory_db, sample_passport_dict):
    """Verifies that foreign key violations raise sqlite3.IntegrityError."""
    with memory_db.get_connection() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            # Attempt to insert document for non-existent user_id 999
            conn.execute(
                """
                INSERT INTO documents (
                    user_id, document_type, document_number, document_number_nonce,
                    document_number_masked, document_number_hash, issue_date,
                    expiry_date, reminder_days, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    999,
                    sample_passport_dict["document_type"],
                    sample_passport_dict["document_number"],
                    sample_passport_dict["document_number_nonce"],
                    sample_passport_dict["document_number_masked"],
                    sample_passport_dict["document_number_hash"],
                    sample_passport_dict["issue_date"],
                    sample_passport_dict["expiry_date"],
                    sample_passport_dict["reminder_days"],
                    sample_passport_dict["created_at"],
                    sample_passport_dict["updated_at"]
                )
            )


def test_cascade_delete(memory_db, sample_user_dict, sample_passport_dict):
    """Verifies that deleting a user cascades and deletes their documents."""
    with memory_db.get_connection() as conn:
        cursor = conn.cursor()
        # 1. Insert user
        cursor.execute(
            """
            INSERT INTO users (
                username, password_hash, password_salt, kek_salt,
                encrypted_dek, dek_nonce, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sample_user_dict["username"],
                sample_user_dict["password_hash"],
                sample_user_dict["password_salt"],
                sample_user_dict["kek_salt"],
                sample_user_dict["encrypted_dek"],
                sample_user_dict["dek_nonce"],
                sample_user_dict["created_at"],
                sample_user_dict["updated_at"]
            )
        )
        user_id = cursor.lastrowid

        # 2. Insert document for user
        cursor.execute(
            """
            INSERT INTO documents (
                user_id, document_type, document_number, document_number_nonce,
                document_number_masked, document_number_hash, issue_date,
                expiry_date, reminder_days, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                sample_passport_dict["document_type"],
                sample_passport_dict["document_number"],
                sample_passport_dict["document_number_nonce"],
                sample_passport_dict["document_number_masked"],
                sample_passport_dict["document_number_hash"],
                sample_passport_dict["issue_date"],
                sample_passport_dict["expiry_date"],
                sample_passport_dict["reminder_days"],
                sample_passport_dict["created_at"],
                sample_passport_dict["updated_at"]
            )
        )

        # Confirm document exists
        cursor.execute("SELECT COUNT(*) FROM documents WHERE user_id = ?", (user_id,))
        assert cursor.fetchone()[0] == 1

        # 3. Delete user
        cursor.execute("DELETE FROM users WHERE user_id = ?", (user_id,))

        # 4. Verify document was cascade deleted
        cursor.execute("SELECT COUNT(*) FROM documents WHERE user_id = ?", (user_id,))
        assert cursor.fetchone()[0] == 0


def test_audit_logs_set_null_on_user_delete(memory_db, sample_user_dict):
    """Verifies that deleting a user sets audit_logs.user_id to NULL."""
    with memory_db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (
                username, password_hash, password_salt, kek_salt,
                encrypted_dek, dek_nonce, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sample_user_dict["username"],
                sample_user_dict["password_hash"],
                sample_user_dict["password_salt"],
                sample_user_dict["kek_salt"],
                sample_user_dict["encrypted_dek"],
                sample_user_dict["dek_nonce"],
                sample_user_dict["created_at"],
                sample_user_dict["updated_at"]
            )
        )
        user_id = cursor.lastrowid

        # Insert audit log
        cursor.execute(
            "INSERT INTO audit_logs (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)",
            (user_id, "LOGIN_SUCCESS", "User logged in", "2026-09-22T10:00:00Z")
        )
        log_id = cursor.lastrowid

        # Delete user
        cursor.execute("DELETE FROM users WHERE user_id = ?", (user_id,))

        # Check audit log still exists but user_id is NULL
        cursor.execute("SELECT user_id, action FROM audit_logs WHERE log_id = ?", (log_id,))
        row = cursor.fetchone()
        assert row is not None
        assert row[0] is None
        assert row[1] == "LOGIN_SUCCESS"


def test_document_type_check_constraint(memory_db, sample_user_dict, sample_passport_dict):
    """Verifies that invalid document types violate the CHECK constraint."""
    with memory_db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (
                username, password_hash, password_salt, kek_salt,
                encrypted_dek, dek_nonce, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sample_user_dict["username"],
                sample_user_dict["password_hash"],
                sample_user_dict["password_salt"],
                sample_user_dict["kek_salt"],
                sample_user_dict["encrypted_dek"],
                sample_user_dict["dek_nonce"],
                sample_user_dict["created_at"],
                sample_user_dict["updated_at"]
            )
        )
        user_id = cursor.lastrowid

        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO documents (
                    user_id, document_type, document_number, document_number_nonce,
                    document_number_masked, document_number_hash, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    "VoterID",  # Invalid type: must be Passport, Aadhaar, or PAN
                    "cipher",
                    "nonce",
                    "masked",
                    "hash_001",
                    "2026-09-22T10:00:00Z",
                    "2026-09-22T10:00:00Z"
                )
            )


def test_case_insensitive_unique_username(memory_db, sample_user_dict):
    """Verifies that username unique constraint is case-insensitive (COLLATE NOCASE)."""
    with memory_db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (
                username, password_hash, password_salt, kek_salt,
                encrypted_dek, dek_nonce, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "citizen_user",
                sample_user_dict["password_hash"],
                sample_user_dict["password_salt"],
                sample_user_dict["kek_salt"],
                sample_user_dict["encrypted_dek"],
                sample_user_dict["dek_nonce"],
                sample_user_dict["created_at"],
                sample_user_dict["updated_at"]
            )
        )

        with pytest.raises(sqlite3.IntegrityError):
            cursor.execute(
                """
                INSERT INTO users (
                    username, password_hash, password_salt, kek_salt,
                    encrypted_dek, dek_nonce, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "CITIZEN_USER",  # Duplicate due to COLLATE NOCASE
                    sample_user_dict["password_hash"],
                    sample_user_dict["password_salt"],
                    sample_user_dict["kek_salt"],
                    sample_user_dict["encrypted_dek"],
                    sample_user_dict["dek_nonce"],
                    sample_user_dict["created_at"],
                    sample_user_dict["updated_at"]
                )
            )
