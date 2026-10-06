"""
Pytest configuration and shared fixtures for Document Guardian test suite.
"""

import os
import sys
import tempfile
import pytest

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from database.database import DatabaseManager
from database.schema import init_database


@pytest.fixture
def memory_db():
    """Provides a clean in-memory DatabaseManager initialized with schema."""
    db = DatabaseManager(":memory:")
    db.init_db()
    yield db
    db.close()


@pytest.fixture
def temp_disk_db():
    """Provides a temporary on-disk DatabaseManager to test file operations and persistence."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "test_guardian.db")
        db = DatabaseManager(db_path)
        db.init_db()
        yield db
        db.close()


@pytest.fixture
def sample_user_dict():
    """Fictional test user data."""
    return {
        "username": "citizen_user",
        "password_hash": "$argon2id$v=19$m=65536,t=3,p=4$fake_hash_value",
        "password_salt": "a1b2c3d4e5f607182930415263748596",
        "kek_salt": "96857463524130291807f6e5d4c3b2a1",
        "encrypted_dek": "bm9uY2VfZW5jcnlwdGVkX2Rla192YWx1ZQ==",
        "dek_nonce": "MTIzNDU2Nzg5MDEy",
        "failed_attempts": 0,
        "created_at": "2026-09-22T10:00:00Z",
        "updated_at": "2026-09-22T10:00:00Z"
    }


@pytest.fixture
def sample_passport_dict():
    """Fictional passport data."""
    return {
        "document_type": "Passport",
        "document_number": "enc_cipher_text_passport",
        "document_number_nonce": "passport_nonce_12",
        "document_number_masked": "X*****78",
        "document_number_hash": "sha256_mock_hash_pass_001",
        "issue_date": "2020-01-15",
        "expiry_date": "2030-01-14",
        "reminder_date": None,
        "reminder_days": 180,
        "created_at": "2026-09-22T10:00:00Z",
        "updated_at": "2026-09-22T10:00:00Z"
    }
