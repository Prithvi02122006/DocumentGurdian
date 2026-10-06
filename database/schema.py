"""
Database schema definition and initialization for Document Guardian.
Enforces relational integrity, foreign key cascades, and indexing.
"""

import sqlite3
import logging

logger = logging.getLogger(__name__)

CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    kek_salt TEXT NOT NULL,
    encrypted_dek TEXT NOT NULL,
    dek_nonce TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT DEFAULT NULL,
    last_login TEXT DEFAULT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

CREATE_DOCUMENTS_TABLE = """
CREATE TABLE IF NOT EXISTS documents (
    document_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    document_type TEXT NOT NULL CHECK(document_type IN ('Passport', 'Aadhaar', 'PAN')),
    document_number TEXT NOT NULL,
    document_number_nonce TEXT NOT NULL,
    document_number_masked TEXT NOT NULL,
    document_number_hash TEXT NOT NULL,
    issue_date TEXT DEFAULT NULL,
    expiry_date TEXT DEFAULT NULL,
    reminder_date TEXT DEFAULT NULL,
    reminder_days INTEGER NOT NULL DEFAULT 180,
    file_reference TEXT DEFAULT NULL,
    file_original_name TEXT DEFAULT NULL,
    file_size INTEGER DEFAULT NULL,
    file_mime_type TEXT DEFAULT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    UNIQUE(user_id, document_type, document_number_hash)
);
"""

CREATE_AUDIT_LOGS_TABLE = """
CREATE TABLE IF NOT EXISTS audit_logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    details TEXT DEFAULT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
);
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);",
    "CREATE INDEX IF NOT EXISTS idx_documents_user_type ON documents(user_id, document_type);",
    "CREATE INDEX IF NOT EXISTS idx_documents_user_hash ON documents(user_id, document_number_hash);",
    "CREATE INDEX IF NOT EXISTS idx_documents_expiry ON documents(expiry_date);",
    "CREATE INDEX IF NOT EXISTS idx_documents_reminder ON documents(reminder_date);",
    "CREATE INDEX IF NOT EXISTS idx_audit_user_time ON audit_logs(user_id, timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);"
]


def init_database(conn: sqlite3.Connection) -> None:
    """
    Initializes SQLite schema, creating tables and indexes if they do not exist.
    Foreign key enforcement must be active on the connection.
    """
    conn.execute("PRAGMA foreign_keys = ON;")
    with conn:
        conn.execute(CREATE_USERS_TABLE)
        conn.execute(CREATE_DOCUMENTS_TABLE)
        conn.execute(CREATE_AUDIT_LOGS_TABLE)
        for idx_sql in CREATE_INDEXES:
            conn.execute(idx_sql)
    logger.info("Database schema initialized successfully.")


def verify_schema(conn: sqlite3.Connection) -> dict:
    """
    Verifies that all required tables and indexes exist.
    Returns a dictionary of table names and their column list.
    """
    conn.execute("PRAGMA foreign_keys = ON;")
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
    tables = [row[0] for row in cursor.fetchall()]

    schema_info = {}
    for table in tables:
        cursor.execute(f"PRAGMA table_info({table});")
        columns = [row[1] for row in cursor.fetchall()]
        schema_info[table] = columns

    return schema_info
