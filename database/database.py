"""
Thread-safe SQLite database connection manager for Document Guardian.
Enforces SQLite foreign key constraints, timeout, row factory, and transactions.
"""

import os
import sqlite3
import threading
from contextlib import contextmanager
from typing import Generator, Optional
from database.schema import init_database

DEFAULT_DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "storage")
DEFAULT_DB_PATH = os.path.join(DEFAULT_DB_DIR, "document_guardian.db")


class DatabaseManager:
    """Manages SQLite connections and schema initialization."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._is_memory = (db_path == ":memory:")
        self._shared_memory_conn: Optional[sqlite3.Connection] = None

        if not self._is_memory:
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)

    def _configure_connection(self, conn: sqlite3.Connection) -> sqlite3.Connection:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        return conn

    def get_raw_connection(self) -> sqlite3.Connection:
        """Returns a configured raw connection. If :memory:, reuses the shared connection."""
        if self._is_memory:
            with self._lock:
                if self._shared_memory_conn is None:
                    self._shared_memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
                    self._configure_connection(self._shared_memory_conn)
                    init_database(self._shared_memory_conn)
                return self._shared_memory_conn

        conn = sqlite3.connect(self.db_path, timeout=5.0)
        return self._configure_connection(conn)

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """
        Context manager for database connections.
        Automatically commits on successful block exit, rolls back on error,
        and cleans up connection.
        """
        if self._is_memory:
            conn = self.get_raw_connection()
            with self._lock:
                try:
                    yield conn
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise
        else:
            conn = self.get_raw_connection()
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def init_db(self) -> None:
        """Initializes tables and indexes."""
        with self.get_connection() as conn:
            init_database(conn)

    def close(self) -> None:
        """Closes shared connection if memory DB."""
        with self._lock:
            if self._shared_memory_conn is not None:
                try:
                    self._shared_memory_conn.close()
                except Exception:
                    pass
                self._shared_memory_conn = None


_db_instance: Optional[DatabaseManager] = None
_instance_lock = threading.Lock()


def get_db(db_path: Optional[str] = None) -> DatabaseManager:
    """Returns singleton DatabaseManager instance, or creates a new one if path is provided."""
    global _db_instance
    with _instance_lock:
        if db_path is not None:
            return DatabaseManager(db_path)
        if _db_instance is None:
            _db_instance = DatabaseManager(DEFAULT_DB_PATH)
            _db_instance.init_db()
        return _db_instance


def reset_db_instance() -> None:
    """Resets global DB instance (used in test teardown)."""
    global _db_instance
    with _instance_lock:
        if _db_instance is not None:
            _db_instance.close()
            _db_instance = None
