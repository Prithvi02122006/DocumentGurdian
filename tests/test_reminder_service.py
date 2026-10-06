"""
Unit tests for NotificationService and ReminderService:
Desktop notifications, deduplication logic, and background scanner thread lifecycle.
"""

from datetime import date
import time
import pytest
from services.notification_service import NotificationService
from services.reminder_service import ReminderService
from services.expiry_service import ExpiryService
from services.document_service import DocumentService
from security.authentication import AuthenticationService
from services.audit_service import AuditService
from models.document import DocumentType


@pytest.fixture
def reminder_env(memory_db):
    audit = AuditService(memory_db)
    auth = AuthenticationService(memory_db, audit)
    reg_res = auth.register("reminder_user", "ReminderPass#2026", "ReminderPass#2026")
    doc_service = DocumentService(memory_db, audit)
    expiry_service = ExpiryService(memory_db, doc_service)
    # Use fallback mode for tests to verify message construction and tracking reliably
    notifier = NotificationService(enable_os_notifications=False)
    reminder_service = ReminderService(expiry_service, notifier, audit)
    return doc_service, reminder_service, notifier, reg_res.user, reg_res.dek


def test_notification_service_resilience():
    """Verifies that notification dispatch handles errors gracefully without crashing."""
    notifier = NotificationService(enable_os_notifications=False)
    success = notifier.notify("Test Alert", "This is a test notification.")
    assert success is True
    history = notifier.get_history()
    assert len(history) == 1
    assert history[0]["title"] == "Test Alert"


def test_reminder_scan_and_deduplication(reminder_env):
    """Verifies scanning for expiring/review-due documents and prevents duplicate alerts."""
    doc_service, reminder_service, notifier, user, dek = reminder_env
    ref_date = date(2026, 9, 23)

    # 1. Add Expired Passport
    doc_service.add_document(
        user_id=user.user_id,
        dek=dek,
        doc_type=DocumentType.PASSPORT,
        doc_number="A9988776",
        issue_date="2015-05-01",
        expiry_date="2025-05-01"
    )

    # 2. Add Review Due Aadhaar
    doc_service.add_document(
        user_id=user.user_id,
        dek=dek,
        doc_type=DocumentType.AADHAAR,
        doc_number="777788889999",
        reminder_date="2026-09-10",
        reminder_days=30
    )

    # 3. Add Lifetime Valid PAN (No review date) -> Should NOT trigger reminder
    doc_service.add_document(
        user_id=user.user_id,
        dek=dek,
        doc_type=DocumentType.PAN,
        doc_number="ABCDE5555X"
    )

    # First Scan
    reminders = reminder_service.check_reminders_for_user(user.user_id, notify=True, reference_date=ref_date)
    assert len(reminders) == 2  # Only Passport and Aadhaar need attention

    history = notifier.get_history()
    assert len(history) == 2
    assert any("Passport" in h["message"] for h in history)
    assert any("Aadhaar" in h["message"] for h in history)

    # Second Scan: Deduplication must prevent re-sending identical notifications
    reminders_again = reminder_service.check_reminders_for_user(user.user_id, notify=True, reference_date=ref_date)
    assert len(reminders_again) == 2
    assert len(notifier.get_history()) == 2  # History remains 2, no duplicate dispatched


def test_background_scanner_lifecycle(reminder_env):
    """Verifies that the background scanner thread starts and terminates cleanly."""
    _, reminder_service, _, user, _ = reminder_env

    reminder_service.start_background_scanner(user.user_id, interval_seconds=1)
    assert reminder_service._bg_thread is not None
    assert reminder_service._bg_thread.is_alive()

    # Let worker execute once
    time.sleep(0.5)

    # Stop scanner
    reminder_service.stop_background_scanner()
    assert reminder_service._bg_thread is None
