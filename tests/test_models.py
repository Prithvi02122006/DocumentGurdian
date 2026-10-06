"""
Unit tests for data models, masking logic, and dynamic status calculation.
"""

from datetime import date, timedelta
from models.user import User
from models.document import (
    Document, DocumentType, DocumentStatus,
    mask_document_number, calculate_status
)
from models.audit import AuditLog, AuditAction


def test_document_masking():
    """Verifies that sensitive document numbers are properly masked for the UI."""
    # Aadhaar: 12 digits
    assert mask_document_number(DocumentType.AADHAAR, "123456789012") == "XXXX XXXX 9012"
    assert mask_document_number(DocumentType.AADHAAR, "1234 5678 9012") == "XXXX XXXX 9012"

    # PAN: 10 characters (5 letters, 4 numbers, 1 letter)
    assert mask_document_number(DocumentType.PAN, "ABCDE1234F") == "XXXXX1234F"

    # Passport: 8 characters
    masked_passport = mask_document_number(DocumentType.PASSPORT, "A1234567")
    assert masked_passport.startswith("A")
    assert masked_passport.endswith("67")
    assert "*" in masked_passport


def test_passport_dynamic_status():
    """Verifies dynamic status calculation for Passport (has issue & expiry dates)."""
    today = date(2026, 9, 22)

    # 1. Past expiry date -> EXPIRED
    past_date = (today - timedelta(days=5)).strftime("%Y-%m-%d")
    status = calculate_status(
        doc_type=DocumentType.PASSPORT,
        expiry_date_str=past_date,
        reminder_days=180,
        reference_date=today
    )
    assert status == DocumentStatus.EXPIRED

    # 2. Expiry within 180 days -> ATTENTION_REQUIRED
    soon_date = (today + timedelta(days=90)).strftime("%Y-%m-%d")
    status = calculate_status(
        doc_type=DocumentType.PASSPORT,
        expiry_date_str=soon_date,
        reminder_days=180,
        reference_date=today
    )
    assert status == DocumentStatus.ATTENTION_REQUIRED

    # 3. Expiry far in future -> VALID
    future_date = (today + timedelta(days=400)).strftime("%Y-%m-%d")
    status = calculate_status(
        doc_type=DocumentType.PASSPORT,
        expiry_date_str=future_date,
        reminder_days=180,
        reference_date=today
    )
    assert status == DocumentStatus.VALID


def test_aadhaar_and_pan_no_invented_expiry():
    """Verifies Aadhaar and PAN do NOT have expiry dates, only optional review reminders."""
    today = date(2026, 9, 22)

    # Without reminder date -> Always VALID
    status_aadhaar = calculate_status(
        doc_type=DocumentType.AADHAAR,
        reminder_date_str=None,
        reference_date=today
    )
    assert status_aadhaar == DocumentStatus.VALID

    status_pan = calculate_status(
        doc_type=DocumentType.PAN,
        reminder_date_str=None,
        reference_date=today
    )
    assert status_pan == DocumentStatus.VALID

    # With past reminder date -> REVIEW_DUE
    past_reminder = (today - timedelta(days=10)).strftime("%Y-%m-%d")
    status_due = calculate_status(
        doc_type=DocumentType.AADHAAR,
        reminder_date_str=past_reminder,
        reminder_days=30,
        reference_date=today
    )
    assert status_due == DocumentStatus.REVIEW_DUE

    # With upcoming reminder date within window -> ATTENTION_REQUIRED
    upcoming_reminder = (today + timedelta(days=15)).strftime("%Y-%m-%d")
    status_soon = calculate_status(
        doc_type=DocumentType.PAN,
        reminder_date_str=upcoming_reminder,
        reminder_days=30,
        reference_date=today
    )
    assert status_soon == DocumentStatus.ATTENTION_REQUIRED


def test_audit_log_actions():
    """Verifies all specified audit actions exist."""
    actions = [a.value for a in AuditAction]
    assert "LOGIN_SUCCESS" in actions
    assert "LOGIN_FAILED" in actions
    assert "DOCUMENT_ADDED" in actions
    assert "DOCUMENT_UPDATED" in actions
    assert "DOCUMENT_DELETED" in actions
    assert "FILE_UPLOADED" in actions
    assert "FILE_VIEWED" in actions
    assert "PASSWORD_CHANGED" in actions
