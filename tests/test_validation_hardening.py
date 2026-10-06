"""
Comprehensive validation and error handling hardening test suite:
Calendar edge cases, boundary conditions, SQL injection resistance, and defensive error handling.
"""

from datetime import date, timedelta
import pytest
from services.document_service import validate_document_input, DocumentService
from security.authentication import AuthenticationService, validate_password_strength
from services.file_service import validate_file, FileService
from services.audit_service import AuditService
from models.document import DocumentType


def test_invalid_calendar_dates():
    """Verifies that invalid calendar dates (e.g. non-leap Feb 29, month 13) are rejected."""
    # 2026 is NOT a leap year: Feb 29 does not exist
    ok, issues = validate_document_input(
        DocumentType.PASSPORT, "A1234567",
        issue_date="2020-01-01",
        expiry_date="2026-02-29"
    )
    assert not ok
    assert any("valid calendar date" in i for i in issues)

    # Month 13 does not exist
    ok, issues = validate_document_input(
        DocumentType.PASSPORT, "A1234567",
        issue_date="2020-13-01",
        expiry_date="2030-01-01"
    )
    assert not ok
    assert any("valid calendar date" in i for i in issues)

    # Day 00 does not exist
    ok, issues = validate_document_input(
        DocumentType.PASSPORT, "A1234567",
        issue_date="2020-01-00",
        expiry_date="2030-01-01"
    )
    assert not ok
    assert any("valid calendar date" in i for i in issues)

    # Wrong format (slashes instead of dashes)
    ok, issues = validate_document_input(
        DocumentType.PASSPORT, "A1234567",
        issue_date="2020/01/01",
        expiry_date="2030/01/01"
    )
    assert not ok
    assert any("valid calendar date" in i for i in issues)


def test_passport_future_issue_date():
    """Verifies that a passport issue date in the future is rejected."""
    tomorrow = (date.today() + timedelta(days=1)).strftime("%Y-%m-%d")
    ten_years_later = (date.today() + timedelta(days=3650)).strftime("%Y-%m-%d")

    ok, issues = validate_document_input(
        DocumentType.PASSPORT, "A1234567",
        issue_date=tomorrow,
        expiry_date=ten_years_later
    )
    assert not ok
    assert any("cannot be in the future" in i for i in issues)


def test_aadhaar_validation_boundaries():
    """Verifies Aadhaar digit constraints, character filtering, and prohibition of expiry dates."""
    # Alphabetic character in Aadhaar
    ok, issues = validate_document_input(DocumentType.AADHAAR, "12345678901A")
    assert not ok
    assert any("12 numerical digits" in i for i in issues)

    # 11 digits (too short)
    ok, issues = validate_document_input(DocumentType.AADHAAR, "12345678901")
    assert not ok
    assert any("12 numerical digits" in i for i in issues)

    # 13 digits (too long)
    ok, issues = validate_document_input(DocumentType.AADHAAR, "1234567890123")
    assert not ok
    assert any("12 numerical digits" in i for i in issues)

    # Special characters
    ok, issues = validate_document_input(DocumentType.AADHAAR, "1234$678#9012")
    assert not ok

    # Attempt to assign an expiry date
    ok, issues = validate_document_input(
        DocumentType.AADHAAR, "123456789012",
        expiry_date="2030-01-01"
    )
    assert not ok
    assert any("does not expire" in i for i in issues)


def test_pan_validation_boundaries():
    """Verifies PAN 10-character structure and prohibition of expiry dates."""
    # Valid PAN in lower case -> normalized and accepted
    ok, _ = validate_document_input(DocumentType.PAN, "abcde1234f")
    assert ok

    # Invalid: 4 letters at start instead of 5
    ok, issues = validate_document_input(DocumentType.PAN, "ABCD12345F")
    assert not ok
    assert any("10 characters" in i for i in issues)

    # Invalid: 6 letters at start
    ok, issues = validate_document_input(DocumentType.PAN, "ABCDEF123F")
    assert not ok

    # Invalid: ends in digit instead of letter
    ok, issues = validate_document_input(DocumentType.PAN, "ABCDE12345")
    assert not ok

    # Attempt to assign an expiry date
    ok, issues = validate_document_input(DocumentType.PAN, "ABCDE1234F", expiry_date="2030-01-01")
    assert not ok
    assert any("does not expire" in i for i in issues)


def test_sql_injection_resistance_in_auth(memory_db):
    """Verifies that SQL injection attempts in username registration are safely rejected by input validation."""
    auth = AuthenticationService(memory_db)

    # Classic SQL injection payloads
    payloads = [
        "admin' OR '1'='1",
        "user'; DROP TABLE users; --",
        "admin'--",
        "'; EXEC sp_msforeachtable 'DROP TABLE ?' --",
        "\" OR \"\"=\""
    ]

    for p in payloads:
        res = auth.register(p, "ValidPassword#2026", "ValidPassword#2026")
        assert res.success is False
        assert "alphanumeric" in res.error_message.lower() or "characters" in res.error_message.lower()


def test_sql_injection_in_document_number(memory_db):
    """Verifies that SQL injection payloads in document numbers are rejected by validators."""
    audit = AuditService(memory_db)
    auth = AuthenticationService(memory_db, audit)
    reg = auth.register("sql_test_user", "ValidPassword#2026", "ValidPassword#2026")
    doc_service = DocumentService(memory_db, audit)

    # Aadhaar injection
    with pytest.raises(ValueError):
        doc_service.add_document(
            user_id=reg.user.user_id,
            dek=reg.dek,
            doc_type=DocumentType.AADHAAR,
            doc_number="1234'; DROP TABLE documents; --"
        )

    # Verify documents table still exists and is untouched
    docs = doc_service.get_documents(reg.user.user_id)
    assert len(docs) == 0


def test_file_validation_hardening():
    """Verifies defensive handling of non-existent files and directories."""
    ok, err, _, _ = validate_file("C:/non_existent_folder_xyz/missing_file.pdf")
    assert ok is False
    assert "does not exist" in err
