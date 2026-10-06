"""
Unit and integration tests for DocumentService:
Input validation, at-rest encryption, duplicate prevention, search, filter, and CRUD.
"""

import pytest
from services.document_service import DocumentService, validate_document_input
from security.authentication import AuthenticationService
from services.audit_service import AuditService
from models.document import DocumentType, DocumentStatus


@pytest.fixture
def auth_and_user(memory_db):
    """Sets up a registered user and returns (auth_service, doc_service, user, dek)."""
    audit = AuditService(memory_db)
    auth = AuthenticationService(memory_db, audit)
    reg_res = auth.register("doc_citizen", "DocMasterPass#2026", "DocMasterPass#2026")
    assert reg_res.success
    doc_service = DocumentService(memory_db, audit)
    return auth, doc_service, reg_res.user, reg_res.dek


def test_document_input_validation_rules():
    """Tests strict validation constraints across all document types."""
    # 1. Aadhaar: must be 12 digits, must NOT have expiry date
    ok, issues = validate_document_input(DocumentType.AADHAAR, "123456789012", expiry_date="2030-01-01")
    assert not ok
    assert any("does not expire" in i for i in issues)

    ok, issues = validate_document_input(DocumentType.AADHAAR, "12345")  # Too short
    assert not ok
    assert any("12 numerical digits" in i for i in issues)

    ok, issues = validate_document_input(DocumentType.AADHAAR, "1234 5678 9012")
    assert ok

    # 2. PAN: must be 10 alphanumeric (ABCDE1234F), must NOT have expiry date
    ok, issues = validate_document_input(DocumentType.PAN, "ABCDE1234F", expiry_date="2030-01-01")
    assert not ok
    assert any("does not expire" in i for i in issues)

    ok, issues = validate_document_input(DocumentType.PAN, "INVALID12")
    assert not ok
    assert any("10 characters long" in i for i in issues)

    ok, issues = validate_document_input(DocumentType.PAN, "ABCDE1234F")
    assert ok

    # 3. Passport: requires issue date and expiry date; expiry must be > issue
    ok, issues = validate_document_input(DocumentType.PASSPORT, "A1234567")
    assert not ok
    assert any("Issue date is required" in i for i in issues)
    assert any("Expiry date is required" in i for i in issues)

    ok, issues = validate_document_input(
        DocumentType.PASSPORT, "A1234567",
        issue_date="2025-01-01",
        expiry_date="2024-01-01"  # Invalid: expiry before issue
    )
    assert not ok
    assert any("strictly after" in i for i in issues)

    ok, issues = validate_document_input(
        DocumentType.PASSPORT, "A1234567",
        issue_date="2020-01-01",
        expiry_date="2030-01-01"
    )
    assert ok


def test_add_document_encryption_and_decryption(auth_and_user):
    """Verifies that document number is encrypted at rest and decrypts accurately."""
    _, doc_service, user, dek = auth_and_user

    doc = doc_service.add_document(
        user_id=user.user_id,
        dek=dek,
        doc_type=DocumentType.PASSPORT,
        doc_number="A7654321",
        issue_date="2020-05-10",
        expiry_date="2030-05-09",
        reminder_days=180
    )

    assert doc.document_id is not None
    assert doc.document_type == DocumentType.PASSPORT
    assert doc.document_number_masked.startswith("A")
    assert doc.document_number_masked.endswith("21")
    # Raw document number must NOT be plaintext
    assert "A7654321" not in doc.document_number

    # Authorized decryption with session DEK
    decrypted_num = doc_service.decrypt_document_number(doc, dek)
    assert decrypted_num == "A7654321"


def test_duplicate_document_prevention(auth_and_user):
    """Verifies that inserting the same document number twice for the same user is rejected."""
    _, doc_service, user, dek = auth_and_user

    # Add first Aadhaar
    doc_service.add_document(
        user_id=user.user_id,
        dek=dek,
        doc_type=DocumentType.AADHAAR,
        doc_number="987654321098"
    )

    # Attempt duplicate
    with pytest.raises(ValueError, match="already registered"):
        doc_service.add_document(
            user_id=user.user_id,
            dek=dek,
            doc_type=DocumentType.AADHAAR,
            doc_number="9876 5432 1098"  # Same number with spaces
        )


def test_search_and_filter_documents(auth_and_user):
    """Verifies querying documents with type filter, dynamic status filter, and text search."""
    _, doc_service, user, dek = auth_and_user

    # 1. Add Passport (Valid)
    doc_service.add_document(
        user_id=user.user_id,
        dek=dek,
        doc_type=DocumentType.PASSPORT,
        doc_number="K1122334",
        issue_date="2022-01-01",
        expiry_date="2032-01-01",
        file_original_name="passport_scan.pdf"
    )

    # 2. Add PAN
    doc_service.add_document(
        user_id=user.user_id,
        dek=dek,
        doc_type=DocumentType.PAN,
        doc_number="ABCDE9999Z",
        reminder_date="2027-10-01",
        file_original_name="pan_card.jpg"
    )

    # All documents
    all_docs = doc_service.get_documents(user.user_id)
    assert len(all_docs) == 2

    # Filter by type
    passports = doc_service.get_documents(user.user_id, doc_type=DocumentType.PASSPORT)
    assert len(passports) == 1
    assert passports[0].document_type == DocumentType.PASSPORT

    # Filter by dynamic status
    valid_docs = doc_service.get_documents(user.user_id, status_filter=DocumentStatus.VALID.value)
    assert len(valid_docs) == 2

    # Search by masked number substring
    search_num = doc_service.get_documents(user.user_id, search_query="9999")
    assert len(search_num) == 1
    assert search_num[0].document_type == DocumentType.PAN

    # Search by filename
    search_file = doc_service.get_documents(user.user_id, search_query="passport_scan")
    assert len(search_file) == 1


def test_update_and_delete_document(auth_and_user):
    """Verifies document update with re-encryption and document deletion."""
    _, doc_service, user, dek = auth_and_user

    # Add initial Aadhaar
    doc = doc_service.add_document(
        user_id=user.user_id,
        dek=dek,
        doc_type=DocumentType.AADHAAR,
        doc_number="111122223333"
    )

    # Update reminder date
    updated = doc_service.update_document(
        document_id=doc.document_id,
        user_id=user.user_id,
        dek=dek,
        doc_type=DocumentType.AADHAAR,
        reminder_date="2028-06-15",
        reminder_days=90
    )
    assert updated.reminder_date == "2028-06-15"
    assert updated.reminder_days == 90

    # Decrypt number to ensure it remained intact
    assert doc_service.decrypt_document_number(updated, dek) == "111122223333"

    # Delete document
    deleted = doc_service.delete_document(doc.document_id, user.user_id)
    assert deleted is True

    # Confirm deletion
    assert doc_service.get_document_by_id(doc.document_id, user.user_id) is None
