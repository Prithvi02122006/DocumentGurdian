"""
Unit tests for ExpiryService:
Date difference calculations, document analysis, dashboard aggregation, and reminder lists.
"""

from datetime import date
import pytest
from services.expiry_service import ExpiryService
from services.document_service import DocumentService
from security.authentication import AuthenticationService
from services.audit_service import AuditService
from models.document import DocumentType, DocumentStatus


@pytest.fixture
def service_env(memory_db):
    audit = AuditService(memory_db)
    auth = AuthenticationService(memory_db, audit)
    reg_res = auth.register("expiry_tester", "ExpiryPass#2026", "ExpiryPass#2026")
    doc_service = DocumentService(memory_db, audit)
    expiry_service = ExpiryService(memory_db, doc_service)
    return auth, doc_service, expiry_service, reg_res.user, reg_res.dek


def test_passport_expiry_analysis(service_env):
    """Verifies detailed date difference and status text for Passport."""
    _, doc_service, expiry_service, user, dek = service_env
    ref_date = date(2026, 9, 23)

    # 1. Expired passport (expired 10 days ago)
    doc_expired = doc_service.add_document(
        user_id=user.user_id,
        dek=dek,
        doc_type=DocumentType.PASSPORT,
        doc_number="A1000001",
        issue_date="2016-09-13",
        expiry_date="2026-09-13"
    )
    info_exp = expiry_service.analyze_document(doc_expired, reference_date=ref_date)
    assert info_exp.status == DocumentStatus.EXPIRED
    assert info_exp.days_remaining == -10
    assert "Expired 10 days ago" in info_exp.days_remaining_display
    assert info_exp.urgency_rank == 0

    # 2. Expiring soon (expires in 45 days, reminder period 180)
    doc_soon = doc_service.add_document(
        user_id=user.user_id,
        dek=dek,
        doc_type=DocumentType.PASSPORT,
        doc_number="B2000002",
        issue_date="2016-11-07",
        expiry_date="2026-11-07",
        reminder_days=180
    )
    info_soon = expiry_service.analyze_document(doc_soon, reference_date=ref_date)
    assert info_soon.status == DocumentStatus.ATTENTION_REQUIRED
    assert info_soon.days_remaining == 45
    assert "Expiring in 45 days" in info_soon.days_remaining_display
    assert info_soon.urgency_rank == 2

    # 3. Valid passport (expires in 500 days)
    doc_valid = doc_service.add_document(
        user_id=user.user_id,
        dek=dek,
        doc_type=DocumentType.PASSPORT,
        doc_number="C3000003",
        issue_date="2024-01-01",
        expiry_date="2034-01-01",
        reminder_days=180
    )
    info_valid = expiry_service.analyze_document(doc_valid, reference_date=ref_date)
    assert info_valid.status == DocumentStatus.VALID
    assert info_valid.days_remaining > 180
    assert "Valid" in info_valid.days_remaining_display
    assert info_valid.urgency_rank == 3


def test_aadhaar_pan_review_analysis(service_env):
    """Verifies Aadhaar and PAN have lifetime validity with optional review reminders."""
    _, doc_service, expiry_service, user, dek = service_env
    ref_date = date(2026, 9, 23)

    # 1. Aadhaar without review date -> Lifetime Validity
    doc_aadhaar = doc_service.add_document(
        user_id=user.user_id,
        dek=dek,
        doc_type=DocumentType.AADHAAR,
        doc_number="123456789012"
    )
    info_aadhaar = expiry_service.analyze_document(doc_aadhaar, reference_date=ref_date)
    assert info_aadhaar.status == DocumentStatus.VALID
    assert info_aadhaar.days_remaining is None
    assert "Lifetime Validity" in info_aadhaar.days_remaining_display

    # 2. PAN with overdue review date
    doc_pan_due = doc_service.add_document(
        user_id=user.user_id,
        dek=dek,
        doc_type=DocumentType.PAN,
        doc_number="ABCDE1111A",
        reminder_date="2026-09-20",
        reminder_days=30
    )
    info_pan = expiry_service.analyze_document(doc_pan_due, reference_date=ref_date)
    assert info_pan.status == DocumentStatus.REVIEW_DUE
    assert info_pan.days_remaining == -3
    assert "Review overdue by 3 days" in info_pan.days_remaining_display
    assert info_pan.urgency_rank == 1


def test_dashboard_summary_and_sorting(service_env):
    """Verifies aggregated metrics and urgency-based sorting on dashboard."""
    _, doc_service, expiry_service, user, dek = service_env
    ref_date = date(2026, 9, 23)

    # Insert 1 Expired Passport
    doc_service.add_document(
        user_id=user.user_id,
        dek=dek,
        doc_type=DocumentType.PASSPORT,
        doc_number="P1111111",
        issue_date="2015-01-01",
        expiry_date="2025-01-01"
    )

    # Insert 1 Review Due Aadhaar
    doc_service.add_document(
        user_id=user.user_id,
        dek=dek,
        doc_type=DocumentType.AADHAAR,
        doc_number="222233334444",
        reminder_date="2026-09-01",
        reminder_days=30
    )

    # Insert 1 Expiring Soon Passport (in 30 days)
    doc_service.add_document(
        user_id=user.user_id,
        dek=dek,
        doc_type=DocumentType.PASSPORT,
        doc_number="P2222222",
        issue_date="2016-10-23",
        expiry_date="2026-10-23",
        reminder_days=90
    )

    # Insert 1 Valid PAN
    doc_service.add_document(
        user_id=user.user_id,
        dek=dek,
        doc_type=DocumentType.PAN,
        doc_number="ZZZZZ9999Z"
    )

    summary = expiry_service.get_user_dashboard_summary(user.user_id, reference_date=ref_date)

    assert summary.total_documents == 4
    assert summary.expired_count == 1
    assert summary.review_due_count == 1
    assert summary.attention_count == 1
    assert summary.valid_count == 1

    # Verify attention items are ordered: Expired (rank 0) -> Review Due (rank 1) -> Attention Required (rank 2)
    assert len(summary.attention_documents) == 3
    assert summary.attention_documents[0].status == DocumentStatus.EXPIRED
    assert summary.attention_documents[1].status == DocumentStatus.REVIEW_DUE
    assert summary.attention_documents[2].status == DocumentStatus.ATTENTION_REQUIRED
