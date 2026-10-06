"""
Expiry and review calculation engine for Document Guardian.
Calculates date differences dynamically without storing statuses permanently.
Enforces legal document constraints:
- Passport: Expiry date, issue date, reminder period.
- Aadhaar / PAN: Lifetime validity (no expiry date); optional review reminder dates.
"""

from dataclasses import dataclass
from datetime import date, datetime
from typing import Optional, List
from database.database import DatabaseManager, get_db
from models.document import Document, DocumentType, DocumentStatus
from services.document_service import DocumentService


@dataclass
class DocumentExpiryInfo:
    """Detailed calculation of document date difference, status, and urgency."""
    document: Document
    status: DocumentStatus
    relevant_date: Optional[str]
    relevant_date_label: str
    days_remaining: Optional[int]
    days_remaining_display: str
    urgency_rank: int  # 0: Expired, 1: Review Due, 2: Attention Required, 3: Valid


@dataclass
class DashboardSummary:
    """Aggregated document counts and priority items for the dashboard."""
    total_documents: int
    valid_count: int
    attention_count: int
    expired_count: int
    review_due_count: int
    attention_documents: List[DocumentExpiryInfo]


class ExpiryService:
    """Service to evaluate document dates, expiration, and review reminders."""

    def __init__(self, db: Optional[DatabaseManager] = None, document_service: Optional[DocumentService] = None):
        self.db = db or get_db()
        self.doc_service = document_service or DocumentService(self.db)

    def analyze_document(
        self,
        document: Document,
        reference_date: Optional[date] = None
    ) -> DocumentExpiryInfo:
        """
        Dynamically analyzes a document against a reference date (defaulting to today).
        Calculates exact days difference, human-friendly status text, and sorting priority.
        """
        today = reference_date or date.today()

        if document.document_type == DocumentType.PASSPORT:
            label = "Expiry Date"
            if not document.expiry_date:
                return DocumentExpiryInfo(
                    document=document,
                    status=DocumentStatus.ATTENTION_REQUIRED,
                    relevant_date=None,
                    relevant_date_label=label,
                    days_remaining=None,
                    days_remaining_display="Missing expiry date",
                    urgency_rank=2
                )

            try:
                exp_date = datetime.strptime(document.expiry_date, "%Y-%m-%d").date()
            except ValueError:
                return DocumentExpiryInfo(
                    document=document,
                    status=DocumentStatus.ATTENTION_REQUIRED,
                    relevant_date=document.expiry_date,
                    relevant_date_label=label,
                    days_remaining=None,
                    days_remaining_display="Invalid date format",
                    urgency_rank=2
                )

            diff_days = (exp_date - today).days

            if diff_days < 0:
                past_days = abs(diff_days)
                return DocumentExpiryInfo(
                    document=document,
                    status=DocumentStatus.EXPIRED,
                    relevant_date=document.expiry_date,
                    relevant_date_label=label,
                    days_remaining=diff_days,
                    days_remaining_display=f"Expired {past_days} day{'s' if past_days != 1 else ''} ago",
                    urgency_rank=0
                )
            elif diff_days == 0:
                return DocumentExpiryInfo(
                    document=document,
                    status=DocumentStatus.ATTENTION_REQUIRED,
                    relevant_date=document.expiry_date,
                    relevant_date_label=label,
                    days_remaining=0,
                    days_remaining_display="Expires today",
                    urgency_rank=2
                )
            elif diff_days <= document.reminder_days:
                return DocumentExpiryInfo(
                    document=document,
                    status=DocumentStatus.ATTENTION_REQUIRED,
                    relevant_date=document.expiry_date,
                    relevant_date_label=label,
                    days_remaining=diff_days,
                    days_remaining_display=f"Expiring in {diff_days} day{'s' if diff_days != 1 else ''}",
                    urgency_rank=2
                )
            else:
                return DocumentExpiryInfo(
                    document=document,
                    status=DocumentStatus.VALID,
                    relevant_date=document.expiry_date,
                    relevant_date_label=label,
                    days_remaining=diff_days,
                    days_remaining_display=f"Valid ({diff_days} days remaining)",
                    urgency_rank=3
                )

        elif document.document_type in (DocumentType.AADHAAR, DocumentType.PAN):
            # Strictly lifetime validity. Optional periodic review reminder date.
            label = "Review Date"
            if not document.reminder_date:
                return DocumentExpiryInfo(
                    document=document,
                    status=DocumentStatus.VALID,
                    relevant_date=None,
                    relevant_date_label=label,
                    days_remaining=None,
                    days_remaining_display="Lifetime Validity (No review scheduled)",
                    urgency_rank=4
                )

            try:
                rem_date = datetime.strptime(document.reminder_date, "%Y-%m-%d").date()
            except ValueError:
                return DocumentExpiryInfo(
                    document=document,
                    status=DocumentStatus.VALID,
                    relevant_date=document.reminder_date,
                    relevant_date_label=label,
                    days_remaining=None,
                    days_remaining_display="Invalid review date format",
                    urgency_rank=4
                )

            diff_days = (rem_date - today).days

            if diff_days < 0:
                overdue = abs(diff_days)
                return DocumentExpiryInfo(
                    document=document,
                    status=DocumentStatus.REVIEW_DUE,
                    relevant_date=document.reminder_date,
                    relevant_date_label=label,
                    days_remaining=diff_days,
                    days_remaining_display=f"Review overdue by {overdue} day{'s' if overdue != 1 else ''}",
                    urgency_rank=1
                )
            elif diff_days == 0:
                return DocumentExpiryInfo(
                    document=document,
                    status=DocumentStatus.REVIEW_DUE,
                    relevant_date=document.reminder_date,
                    relevant_date_label=label,
                    days_remaining=0,
                    days_remaining_display="Review due today",
                    urgency_rank=1
                )
            elif diff_days <= document.reminder_days:
                return DocumentExpiryInfo(
                    document=document,
                    status=DocumentStatus.ATTENTION_REQUIRED,
                    relevant_date=document.reminder_date,
                    relevant_date_label=label,
                    days_remaining=diff_days,
                    days_remaining_display=f"Review due in {diff_days} day{'s' if diff_days != 1 else ''}",
                    urgency_rank=2
                )
            else:
                return DocumentExpiryInfo(
                    document=document,
                    status=DocumentStatus.VALID,
                    relevant_date=document.reminder_date,
                    relevant_date_label=label,
                    days_remaining=diff_days,
                    days_remaining_display=f"Valid (Review in {diff_days} days)",
                    urgency_rank=3
                )

        # Fallback default
        return DocumentExpiryInfo(
            document=document,
            status=DocumentStatus.VALID,
            relevant_date=None,
            relevant_date_label="N/A",
            days_remaining=None,
            days_remaining_display="Valid",
            urgency_rank=3
        )

    def get_user_dashboard_summary(
        self,
        user_id: int,
        reference_date: Optional[date] = None
    ) -> DashboardSummary:
        """
        Computes dashboard totals and retrieves documents requiring attention,
        ordered by urgency (Expired -> Review Due -> Attention Required -> Valid).
        """
        all_docs = self.doc_service.get_documents(user_id)
        analyzed = [self.analyze_document(d, reference_date) for d in all_docs]

        valid_count = sum(1 for a in analyzed if a.status == DocumentStatus.VALID)
        attention_count = sum(1 for a in analyzed if a.status == DocumentStatus.ATTENTION_REQUIRED)
        expired_count = sum(1 for a in analyzed if a.status == DocumentStatus.EXPIRED)
        review_due_count = sum(1 for a in analyzed if a.status == DocumentStatus.REVIEW_DUE)

        # Items requiring attention or review or expired
        attention_items = [
            a for a in analyzed
            if a.status in (DocumentStatus.EXPIRED, DocumentStatus.REVIEW_DUE, DocumentStatus.ATTENTION_REQUIRED)
        ]

        # Sort priority: urgency rank first, then days remaining
        attention_items.sort(key=lambda x: (x.urgency_rank, x.days_remaining if x.days_remaining is not None else 9999))

        return DashboardSummary(
            total_documents=len(all_docs),
            valid_count=valid_count,
            attention_count=attention_count,
            expired_count=expired_count,
            review_due_count=review_due_count,
            attention_documents=attention_items
        )

    def get_reminders_list(
        self,
        user_id: int,
        reference_date: Optional[date] = None
    ) -> List[DocumentExpiryInfo]:
        """
        Retrieves all documents currently requiring user action:
        Expired, Review Due, or Attention Required.
        """
        summary = self.get_user_dashboard_summary(user_id, reference_date)
        return summary.attention_documents
