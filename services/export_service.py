"""
CSV export service for Document Guardian.
Uses Python's standard csv module to export document metadata and statuses.
Prioritizes data security by exporting masked document numbers by default.
Audits all export operations.
"""

import csv
import os
import logging
from typing import Optional, List
from database.database import DatabaseManager, get_db
from models.document import Document
from models.audit import AuditAction
from services.document_service import DocumentService
from services.expiry_service import ExpiryService, DocumentExpiryInfo
from services.audit_service import AuditService

logger = logging.getLogger(__name__)

CSV_HEADERS = [
    "Document Type",
    "Document Number",
    "Issue Date",
    "Expiry Date",
    "Review Date",
    "Reminder Window (Days)",
    "Current Status",
    "Milestone / Days Remaining",
    "Supporting File Attachment",
    "Record Created Date",
    "Last Updated Date"
]


class ExportService:
    """Manages CSV record export and privacy sanitization."""

    def __init__(
        self,
        db: Optional[DatabaseManager] = None,
        document_service: Optional[DocumentService] = None,
        expiry_service: Optional[ExpiryService] = None,
        audit_service: Optional[AuditService] = None
    ):
        self.db = db or get_db()
        self.doc_service = document_service or DocumentService(self.db)
        self.expiry_service = expiry_service or ExpiryService(self.db, self.doc_service)
        self.audit = audit_service or AuditService(self.db)

    def export_documents_to_csv(
        self,
        user_id: int,
        destination_csv_path: str,
        include_decrypted_numbers: bool = False,
        dek: Optional[bytes] = None
    ) -> int:
        """
        Exports document records to a CSV file.
        Defaults to masked document numbers for privacy.
        Logs RECORDS_EXPORTED to the audit log.
        Returns the number of rows exported.
        """
        docs: List[Document] = self.doc_service.get_documents(user_id)

        # Ensure target directory exists
        os.makedirs(os.path.dirname(os.path.abspath(destination_csv_path)), exist_ok=True)

        rows = []
        for doc in docs:
            # Determine number representation
            if include_decrypted_numbers and dek:
                try:
                    doc_number_val = self.doc_service.decrypt_document_number(doc, dek)
                except Exception:
                    doc_number_val = doc.document_number_masked
            else:
                doc_number_val = doc.document_number_masked

            analysis: DocumentExpiryInfo = self.expiry_service.analyze_document(doc)

            row = [
                doc.document_type,
                doc_number_val,
                doc.issue_date or "N/A",
                doc.expiry_date or "N/A",
                doc.reminder_date or "N/A",
                doc.reminder_days,
                analysis.status.value,
                analysis.days_remaining_display,
                doc.file_original_name if doc.file_reference else "None",
                doc.created_at[:10] if doc.created_at else "N/A",
                doc.updated_at[:10] if doc.updated_at else "N/A"
            ]
            rows.append(row)

        with open(destination_csv_path, "w", newline="", encoding="utf-8-sig") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(CSV_HEADERS)
            writer.writerows(rows)

        # Audit the export action
        mode_str = "decrypted numbers" if include_decrypted_numbers else "masked numbers"
        self.audit.log(
            action=AuditAction.RECORDS_EXPORTED,
            user_id=user_id,
            details=f"Exported {len(rows)} records to CSV with {mode_str}"
        )
        logger.info(f"Exported {len(rows)} document records to {destination_csv_path}")
        return len(rows)
