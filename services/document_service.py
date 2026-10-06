"""
Document management service for Document Guardian.
Handles document validation, encryption at rest, CRUD operations,
search, filtering, and audit logging.
Strict rule: No invented expiry dates for Aadhaar or PAN.
"""

from datetime import datetime, date, timezone
import re
import logging
from typing import Optional, List, Tuple
from database.database import DatabaseManager, get_db
from models.document import (
    Document, DocumentType, DocumentStatus,
    mask_document_number, calculate_status
)
from models.audit import AuditAction
from security.encryption import (
    encrypt_string, decrypt_string, generate_document_hash
)
from services.audit_service import AuditService

logger = logging.getLogger(__name__)

# Validation Regex patterns
PAN_REGEX = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]{1}$")
PASSPORT_REGEX = re.compile(r"^[A-PR-WYa-pr-wy][0-9]{7}$")  # Standard Indian passport (1 letter + 7 digits, Q/X/Z excluded)


def validate_document_input(
    doc_type: str,
    doc_number: str,
    issue_date: Optional[str] = None,
    expiry_date: Optional[str] = None,
    reminder_date: Optional[str] = None,
    reminder_days: int = 180
) -> Tuple[bool, List[str]]:
    """
    Validates document input according to strict public-service rules:
    - Aadhaar: Exactly 12 digits. NO expiry date allowed.
    - PAN: Exactly 10 chars (5 letters, 4 numbers, 1 letter). NO expiry date allowed.
    - Passport: 1 letter + 7 digits. Issue date & Expiry date required. Expiry > Issue.
    """
    issues = []

    if doc_type not in (DocumentType.PASSPORT, DocumentType.AADHAAR, DocumentType.PAN):
        issues.append(f"Invalid document type: {doc_type}. Must be Passport, Aadhaar, or PAN.")

    cleaned_number = doc_number.strip().replace(" ", "").replace("-", "")
    if not cleaned_number:
        issues.append("Document number is required.")

    # 1. Document type specific checks
    if doc_type == DocumentType.AADHAAR:
        if not (len(cleaned_number) == 12 and cleaned_number.isdigit()):
            issues.append("Aadhaar number must contain exactly 12 numerical digits.")
        if expiry_date:
            issues.append("Aadhaar does not expire. Please do not set an expiry date (use review reminder if needed).")

    elif doc_type == DocumentType.PAN:
        if not PAN_REGEX.match(cleaned_number.upper()):
            issues.append("PAN must be 10 characters long (e.g. ABCDE1234F: 5 letters, 4 digits, 1 letter).")
        if expiry_date:
            issues.append("PAN does not expire. Please do not set an expiry date (use review reminder if needed).")

    elif doc_type == DocumentType.PASSPORT:
        if not (PASSPORT_REGEX.match(cleaned_number.upper()) or (len(cleaned_number) in (8, 9) and cleaned_number.isalnum())):
            issues.append("Passport number must follow standard passport format (e.g. A1234567: 1 letter followed by 7 digits).")

        if not issue_date:
            issues.append("Issue date is required for Passport.")
        if not expiry_date:
            issues.append("Expiry date is required for Passport.")

    if len(doc_number) > 100:
        issues.append("Document number exceeds maximum permitted length of 100 characters.")

    # 2. Date validations
    today = date.today()
    issue_dt = None
    if issue_date:
        try:
            issue_dt = datetime.strptime(issue_date, "%Y-%m-%d").date()
            if issue_dt > today:
                issues.append("Issue date cannot be in the future.")
            if issue_dt.year < 1900 or issue_dt.year > 2100:
                issues.append("Issue date year is out of valid range (1900-2100).")
        except ValueError:
            issues.append("Issue date must be a valid calendar date in YYYY-MM-DD format.")

    expiry_dt = None
    if expiry_date:
        try:
            expiry_dt = datetime.strptime(expiry_date, "%Y-%m-%d").date()
            if expiry_dt.year < 1900 or expiry_dt.year > 2150:
                issues.append("Expiry date year is out of valid range (1900-2150).")
        except ValueError:
            issues.append("Expiry date must be a valid calendar date in YYYY-MM-DD format.")

    if issue_dt and expiry_dt:
        if expiry_dt <= issue_dt:
            issues.append("Passport expiry date must be strictly after the issue date.")

    if reminder_date:
        try:
            rem_dt = datetime.strptime(reminder_date, "%Y-%m-%d").date()
            if rem_dt.year < 1900 or rem_dt.year > 2150:
                issues.append("Reminder date year is out of valid range (1900-2150).")
        except ValueError:
            issues.append("Reminder date must be a valid calendar date in YYYY-MM-DD format.")

    if reminder_days <= 0 or reminder_days > 730:
        issues.append("Reminder period must be between 1 and 730 days.")

    return (len(issues) == 0, issues)


class DocumentService:
    """Manages document CRUD operations with at-rest encryption and audit logging."""

    def __init__(self, db: Optional[DatabaseManager] = None, audit_service: Optional[AuditService] = None):
        self.db = db or get_db()
        self.audit = audit_service or AuditService(self.db)

    def _get_user_salt(self, user_id: int) -> str:
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT kek_salt FROM users WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"User {user_id} not found.")
            return row["kek_salt"]

    def add_document(
        self,
        user_id: int,
        dek: bytes,
        doc_type: str,
        doc_number: str,
        issue_date: Optional[str] = None,
        expiry_date: Optional[str] = None,
        reminder_date: Optional[str] = None,
        reminder_days: int = 180,
        file_reference: Optional[str] = None,
        file_original_name: Optional[str] = None,
        file_size: Optional[int] = None,
        file_mime_type: Optional[str] = None
    ) -> Document:
        """
        Validates input, encrypts document number with DEK,
        computes masked number & duplicate HMAC hash, inserts record, and audits.
        """
        # Validate inputs
        is_valid, issues = validate_document_input(
            doc_type=doc_type,
            doc_number=doc_number,
            issue_date=issue_date,
            expiry_date=expiry_date,
            reminder_date=reminder_date,
            reminder_days=reminder_days
        )
        if not is_valid:
            raise ValueError("Validation failed: " + " ".join(issues))

        user_salt = self._get_user_salt(user_id)
        number_hash = generate_document_hash(doc_number, user_salt)

        # Check duplicate
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT document_id FROM documents
                WHERE user_id = ? AND document_type = ? AND document_number_hash = ?
                """,
                (user_id, doc_type, number_hash)
            )
            if cursor.fetchone():
                raise ValueError(f"A {doc_type} with this document number is already registered in your vault.")

        # Encrypt document number
        cipher_b64, nonce_b64 = encrypt_string(doc_number.strip(), dek)
        masked_number = mask_document_number(doc_type, doc_number)
        now_iso = datetime.now(timezone.utc).isoformat()

        # Insert record
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO documents (
                    user_id, document_type, document_number, document_number_nonce,
                    document_number_masked, document_number_hash, issue_date,
                    expiry_date, reminder_date, reminder_days, file_reference,
                    file_original_name, file_size, file_mime_type, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id, doc_type, cipher_b64, nonce_b64,
                    masked_number, number_hash, issue_date,
                    expiry_date, reminder_date, reminder_days, file_reference,
                    file_original_name, file_size, file_mime_type, now_iso, now_iso
                )
            )
            doc_id = cursor.lastrowid
            cursor.execute("SELECT * FROM documents WHERE document_id = ?", (doc_id,))
            row = cursor.fetchone()
            document = Document.from_row(row)

        self.audit.log(
            action=AuditAction.DOCUMENT_ADDED,
            user_id=user_id,
            details=f"Added {doc_type} ({masked_number})"
        )

        return document

    def get_documents(
        self,
        user_id: int,
        doc_type: Optional[str] = None,
        status_filter: Optional[str] = None,
        search_query: Optional[str] = None
    ) -> List[Document]:
        """
        Retrieves documents for the user with optional type filtering,
        search query on masked number / file name, and dynamic status filter.
        """
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM documents WHERE user_id = ?"
            params = [user_id]

            if doc_type:
                query += " AND document_type = ?"
                params.append(doc_type)

            query += " ORDER BY created_at DESC"
            cursor.execute(query, params)
            rows = cursor.fetchall()

        documents = [Document.from_row(row) for row in rows]

        # Apply search query filter
        if search_query:
            q = search_query.strip().lower()
            documents = [
                d for d in documents
                if q in d.document_number_masked.lower()
                or (d.file_original_name and q in d.file_original_name.lower())
                or q in d.document_type.lower()
            ]

        # Apply dynamic status filter
        if status_filter:
            documents = [d for d in documents if d.status.value.lower() == status_filter.lower()]

        return documents

    def get_document_by_id(self, document_id: int, user_id: int) -> Optional[Document]:
        """Fetches a single document ensuring user ownership."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM documents WHERE document_id = ? AND user_id = ?",
                (document_id, user_id)
            )
            row = cursor.fetchone()
            if not row:
                return None
            return Document.from_row(row)

    def decrypt_document_number(self, document: Document, dek: bytes) -> str:
        """Decrypts and returns the raw sensitive document number for authorized viewing/editing."""
        return decrypt_string(document.document_number, document.document_number_nonce, dek)

    def update_document(
        self,
        document_id: int,
        user_id: int,
        dek: bytes,
        doc_type: str,
        doc_number: Optional[str] = None,
        issue_date: Optional[str] = None,
        expiry_date: Optional[str] = None,
        reminder_date: Optional[str] = None,
        reminder_days: int = 180,
        file_reference: Optional[str] = None,
        file_original_name: Optional[str] = None,
        file_size: Optional[int] = None,
        file_mime_type: Optional[str] = None
    ) -> Document:
        """
        Updates an existing document record.
        Re-encrypts document number if updated.
        """
        existing = self.get_document_by_id(document_id, user_id)
        if not existing:
            raise ValueError("Document not found or unauthorized access.")

        # Determine effective document number for validation
        if doc_number:
            effective_num = doc_number.strip()
        else:
            effective_num = self.decrypt_document_number(existing, dek)

        # Preserve existing values if not specified
        eff_issue_date = issue_date if issue_date is not None else existing.issue_date
        eff_expiry_date = expiry_date if expiry_date is not None else existing.expiry_date
        eff_reminder_date = reminder_date if reminder_date is not None else existing.reminder_date
        eff_reminder_days = reminder_days if reminder_days is not None else existing.reminder_days

        is_valid, issues = validate_document_input(
            doc_type=doc_type,
            doc_number=effective_num,
            issue_date=eff_issue_date,
            expiry_date=eff_expiry_date,
            reminder_date=eff_reminder_date,
            reminder_days=eff_reminder_days
        )
        if not is_valid:
            raise ValueError("Validation failed: " + " ".join(issues))

        user_salt = self._get_user_salt(user_id)
        number_hash = generate_document_hash(effective_num, user_salt)

        # Check duplicate if number or type changed
        if doc_number or doc_type != existing.document_type:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT document_id FROM documents
                    WHERE user_id = ? AND document_type = ? AND document_number_hash = ? AND document_id != ?
                    """,
                    (user_id, doc_type, number_hash, document_id)
                )
                if cursor.fetchone():
                    raise ValueError(f"Another {doc_type} with this document number already exists in your vault.")

        if doc_number:
            cipher_b64, nonce_b64 = encrypt_string(doc_number.strip(), dek)
            masked_number = mask_document_number(doc_type, doc_number)
        else:
            cipher_b64 = existing.document_number
            nonce_b64 = existing.document_number_nonce
            masked_number = mask_document_number(doc_type, effective_num)

        now_iso = datetime.now(timezone.utc).isoformat()

        # Preserve file reference if not explicitly updated
        eff_file_ref = file_reference if file_reference is not None else existing.file_reference
        eff_file_name = file_original_name if file_original_name is not None else existing.file_original_name
        eff_file_size = file_size if file_size is not None else existing.file_size
        eff_file_mime = file_mime_type if file_mime_type is not None else existing.file_mime_type

        with self.db.get_connection() as conn:
            conn.execute(
                """
                UPDATE documents
                SET document_type = ?, document_number = ?, document_number_nonce = ?,
                    document_number_masked = ?, document_number_hash = ?,
                    issue_date = ?, expiry_date = ?, reminder_date = ?,
                    reminder_days = ?, file_reference = ?, file_original_name = ?,
                    file_size = ?, file_mime_type = ?, updated_at = ?
                WHERE document_id = ? AND user_id = ?
                """,
                (
                    doc_type, cipher_b64, nonce_b64,
                    masked_number, number_hash,
                    eff_issue_date, eff_expiry_date, eff_reminder_date,
                    eff_reminder_days, eff_file_ref, eff_file_name,
                    eff_file_size, eff_file_mime, now_iso,
                    document_id, user_id
                )
            )

        updated_doc = self.get_document_by_id(document_id, user_id)
        self.audit.log(
            action=AuditAction.DOCUMENT_UPDATED,
            user_id=user_id,
            details=f"Updated {doc_type} ({masked_number})"
        )
        return updated_doc

    def delete_document(self, document_id: int, user_id: int) -> bool:
        """
        Deletes a document record and audits the action with masked document number.
        Returns True if deleted.
        """
        doc = self.get_document_by_id(document_id, user_id)
        if not doc:
            return False

        with self.db.get_connection() as conn:
            conn.execute(
                "DELETE FROM documents WHERE document_id = ? AND user_id = ?",
                (document_id, user_id)
            )

        self.audit.log(
            action=AuditAction.DOCUMENT_DELETED,
            user_id=user_id,
            details=f"Deleted {doc.document_type} ({doc.document_number_masked})"
        )
        logger.info(f"Deleted document {document_id} for user {user_id}")
        return True
