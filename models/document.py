"""
Document entity model and status calculation for Document Guardian.
Strictly adheres to document-specific rules:
- Passport: Issue date, expiry date, reminder period.
- Aadhaar / PAN: No expiry date. Optional review reminder date.
"""

from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
from typing import Optional
import sqlite3


class DocumentType(str, Enum):
    PASSPORT = "Passport"
    AADHAAR = "Aadhaar"
    PAN = "PAN"


class DocumentStatus(str, Enum):
    VALID = "Valid"
    ATTENTION_REQUIRED = "Attention Required"
    EXPIRED = "Expired"
    REVIEW_DUE = "Review Due"


def mask_document_number(doc_type: str, number: str) -> str:
    """
    Returns a masked version of the sensitive document number for safe UI display.
    """
    cleaned = number.strip().replace(" ", "").replace("-", "")
    if doc_type == DocumentType.AADHAAR:
        # Expected 12 digits: XXXX XXXX 1234
        if len(cleaned) == 12:
            return f"XXXX XXXX {cleaned[-4:]}"
        return "XXXX XXXX " + (cleaned[-4:] if len(cleaned) >= 4 else "XXXX")

    elif doc_type == DocumentType.PAN:
        # Expected 10 alphanumeric: XXXXX1234X
        if len(cleaned) == 10:
            return f"XXXXX{cleaned[5:9]}{cleaned[9]}"
        return "XXXXX" + (cleaned[-5:] if len(cleaned) >= 5 else "XXXXX")

    elif doc_type == DocumentType.PASSPORT:
        # Expected 8 alphanumeric (1 letter + 7 digits)
        if len(cleaned) >= 4:
            first_char = cleaned[0]
            last_two = cleaned[-2:]
            middle_stars = "*" * (len(cleaned) - 3)
            return f"{first_char}{middle_stars}{last_two}"
        return "X******X"

    # Default fallback masking
    if len(cleaned) > 4:
        return "*" * (len(cleaned) - 4) + cleaned[-4:]
    return "****"


def calculate_status(
    doc_type: str,
    expiry_date_str: Optional[str] = None,
    reminder_date_str: Optional[str] = None,
    reminder_days: int = 180,
    reference_date: Optional[date] = None
) -> DocumentStatus:
    """
    Dynamically computes document status from current date without permanently storing it in DB.
    - Passport: Uses expiry_date. If expired -> EXPIRED. If within reminder_days -> ATTENTION_REQUIRED. Else VALID.
    - Aadhaar / PAN: Strictly no expiry date. Uses optional reminder_date.
      If past reminder_date -> REVIEW_DUE. If within reminder_days -> ATTENTION_REQUIRED. Else VALID.
    """
    today = reference_date or date.today()

    if doc_type == DocumentType.PASSPORT:
        if not expiry_date_str:
            return DocumentStatus.ATTENTION_REQUIRED
        try:
            exp_date = datetime.strptime(expiry_date_str, "%Y-%m-%d").date()
        except ValueError:
            return DocumentStatus.ATTENTION_REQUIRED

        days_remaining = (exp_date - today).days
        if days_remaining < 0:
            return DocumentStatus.EXPIRED
        elif days_remaining <= reminder_days:
            return DocumentStatus.ATTENTION_REQUIRED
        else:
            return DocumentStatus.VALID

    elif doc_type in (DocumentType.AADHAAR, DocumentType.PAN):
        # Aadhaar and PAN do not expire. They only have optional review reminders.
        if not reminder_date_str:
            return DocumentStatus.VALID

        try:
            rem_date = datetime.strptime(reminder_date_str, "%Y-%m-%d").date()
        except ValueError:
            return DocumentStatus.VALID

        days_remaining = (rem_date - today).days
        if days_remaining < 0:
            return DocumentStatus.REVIEW_DUE
        elif days_remaining <= reminder_days:
            return DocumentStatus.ATTENTION_REQUIRED
        else:
            return DocumentStatus.VALID

    return DocumentStatus.VALID


@dataclass
class Document:
    document_id: Optional[int]
    user_id: int
    document_type: str
    document_number: str
    document_number_nonce: str
    document_number_masked: str
    document_number_hash: str
    issue_date: Optional[str] = None
    expiry_date: Optional[str] = None
    reminder_date: Optional[str] = None
    reminder_days: int = 180
    file_reference: Optional[str] = None
    file_original_name: Optional[str] = None
    file_size: Optional[int] = None
    file_mime_type: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @property
    def status(self) -> DocumentStatus:
        """Dynamically calculated status."""
        return calculate_status(
            doc_type=self.document_type,
            expiry_date_str=self.expiry_date,
            reminder_date_str=self.reminder_date,
            reminder_days=self.reminder_days
        )

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Document":
        """Instantiates Document from SQLite Row."""
        return cls(
            document_id=row["document_id"],
            user_id=row["user_id"],
            document_type=row["document_type"],
            document_number=row["document_number"],
            document_number_nonce=row["document_number_nonce"],
            document_number_masked=row["document_number_masked"],
            document_number_hash=row["document_number_hash"],
            issue_date=row["issue_date"],
            expiry_date=row["expiry_date"],
            reminder_date=row["reminder_date"],
            reminder_days=row["reminder_days"],
            file_reference=row["file_reference"],
            file_original_name=row["file_original_name"],
            file_size=row["file_size"],
            file_mime_type=row["file_mime_type"],
            created_at=row["created_at"],
            updated_at=row["updated_at"]
        )

    def to_dict(self) -> dict:
        """Serializes document fields with dynamic status, omitting raw cipher/nonce."""
        return {
            "document_id": self.document_id,
            "user_id": self.user_id,
            "document_type": self.document_type,
            "document_number_masked": self.document_number_masked,
            "issue_date": self.issue_date,
            "expiry_date": self.expiry_date,
            "reminder_date": self.reminder_date,
            "reminder_days": self.reminder_days,
            "status": self.status.value,
            "has_file": bool(self.file_reference),
            "file_original_name": self.file_original_name,
            "file_size": self.file_size,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }
