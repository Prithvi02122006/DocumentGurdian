"""
Unit tests for ExportService:
CSV file generation, header structure, masked vs decrypted exports, and audit recording.
"""

import csv
import os
import tempfile
import pytest
from services.export_service import ExportService, CSV_HEADERS
from services.document_service import DocumentService
from security.authentication import AuthenticationService
from services.audit_service import AuditService
from models.document import DocumentType


@pytest.fixture
def export_env(memory_db):
    audit = AuditService(memory_db)
    auth = AuthenticationService(memory_db, audit)
    reg_res = auth.register("export_user", "ExportPass#2026", "ExportPass#2026")
    doc_service = DocumentService(memory_db, audit)
    export_service = ExportService(db=memory_db, document_service=doc_service, audit_service=audit)

    # Populate 3 documents
    doc_service.add_document(
        user_id=reg_res.user.user_id,
        dek=reg_res.dek,
        doc_type=DocumentType.PASSPORT,
        doc_number="Z1234567",
        issue_date="2020-01-01",
        expiry_date="2030-01-01"
    )
    doc_service.add_document(
        user_id=reg_res.user.user_id,
        dek=reg_res.dek,
        doc_type=DocumentType.AADHAAR,
        doc_number="123412341234"
    )
    doc_service.add_document(
        user_id=reg_res.user.user_id,
        dek=reg_res.dek,
        doc_type=DocumentType.PAN,
        doc_number="ABCDE8888K"
    )

    return export_service, audit, reg_res.user, reg_res.dek


def test_export_documents_to_csv_masked(export_env):
    """Verifies CSV export contains expected headers and masked numbers by default."""
    export_service, audit, user, dek = export_env

    with tempfile.TemporaryDirectory() as tmp_dir:
        csv_file = os.path.join(tmp_dir, "records_masked.csv")
        count = export_service.export_documents_to_csv(
            user_id=user.user_id,
            destination_csv_path=csv_file,
            include_decrypted_numbers=False
        )
        assert count == 3
        assert os.path.isfile(csv_file)

        with open(csv_file, "r", encoding="utf-8-sig") as f:
            reader = list(csv.reader(f))

        # Check headers
        assert reader[0] == CSV_HEADERS
        # Check rows
        data_rows = reader[1:]
        assert len(data_rows) == 3

        # Numbers must be masked
        for row in data_rows:
            doc_type = row[0]
            number_val = row[1]
            if doc_type == DocumentType.AADHAAR:
                assert number_val.startswith("XXXX XXXX")
            elif doc_type == DocumentType.PAN:
                assert number_val.startswith("XXXXX")
            elif doc_type == DocumentType.PASSPORT:
                assert "*" in number_val

        # Verify audit log
        logs = audit.get_logs_for_user(user.user_id)
        assert any(l.action == "RECORDS_EXPORTED" for l in logs)


def test_export_documents_to_csv_decrypted(export_env):
    """Verifies CSV export can optionally include decrypted numbers when authorized."""
    export_service, audit, user, dek = export_env

    with tempfile.TemporaryDirectory() as tmp_dir:
        csv_file = os.path.join(tmp_dir, "records_decrypted.csv")
        count = export_service.export_documents_to_csv(
            user_id=user.user_id,
            destination_csv_path=csv_file,
            include_decrypted_numbers=True,
            dek=dek
        )
        assert count == 3

        with open(csv_file, "r", encoding="utf-8-sig") as f:
            reader = list(csv.reader(f))

        data_rows = reader[1:]
        exported_numbers = [r[1] for r in data_rows]

        assert "Z1234567" in exported_numbers
        assert "123412341234" in exported_numbers
        assert "ABCDE8888K" in exported_numbers

        # Verify audit log recorded decrypted mode
        logs = audit.get_logs_for_user(user.user_id)
        assert any("decrypted numbers" in (l.details or "") for l in logs)
