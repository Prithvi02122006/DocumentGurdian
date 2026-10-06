"""
End-to-End (E2E) Integration Tests for Document Guardian.
Tests full user journeys across all subsystems:
- User registration, Argon2id hashing, and DEK envelope generation
- Failed login tracking and lockout enforcement
- Session management, DEK lifecycle, and inactivity lock/unlock
- Document CRUD (Passport, Aadhaar, PAN) with AES-256-GCM encryption
- Duplicate document prevention via HMAC hashes
- Encrypted file attachment and on-demand decryption in vault
- Expiry calculation and dynamic status determination
- Reminder engine and notification deduplication
- Masked and decrypted CSV export with audit trail tracking
- Master password modification with DEK re-wrapping
- Cryptographic tamper detection and zero plaintext data leaks
- Cascade deletion and secure logout
"""

import os
import tempfile
import pytest
from datetime import datetime, timedelta
from cryptography.exceptions import InvalidTag

from database.database import DatabaseManager
from security.authentication import AuthenticationService, MAX_FAILED_ATTEMPTS
from security.session import SessionManager
from security.encryption import encrypt_aes_gcm, decrypt_aes_gcm
from services.audit_service import AuditService
from services.document_service import DocumentService
from services.expiry_service import ExpiryService
from services.reminder_service import ReminderService
from services.notification_service import NotificationService
from services.file_service import FileService
from services.export_service import ExportService
from models.document import DocumentType, DocumentStatus
from models.audit import AuditAction


@pytest.fixture
def e2e_env():
    """Sets up a complete isolated environment with on-disk DB and vault directory."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "e2e_guardian.db")
        vault_dir = os.path.join(tmp_dir, "vault")
        os.makedirs(vault_dir, exist_ok=True)

        db = DatabaseManager(db_path)
        db.init_db()

        audit_service = AuditService(db)
        auth_service = AuthenticationService(db, audit_service)
        session_manager = SessionManager(audit_service=audit_service)
        doc_service = DocumentService(db, audit_service)
        file_service = FileService(
            vault_dir=vault_dir,
            db=db,
            audit_service=audit_service,
            document_service=doc_service
        )
        notif_service = NotificationService(enable_os_notifications=False)
        expiry_service = ExpiryService(db, doc_service)
        reminder_service = ReminderService(expiry_service, notif_service, audit_service)
        export_service = ExportService(
            db=db,
            document_service=doc_service,
            expiry_service=expiry_service,
            audit_service=audit_service
        )

        yield {
            "tmp_dir": tmp_dir,
            "db": db,
            "vault_dir": vault_dir,
            "audit": audit_service,
            "auth": auth_service,
            "session": session_manager,
            "docs": doc_service,
            "files": file_service,
            "expiry": expiry_service,
            "reminders": reminder_service,
            "export": export_service
        }

        db.close()


def test_e2e_complete_citizen_journey(e2e_env):
    """
    Simulates a full citizen journey from initial registration to secure logout.
    Validates end-to-end integration across all system components.
    """
    auth = e2e_env["auth"]
    session = e2e_env["session"]
    docs = e2e_env["docs"]
    files = e2e_env["files"]
    export = e2e_env["export"]
    audit = e2e_env["audit"]
    expiry = e2e_env["expiry"]
    reminders = e2e_env["reminders"]
    tmp_dir = e2e_env["tmp_dir"]

    username = "priya_sharma"
    master_pass = "PriyaGuard#2026"

    # =========================================================================
    # Step 1: User Registration
    # =========================================================================
    reg_result = auth.register(username, master_pass, master_pass)
    assert reg_result.success is True, f"Registration failed: {reg_result.error_message}"
    user = reg_result.user
    original_dek = reg_result.dek
    assert user is not None
    assert user.user_id is not None
    assert len(original_dek) == 32

    # Verify audit log recorded user creation
    user_logs = audit.get_logs_for_user(user_id=user.user_id)
    assert any(log.action == AuditAction.LOGIN_SUCCESS.value for log in user_logs)

    # =========================================================================
    # Step 2: Failed Login & Lockout Protection
    # =========================================================================
    # Attempt 5 invalid logins
    for i in range(MAX_FAILED_ATTEMPTS):
        bad_login = auth.login(username, "WrongPassword#999")
        assert bad_login.success is False

    # The 6th attempt should be rejected due to account lockout
    locked_login = auth.login(username, "WrongPassword#999")
    assert locked_login.success is False
    assert "locked" in locked_login.error_message.lower()

    # Reset lockout in database for the test user to proceed with valid login
    with e2e_env["db"].get_connection() as conn:
        conn.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?", (username,))

    # =========================================================================
    # Step 3: Successful Login & Session Initialization
    # =========================================================================
    login_result = auth.login(username, master_pass)
    assert login_result.success is True
    assert login_result.dek == original_dek

    session.start_session(login_result.user, login_result.dek)
    assert session.is_authenticated is True
    assert session.is_locked is False
    active_dek = session.get_dek()

    # =========================================================================
    # Step 4: Add Documents (Passport, Aadhaar, PAN)
    # =========================================================================
    # 4A. Add Passport (requires issue & expiry dates)
    passport = docs.add_document(
        user_id=user.user_id,
        dek=active_dek,
        doc_type=DocumentType.PASSPORT,
        doc_number="Z9876543",
        issue_date="2020-06-15",
        expiry_date="2030-06-14"
    )
    assert passport.document_id is not None
    assert passport.document_number_masked == "Z*****43"
    assert passport.document_type == DocumentType.PASSPORT.value

    # 4B. Add Aadhaar (12 digits, strictly NO expiry date, optional review date)
    aadhaar = docs.add_document(
        user_id=user.user_id,
        dek=active_dek,
        doc_type=DocumentType.AADHAAR,
        doc_number="234567890128",
        reminder_date="2028-12-31"
    )
    assert aadhaar.document_id is not None
    assert aadhaar.document_number_masked == "XXXX XXXX 0128"
    assert aadhaar.expiry_date is None

    # 4C. Add PAN (10 chars, strictly NO expiry date)
    pan = docs.add_document(
        user_id=user.user_id,
        dek=active_dek,
        doc_type=DocumentType.PAN,
        doc_number="ABCDE1234F"
    )
    assert pan.document_id is not None
    assert pan.document_number_masked == "XXXXX1234F"
    assert pan.expiry_date is None

    # Verify duplicate prevention: attempting to re-add same Aadhaar must raise ValueError
    with pytest.raises(ValueError) as dup_err:
        docs.add_document(
            user_id=user.user_id,
            dek=active_dek,
            doc_type=DocumentType.AADHAAR,
            doc_number="2345 6789 0128"  # Same Aadhaar with spaces
        )
    assert "already registered" in str(dup_err.value).lower()

    # =========================================================================
    # Step 5: Encrypted File Attachment in Vault
    # =========================================================================
    # Create sample PDF file
    sample_pdf = os.path.join(tmp_dir, "passport_scan.pdf")
    pdf_content = b"%PDF-1.5\n%Document Guardian Encrypted Vault Test Payload\n%%EOF"
    with open(sample_pdf, "wb") as f:
        f.write(pdf_content)

    # Attach file to passport
    passport_with_file = files.attach_file_to_document(
        document_id=passport.document_id,
        user_id=user.user_id,
        dek=active_dek,
        source_file_path=sample_pdf
    )
    assert passport_with_file.file_reference is not None

    # Verify on-disk file in encrypted vault is ciphertext (raw PDF header absent)
    vault_file_path = os.path.join(e2e_env["vault_dir"], passport_with_file.file_reference)
    assert os.path.exists(vault_file_path)
    with open(vault_file_path, "rb") as f:
        vault_raw_bytes = f.read()
    assert b"%PDF-1.5" not in vault_raw_bytes, "Vault file contains plaintext PDF header!"

    # Read and decrypt file on-demand, verify byte-level fidelity
    dec_bytes = files.read_decrypted_file_bytes(
        file_reference=passport_with_file.file_reference,
        dek=active_dek,
        user_id=user.user_id
    )
    assert dec_bytes == pdf_content

    # =========================================================================
    # Step 6: Expiry Engine & Dynamic Metrics
    # =========================================================================
    user_docs = docs.get_documents(user_id=user.user_id)
    assert len(user_docs) == 3

    dashboard_summary = expiry.get_user_dashboard_summary(user.user_id)
    assert dashboard_summary.total_documents == 3
    # Passport is valid until 2030, Aadhaar has review in 2028, PAN is valid
    assert dashboard_summary.valid_count >= 1

    # Check reminder scan executes safely
    reminder_items = reminders.check_reminders_for_user(user.user_id, notify=True)
    assert isinstance(reminder_items, list)

    # =========================================================================
    # Step 7: Masked and Decrypted CSV Export
    # =========================================================================
    # 7A. Masked CSV Export (Default Privacy Mode)
    masked_csv_path = os.path.join(tmp_dir, "exported_masked.csv")
    rows_masked = export.export_documents_to_csv(
        user_id=user.user_id,
        destination_csv_path=masked_csv_path,
        include_decrypted_numbers=False
    )
    assert rows_masked == 3
    assert os.path.exists(masked_csv_path)

    with open(masked_csv_path, "r", encoding="utf-8") as f:
        csv_content = f.read()
    assert "Z*****43" in csv_content
    assert "XXXX XXXX 0128" in csv_content
    assert "XXXXX1234F" in csv_content
    assert "Z9876543" not in csv_content, "Plaintext passport number leaked in masked export!"

    # 7B. Decrypted CSV Export
    decrypted_csv_path = os.path.join(tmp_dir, "exported_decrypted.csv")
    rows_dec = export.export_documents_to_csv(
        user_id=user.user_id,
        destination_csv_path=decrypted_csv_path,
        include_decrypted_numbers=True,
        dek=active_dek
    )
    assert rows_dec == 3

    with open(decrypted_csv_path, "r", encoding="utf-8") as f:
        dec_csv_content = f.read()
    assert "Z9876543" in dec_csv_content
    assert "234567890128" in dec_csv_content
    assert "ABCDE1234F" in dec_csv_content

    # =========================================================================
    # Step 8: Session Inactivity & Locking Workflow
    # =========================================================================
    session.lock_session(reason="Inactivity timeout")
    assert session.is_locked is True

    # Accessing DEK while locked must raise PermissionError
    with pytest.raises(PermissionError):
        session.get_dek()

    # Unlocking with bad password must fail
    assert session.unlock_session("WrongPass#2026") is False
    assert session.is_locked is True

    # Unlocking with correct master password restores DEK
    assert session.unlock_session(master_pass) is True
    assert session.is_locked is False
    assert session.get_dek() == active_dek

    # =========================================================================
    # Step 9: Master Password Change & DEK Re-wrapping
    # =========================================================================
    new_master_pass = "PriyaNewSecure#2027"
    change_res = auth.change_password(user.user_id, master_pass, new_master_pass, new_master_pass)
    assert change_res.success is True

    # Verify old password no longer logs in
    old_login = auth.login(username, master_pass)
    assert old_login.success is False

    # Login with new master password succeeds and returns the exact same DEK
    new_login = auth.login(username, new_master_pass)
    assert new_login.success is True
    assert new_login.dek == original_dek

    # Verify existing documents can be decrypted using DEK unwrapped with new password
    fresh_doc = docs.get_document_by_id(passport.document_id, user.user_id)
    dec_pass_number = docs.decrypt_document_number(fresh_doc, new_login.dek)
    assert dec_pass_number == "Z9876543"

    # Verify vault file remains decryptable
    file_bytes_after = files.read_decrypted_file_bytes(passport_with_file.file_reference, new_login.dek, user.user_id)
    assert file_bytes_after == pdf_content

    # =========================================================================
    # Step 10: Secure Logout
    # =========================================================================
    session.logout()
    assert session.is_authenticated is False
    with pytest.raises(PermissionError):
        session.get_dek()

    # Final audit log check
    final_logs = audit.get_logs_for_user(user_id=user.user_id)
    actions = [l.action for l in final_logs]
    assert AuditAction.LOGOUT.value in actions
    assert AuditAction.PASSWORD_CHANGED.value in actions
    assert AuditAction.DOCUMENT_ADDED.value in actions
    assert AuditAction.FILE_UPLOADED.value in actions
    assert AuditAction.RECORDS_EXPORTED.value in actions


def test_e2e_tamper_detection(e2e_env):
    """
    Verifies AES-256-GCM authenticated encryption detects ciphertext tampering
    in both database records and disk-based vault storage.
    """
    auth = e2e_env["auth"]
    docs = e2e_env["docs"]
    files = e2e_env["files"]
    db = e2e_env["db"]
    tmp_dir = e2e_env["tmp_dir"]

    reg = auth.register("tamper_target", "TamperTarget#2026", "TamperTarget#2026")
    user = reg.user
    dek = reg.dek

    # Add a document
    doc = docs.add_document(
        user_id=user.user_id,
        dek=dek,
        doc_type=DocumentType.PAN,
        doc_number="ABCDE9999Z"
    )

    # Attach file
    sample_file = os.path.join(tmp_dir, "test.png")
    with open(sample_file, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 30)

    doc_with_file = files.attach_file_to_document(doc.document_id, user.user_id, dek, sample_file)
    assert doc_with_file.file_reference is not None

    # 1. Tamper with document number in database
    with db.get_connection() as conn:
        conn.execute(
            "UPDATE documents SET document_number = 'tampered_corrupt_data' WHERE document_id = ?",
            (doc.document_id,)
        )

    tampered_doc = docs.get_document_by_id(doc.document_id, user.user_id)
    with pytest.raises(Exception):
        # AES-GCM tag verification must fail
        docs.decrypt_document_number(tampered_doc, dek)

    # 2. Tamper with encrypted vault file on disk
    vault_path = os.path.join(e2e_env["vault_dir"], doc_with_file.file_reference)
    with open(vault_path, "r+b") as f:
        f.seek(20)
        f.write(b"\xFF\xFF\xFF\xFF")  # Invert 4 bytes of ciphertext

    with pytest.raises(InvalidTag):
        files.read_decrypted_file_bytes(doc_with_file.file_reference, dek, user.user_id)


def test_e2e_user_cascade_deletion(e2e_env):
    """
    Verifies that deleting a user account cascades to delete all document records
    and dissociates audit log entries (sets user_id to NULL) while preserving logs.
    """
    auth = e2e_env["auth"]
    docs = e2e_env["docs"]
    db = e2e_env["db"]

    reg = auth.register("cascade_target", "CascadePass#2026", "CascadePass#2026")
    user = reg.user
    dek = reg.dek

    docs.add_document(user.user_id, dek, DocumentType.PASSPORT, "K1234567", issue_date="2022-01-01", expiry_date="2032-01-01")
    docs.add_document(user.user_id, dek, DocumentType.PAN, "ABCDE5678G")

    assert len(docs.get_documents(user.user_id)) == 2

    # Delete the user directly from DB
    with db.get_connection() as conn:
        conn.execute("DELETE FROM users WHERE user_id = ?", (user.user_id,))

    # Documents must be cascade deleted
    user_docs_after = docs.get_documents(user.user_id)
    assert len(user_docs_after) == 0

    # Audit logs must still exist, with user_id set to NULL
    with db.get_connection() as conn:
        cursor = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE user_id IS NULL")
        null_user_logs = cursor.fetchone()[0]
        assert null_user_logs > 0
