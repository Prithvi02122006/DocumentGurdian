"""
Unit tests for FileService:
File validation (PDF, JPG, JPEG, PNG), magic bytes checks, AES-256-GCM vault encryption,
decryption, document attachment/detachment, and audit logging.
"""

import os
import tempfile
import pytest
from cryptography.exceptions import InvalidTag
from services.file_service import FileService, validate_file
from services.document_service import DocumentService
from security.authentication import AuthenticationService
from services.audit_service import AuditService
from models.document import DocumentType


@pytest.fixture
def file_env(memory_db):
    with tempfile.TemporaryDirectory() as temp_vault:
        audit = AuditService(memory_db)
        auth = AuthenticationService(memory_db, audit)
        reg_res = auth.register("file_user", "FileMasterPass#2026", "FileMasterPass#2026")
        doc_service = DocumentService(memory_db, audit)
        file_service = FileService(
            vault_dir=temp_vault,
            db=memory_db,
            audit_service=audit,
            document_service=doc_service
        )
        yield file_service, doc_service, audit, reg_res.user, reg_res.dek, temp_vault


def test_file_validation():
    """Verifies file type, extension, size, and magic byte validation."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        # 1. Valid PDF
        pdf_path = os.path.join(tmp_dir, "valid.pdf")
        with open(pdf_path, "wb") as f:
            f.write(b"%PDF-1.4\n%mock content\n%%EOF")
        ok, mime, size, name = validate_file(pdf_path)
        assert ok is True
        assert mime == "application/pdf"
        assert name == "valid.pdf"

        # 2. Valid PNG
        png_path = os.path.join(tmp_dir, "valid.png")
        with open(png_path, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
        ok, mime, size, name = validate_file(png_path)
        assert ok is True
        assert mime == "image/png"

        # 3. Valid JPG
        jpg_path = os.path.join(tmp_dir, "valid.jpg")
        with open(jpg_path, "wb") as f:
            f.write(b"\xff\xd8\xff\xe0\x00\x10JFIF")
        ok, mime, size, name = validate_file(jpg_path)
        assert ok is True
        assert mime == "image/jpeg"

        # 4. Disallowed extension
        exe_path = os.path.join(tmp_dir, "malicious.exe")
        with open(exe_path, "wb") as f:
            f.write(b"MZ\x90\x00")
        ok, err, _, _ = validate_file(exe_path)
        assert not ok
        assert "Unsupported file type" in err

        # 5. Empty file
        empty_path = os.path.join(tmp_dir, "empty.pdf")
        with open(empty_path, "wb") as f:
            pass
        ok, err, _, _ = validate_file(empty_path)
        assert not ok
        assert "empty" in err

        # 6. Spoofed magic bytes (plain text file renamed to .pdf)
        spoofed_path = os.path.join(tmp_dir, "fake.pdf")
        with open(spoofed_path, "wb") as f:
            f.write(b"Hello world, I am plain text, not a PDF.")
        ok, err, _, _ = validate_file(spoofed_path)
        assert not ok
        assert "does not match" in err


def test_file_encryption_and_decryption(file_env):
    """Verifies that uploaded files are encrypted with AES-256-GCM at rest and decrypt cleanly."""
    file_service, _, _, user, dek, temp_vault = file_env

    with tempfile.TemporaryDirectory() as tmp_dir:
        original_content = b"%PDF-1.4\nSample Passport Scan Data 12345\n%%EOF"
        source_path = os.path.join(tmp_dir, "passport_doc.pdf")
        with open(source_path, "wb") as f:
            f.write(original_content)

        # Store in vault
        file_ref, orig_name, fsize, mime = file_service.store_encrypted_file(source_path, dek, user.user_id)
        assert file_ref.endswith(".enc")
        assert orig_name == "passport_doc.pdf"

        # Check raw vault file on disk: MUST NOT contain plaintext
        vault_file_path = os.path.join(temp_vault, file_ref)
        assert os.path.isfile(vault_file_path)
        with open(vault_file_path, "rb") as f:
            stored_cipher = f.read()
        assert b"Sample Passport Scan Data" not in stored_cipher

        # Decrypt with correct session DEK
        decrypted = file_service.read_decrypted_file_bytes(file_ref, dek, user.user_id)
        assert decrypted == original_content

        # Decrypt with wrong DEK -> InvalidTag
        wrong_dek = os.urandom(32)
        with pytest.raises(InvalidTag):
            file_service.read_decrypted_file_bytes(file_ref, wrong_dek, user.user_id)


def test_attach_and_detach_document_file(file_env):
    """Verifies attaching a file to a document and detaching/deleting it from the vault."""
    file_service, doc_service, audit, user, dek, temp_vault = file_env

    # 1. Create document
    doc = doc_service.add_document(
        user_id=user.user_id,
        dek=dek,
        doc_type=DocumentType.AADHAAR,
        doc_number="555566667777"
    )
    assert not doc.file_reference

    # 2. Attach PDF
    with tempfile.TemporaryDirectory() as tmp_dir:
        pdf_path = os.path.join(tmp_dir, "aadhaar_card.pdf")
        with open(pdf_path, "wb") as f:
            f.write(b"%PDF-1.4\nAadhaar e-copy\n%%EOF")

        updated_doc = file_service.attach_file_to_document(doc.document_id, user.user_id, dek, pdf_path)
        assert updated_doc.file_reference
        assert updated_doc.file_original_name == "aadhaar_card.pdf"
        assert updated_doc.file_mime_type == "application/pdf"

        # Verify physical encrypted file exists
        vault_path = os.path.join(temp_vault, updated_doc.file_reference)
        assert os.path.isfile(vault_path)

        # 3. Detach file
        detached_doc = file_service.detach_file_from_document(doc.document_id, user.user_id, dek)
        assert not detached_doc.file_reference
        # Verify physical encrypted file was deleted
        assert not os.path.isfile(vault_path)

    # 4. Verify audit actions
    user_logs = audit.get_logs_for_user(user.user_id)
    actions = [l.action for l in user_logs]
    assert "FILE_UPLOADED" in actions
    assert "FILE_DELETED" in actions
