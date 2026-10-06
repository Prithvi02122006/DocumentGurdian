"""
Encrypted document file storage service for Document Guardian.
Handles file validation, AES-256-GCM encryption at rest, secure vault storage,
authorized decryption, viewing, and deletion.
Supported formats: PDF, JPG, JPEG, PNG (max 10 MB).
"""

import os
import uuid
import tempfile
import logging
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from database.database import DatabaseManager, get_db
from models.document import Document
from models.audit import AuditAction
from services.audit_service import AuditService
from services.document_service import DocumentService

logger = logging.getLogger(__name__)

VAULT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "storage", "encrypted_vault")
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

ALLOWED_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png"}

MAGIC_BYTES = {
    b"%PDF-": "application/pdf",
    b"\xff\xd8\xff": "image/jpeg",
    b"\x89PNG\r\n\x1a\n": "image/png"
}


def validate_file(file_path: str) -> Tuple[bool, str, int, str]:
    """
    Validates file existence, extension, size, and magic bytes.
    Returns (is_valid, mime_or_error, file_size, original_filename).
    """
    if not os.path.isfile(file_path):
        return False, "File does not exist.", 0, ""

    filename = os.path.basename(file_path)
    ext = os.path.splitext(filename)[1].lower()

    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Unsupported file type '{ext}'. Only PDF, JPG, JPEG, and PNG are allowed.", 0, filename

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        return False, "Selected file is empty (0 bytes).", 0, filename

    if file_size > MAX_FILE_SIZE_BYTES:
        mb_size = file_size / (1024 * 1024)
        return False, f"File exceeds maximum allowed size of 10 MB (File size: {mb_size:.2f} MB).", file_size, filename

    # Inspect magic bytes
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)

        detected_mime = None
        for magic, mime in MAGIC_BYTES.items():
            if header.startswith(magic):
                detected_mime = mime
                break

        if not detected_mime:
            return False, "File content does not match allowed PDF or Image format.", file_size, filename

        return True, detected_mime, file_size, filename

    except Exception as e:
        return False, f"Error inspecting file: {str(e)}", file_size, filename


class FileService:
    """Manages encrypted file storage in the local vault."""

    def __init__(
        self,
        vault_dir: str = VAULT_DIR,
        db: Optional[DatabaseManager] = None,
        audit_service: Optional[AuditService] = None,
        document_service: Optional[DocumentService] = None
    ):
        self.vault_dir = vault_dir
        self.db = db or get_db()
        self.audit = audit_service or AuditService(self.db)
        self.doc_service = document_service or DocumentService(self.db, self.audit)
        os.makedirs(self.vault_dir, exist_ok=True)

    def _get_vault_file_path(self, file_reference: str) -> str:
        # Sanitize file_reference to prevent directory traversal
        safe_name = os.path.basename(file_reference)
        return os.path.join(self.vault_dir, safe_name)

    def store_encrypted_file(
        self,
        source_file_path: str,
        dek: bytes,
        user_id: int
    ) -> Tuple[str, str, int, str]:
        """
        Validates, encrypts with AES-256-GCM, and stores file in the encrypted vault.
        Returns (file_reference, original_name, file_size, mime_type).
        """
        is_valid, mime_or_err, file_size, original_name = validate_file(source_file_path)
        if not is_valid:
            raise ValueError(mime_or_err)

        mime_type = mime_or_err
        with open(source_file_path, "rb") as f:
            plaintext_bytes = f.read()

        # Encrypt with AES-256-GCM
        nonce = os.urandom(12)
        aesgcm = AESGCM(dek)
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)

        file_reference = f"{uuid.uuid4().hex}.enc"
        dest_path = self._get_vault_file_path(file_reference)

        # Write [12-byte nonce] + [ciphertext]
        with open(dest_path, "wb") as f:
            f.write(nonce + ciphertext)

        self.audit.log(
            action=AuditAction.FILE_UPLOADED,
            user_id=user_id,
            details=f"Uploaded encrypted file: {original_name} ({file_size} bytes)"
        )
        logger.info(f"Encrypted and stored file {original_name} as {file_reference}")
        return file_reference, original_name, file_size, mime_type

    def read_decrypted_file_bytes(
        self,
        file_reference: str,
        dek: bytes,
        user_id: int
    ) -> bytes:
        """
        Reads and decrypts an encrypted vault file into memory.
        Logs FILE_VIEWED.
        """
        dest_path = self._get_vault_file_path(file_reference)
        if not os.path.isfile(dest_path):
            raise FileNotFoundError("Encrypted file not found in vault.")

        with open(dest_path, "rb") as f:
            payload = f.read()

        if len(payload) < 28:  # 12 nonce + 16 auth tag minimum
            raise ValueError("Corrupted encrypted file.")

        nonce = payload[:12]
        ciphertext = payload[12:]

        aesgcm = AESGCM(dek)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)

        self.audit.log(
            action=AuditAction.FILE_VIEWED,
            user_id=user_id,
            details=f"Viewed encrypted document file ({file_reference})"
        )
        return decrypted_bytes

    def export_decrypted_file(
        self,
        file_reference: str,
        destination_path: str,
        dek: bytes,
        user_id: int
    ) -> str:
        """Decrypts a vault file and writes it to an authorized export path."""
        data = self.read_decrypted_file_bytes(file_reference, dek, user_id)
        with open(destination_path, "wb") as f:
            f.write(data)
        logger.info(f"Exported decrypted file {file_reference} to {destination_path}")
        return destination_path

    def delete_vault_file(self, file_reference: str, user_id: int) -> bool:
        """Removes the encrypted physical file from the vault folder."""
        dest_path = self._get_vault_file_path(file_reference)
        deleted = False
        if os.path.isfile(dest_path):
            try:
                os.remove(dest_path)
                deleted = True
            except Exception as e:
                logger.error(f"Error deleting vault file {dest_path}: {e}")

        self.audit.log(
            action=AuditAction.FILE_DELETED,
            user_id=user_id,
            details=f"Deleted encrypted vault file ({file_reference})"
        )
        return deleted

    def attach_file_to_document(
        self,
        document_id: int,
        user_id: int,
        dek: bytes,
        source_file_path: str
    ) -> Document:
        """
        Encrypts and links a supporting file to an existing document.
        Removes any previously attached encrypted file.
        """
        doc = self.doc_service.get_document_by_id(document_id, user_id)
        if not doc:
            raise ValueError("Document not found.")

        # If previous file existed, clean it up
        if doc.file_reference:
            self.delete_vault_file(doc.file_reference, user_id)

        file_ref, orig_name, fsize, mime = self.store_encrypted_file(source_file_path, dek, user_id)

        return self.doc_service.update_document(
            document_id=document_id,
            user_id=user_id,
            dek=dek,
            doc_type=doc.document_type,
            file_reference=file_ref,
            file_original_name=orig_name,
            file_size=fsize,
            file_mime_type=mime
        )

    def detach_file_from_document(
        self,
        document_id: int,
        user_id: int,
        dek: bytes
    ) -> Document:
        """Detaches and deletes the encrypted file associated with a document."""
        doc = self.doc_service.get_document_by_id(document_id, user_id)
        if not doc:
            raise ValueError("Document not found.")

        if doc.file_reference:
            self.delete_vault_file(doc.file_reference, user_id)

        return self.doc_service.update_document(
            document_id=document_id,
            user_id=user_id,
            dek=dek,
            doc_type=doc.document_type,
            file_reference="",
            file_original_name="",
            file_size=0,
            file_mime_type=""
        )
