"""
View Document modal dialog for Document Guardian.
Allows authorized users to inspect decrypted document details, copy numbers,
and export/view attached vault files securely.
"""

import os
import customtkinter as ctk
from tkinter import filedialog, messagebox
from typing import Optional
from ui.theme import (
    FONT_TITLE, FONT_SUBTITLE, FONT_BODY, FONT_BODY_BOLD, FONT_SMALL, FONT_MONO,
    COLOR_PRIMARY, COLOR_PRIMARY_HOVER, COLOR_SECONDARY, COLOR_BORDER, COLOR_SURFACE,
    COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY, COLOR_STATUS_VALID, COLOR_STATUS_ATTENTION,
    COLOR_STATUS_EXPIRED, CORNER_RADIUS_FORMAL, BORDER_WIDTH_FORMAL
)
from models.document import Document, DocumentStatus, DocumentType
from services.document_service import DocumentService
from services.file_service import FileService


class ViewDocumentModal(ctk.CTkToplevel):
    """Modal dialog displaying verified document information."""

    def __init__(
        self,
        master,
        document: Document,
        user_id: int,
        dek: bytes,
        doc_service: DocumentService,
        file_service: FileService,
        **kwargs
    ):
        super().__init__(master, **kwargs)
        self.doc = document
        self.user_id = user_id
        self.dek = dek
        self.doc_service = doc_service
        self.file_service = file_service

        self.title(f"Document Details - {self.doc.document_type}")
        self.geometry("540x580")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()

        self._build_ui()

    def _build_ui(self):
        container = ctk.CTkFrame(
            self,
            fg_color=COLOR_SURFACE,
            corner_radius=CORNER_RADIUS_FORMAL,
            border_width=BORDER_WIDTH_FORMAL,
            border_color=COLOR_BORDER
        )
        container.pack(fill="both", expand=True, padx=20, pady=20)

        # Header Title & Status
        hdr_frame = ctk.CTkFrame(container, fg_color="transparent")
        hdr_frame.pack(fill="x", padx=20, pady=(15, 10))

        title_lbl = ctk.CTkLabel(
            hdr_frame,
            text=f"{self.doc.document_type.upper()} RECORD",
            font=FONT_TITLE,
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w"
        )
        title_lbl.pack(side="left")

        # Status badge
        status = self.doc.status
        if status == DocumentStatus.EXPIRED:
            s_color = COLOR_STATUS_EXPIRED
        elif status in (DocumentStatus.ATTENTION_REQUIRED, DocumentStatus.REVIEW_DUE):
            s_color = COLOR_STATUS_ATTENTION
        else:
            s_color = COLOR_STATUS_VALID

        badge = ctk.CTkLabel(
            hdr_frame,
            text=f"[{status.value.upper()}]",
            font=FONT_BODY_BOLD,
            text_color=s_color
        )
        badge.pack(side="right")

        # Info Box
        info_box = ctk.CTkFrame(container, fg_color=COLOR_BORDER, corner_radius=CORNER_RADIUS_FORMAL)
        info_box.pack(fill="x", padx=20, pady=(0, 15))

        # Decrypt document number
        try:
            full_number = self.doc_service.decrypt_document_number(self.doc, self.dek)
        except Exception:
            full_number = self.doc.document_number_masked

        self._add_detail_row(info_box, "Document Type:", self.doc.document_type)
        self._add_detail_row(info_box, "Document Number:", full_number, is_mono=True)
        self._add_detail_row(info_box, "Masked Display:", self.doc.document_number_masked)

        if self.doc.document_type == DocumentType.PASSPORT.value:
            self._add_detail_row(info_box, "Issue Date:", self.doc.issue_date or "N/A")
            self._add_detail_row(info_box, "Expiry Date:", self.doc.expiry_date or "N/A")
            self._add_detail_row(info_box, "Reminder Window:", f"{self.doc.reminder_days} days before expiry")
        else:
            self._add_detail_row(info_box, "Validity:", "Lifetime Validity (Does not expire)")
            self._add_detail_row(info_box, "Review Reminder Date:", self.doc.reminder_date or "Not scheduled")

        self._add_detail_row(info_box, "Record Created:", self.doc.created_at[:10] if self.doc.created_at else "N/A")
        self._add_detail_row(info_box, "Last Updated:", self.doc.updated_at[:10] if self.doc.updated_at else "N/A")

        # Supporting Attachment Section
        att_frame = ctk.CTkFrame(container, fg_color="transparent")
        att_frame.pack(fill="x", padx=20, pady=(0, 15))

        att_title = ctk.CTkLabel(att_frame, text="Supporting Attachment (Vault File)", font=FONT_BODY_BOLD, anchor="w")
        att_title.pack(fill="x", pady=(0, 4))

        if self.doc.file_reference:
            file_box = ctk.CTkFrame(att_frame, fg_color=COLOR_BORDER, corner_radius=CORNER_RADIUS_FORMAL)
            file_box.pack(fill="x", pady=2)

            f_size_kb = (self.doc.file_size or 0) / 1024
            file_desc = f"{self.doc.file_original_name} ({f_size_kb:.1f} KB - AES-256-GCM Encrypted)"
            ctk.CTkLabel(file_box, text=file_desc, font=FONT_SMALL, text_color=COLOR_TEXT_PRIMARY).pack(side="left", padx=10, pady=8)

            btn_export = ctk.CTkButton(
                file_box,
                text="Export Copy",
                font=FONT_SMALL,
                height=26,
                width=80,
                fg_color=COLOR_PRIMARY,
                hover_color=COLOR_PRIMARY_HOVER,
                corner_radius=CORNER_RADIUS_FORMAL,
                command=self._handle_export_file
            )
            btn_export.pack(side="right", padx=10, pady=6)
        else:
            ctk.CTkLabel(att_frame, text="No supporting digital file uploaded for this record.", font=FONT_SMALL, text_color=COLOR_TEXT_SECONDARY, anchor="w").pack(fill="x")

        # Close Button
        btn_close = ctk.CTkButton(
            container,
            text="Close",
            font=FONT_BODY,
            height=34,
            width=90,
            fg_color=COLOR_SECONDARY,
            hover_color=COLOR_SECONDARY[0],
            corner_radius=CORNER_RADIUS_FORMAL,
            command=self.destroy
        )
        btn_close.pack(side="right", padx=20, pady=(5, 15))

    def _add_detail_row(self, parent, label: str, value: str, is_mono: bool = False):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=4)

        ctk.CTkLabel(row, text=label, font=FONT_BODY_BOLD, text_color=COLOR_TEXT_SECONDARY, width=150, anchor="w").pack(side="left")
        ctk.CTkLabel(row, text=value, font=FONT_MONO if is_mono else FONT_BODY, text_color=COLOR_TEXT_PRIMARY, anchor="w").pack(side="left", fill="x", expand=True)

    def _handle_export_file(self):
        """Allows user to decrypt and save a local copy of their attached file."""
        if not self.doc.file_reference:
            return

        orig_ext = os.path.splitext(self.doc.file_original_name or "file.pdf")[1]
        dest = filedialog.asksaveasfilename(
            title="Export Decrypted Document Copy",
            initialfile=self.doc.file_original_name or f"exported_doc{orig_ext}",
            defaultextension=orig_ext,
            filetypes=[("Original File Format", f"*{orig_ext}"), ("All Files", "*.*")]
        )
        if dest:
            try:
                self.file_service.export_decrypted_file(
                    file_reference=self.doc.file_reference,
                    destination_path=dest,
                    dek=self.dek,
                    user_id=self.user_id
                )
                messagebox.showinfo("Export Successful", f"Decrypted file successfully saved to:\n{dest}")
            except Exception as e:
                messagebox.showerror("Export Failed", f"Could not export file: {str(e)}")
