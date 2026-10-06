"""
Add / Edit Document modal dialog for Document Guardian.
Fields dynamically adjust based on document type (Passport vs Aadhaar vs PAN).
Strictly adheres to document-specific rules:
- Passport: Requires Issue Date and Expiry Date.
- Aadhaar / PAN: Lifetime validity (no expiry date allowed); optional review reminder date.
"""

import os
import customtkinter as ctk
from tkinter import filedialog, messagebox
from typing import Optional, Callable
from ui.theme import (
    FONT_TITLE, FONT_SUBTITLE, FONT_BODY, FONT_BODY_BOLD, FONT_SMALL,
    COLOR_PRIMARY, COLOR_PRIMARY_HOVER, COLOR_SECONDARY, COLOR_BORDER, COLOR_SURFACE,
    COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY, COLOR_STATUS_EXPIRED, COLOR_STATUS_VALID,
    CORNER_RADIUS_FORMAL, BORDER_WIDTH_FORMAL
)
from models.document import Document, DocumentType
from services.document_service import DocumentService, validate_document_input
from services.file_service import FileService, validate_file


class DocumentModal(ctk.CTkToplevel):
    """Modal dialog for adding or editing a document record."""

    def __init__(
        self,
        master,
        user_id: int,
        dek: bytes,
        doc_service: DocumentService,
        file_service: FileService,
        on_saved: Callable[[], None],
        editing_document: Optional[Document] = None,
        **kwargs
    ):
        super().__init__(master, **kwargs)
        self.user_id = user_id
        self.dek = dek
        self.doc_service = doc_service
        self.file_service = file_service
        self.on_saved = on_saved
        self.doc = editing_document
        self.is_edit = self.doc is not None

        self.selected_file_path: Optional[str] = None
        self.detach_existing_file: bool = False

        self.title("Edit Document" if self.is_edit else "Add New Document")
        self.geometry("560x650")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()

        self._build_ui()
        if self.is_edit:
            self._populate_existing()

    def _build_ui(self):
        # Outer Card
        container = ctk.CTkFrame(
            self,
            fg_color=COLOR_SURFACE,
            corner_radius=CORNER_RADIUS_FORMAL,
            border_width=BORDER_WIDTH_FORMAL,
            border_color=COLOR_BORDER
        )
        container.pack(fill="both", expand=True, padx=20, pady=20)

        # Header Title
        title_text = "Edit Document Record" if self.is_edit else "Add New Document Record"
        hdr_lbl = ctk.CTkLabel(
            container,
            text=title_text,
            font=FONT_TITLE,
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w"
        )
        hdr_lbl.pack(fill="x", padx=25, pady=(18, 5))

        sub_text = "Fill in the verified document details below."
        sub_lbl = ctk.CTkLabel(
            container,
            text=sub_text,
            font=FONT_SMALL,
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w"
        )
        sub_lbl.pack(fill="x", padx=25, pady=(0, 15))

        # Scrollable form area
        self.form_frame = ctk.CTkScrollableFrame(container, fg_color="transparent")
        self.form_frame.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        # 1. Document Type Dropdown
        ctk.CTkLabel(self.form_frame, text="Document Type *", font=FONT_BODY_BOLD, text_color=COLOR_TEXT_PRIMARY, anchor="w").pack(fill="x", pady=(4, 2))
        self.type_combo = ctk.CTkComboBox(
            self.form_frame,
            values=[DocumentType.PASSPORT.value, DocumentType.AADHAAR.value, DocumentType.PAN.value],
            height=34,
            corner_radius=CORNER_RADIUS_FORMAL,
            font=FONT_BODY,
            command=self._on_type_changed
        )
        self.type_combo.set(DocumentType.PASSPORT.value)
        self.type_combo.pack(fill="x", pady=(0, 10))

        # 2. Document Number
        self.num_lbl = ctk.CTkLabel(self.form_frame, text="Passport Number *", font=FONT_BODY_BOLD, text_color=COLOR_TEXT_PRIMARY, anchor="w")
        self.num_lbl.pack(fill="x", pady=(4, 2))

        self.num_entry = ctk.CTkEntry(
            self.form_frame,
            placeholder_text="e.g. A1234567",
            height=34,
            corner_radius=CORNER_RADIUS_FORMAL,
            font=FONT_BODY
        )
        self.num_entry.pack(fill="x", pady=(0, 10))

        # 3. Dynamic Fields Container
        self.dynamic_frame = ctk.CTkFrame(self.form_frame, fg_color="transparent")
        self.dynamic_frame.pack(fill="x", pady=0)

        # 4. Supporting File Section
        file_sec_lbl = ctk.CTkLabel(self.form_frame, text="Supporting File (Encrypted Vault)", font=FONT_BODY_BOLD, text_color=COLOR_TEXT_PRIMARY, anchor="w")
        file_sec_lbl.pack(fill="x", pady=(10, 2))

        file_picker_frame = ctk.CTkFrame(self.form_frame, fg_color=COLOR_BORDER, corner_radius=CORNER_RADIUS_FORMAL)
        file_picker_frame.pack(fill="x", pady=(0, 10))

        self.file_name_lbl = ctk.CTkLabel(
            file_picker_frame,
            text="No file selected (Optional: PDF, JPG, JPEG, PNG up to 10 MB)",
            font=FONT_SMALL,
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w"
        )
        self.file_name_lbl.pack(side="left", padx=10, pady=8, fill="x", expand=True)

        btn_browse = ctk.CTkButton(
            file_picker_frame,
            text="Choose File...",
            font=FONT_SMALL,
            height=28,
            width=90,
            fg_color=COLOR_SECONDARY,
            hover_color=COLOR_SECONDARY[0],
            corner_radius=CORNER_RADIUS_FORMAL,
            command=self._browse_file
        )
        btn_browse.pack(side="right", padx=(5, 10), pady=6)

        self.btn_clear_file = ctk.CTkButton(
            file_picker_frame,
            text="Remove",
            font=FONT_SMALL,
            height=28,
            width=70,
            fg_color="#7F1D1D",
            hover_color="#991B1B",
            corner_radius=CORNER_RADIUS_FORMAL,
            command=self._clear_selected_file
        )
        # initially not shown unless file chosen

        # Error / Status message label
        self.status_lbl = ctk.CTkLabel(
            container,
            text="",
            font=FONT_SMALL,
            text_color=COLOR_STATUS_EXPIRED,
            wraplength=480
        )
        self.status_lbl.pack(padx=20, pady=(0, 6))

        # Bottom Action Buttons
        btn_bar = ctk.CTkFrame(container, fg_color="transparent")
        btn_bar.pack(fill="x", padx=25, pady=(0, 15))

        btn_cancel = ctk.CTkButton(
            btn_bar,
            text="Cancel",
            font=FONT_BODY,
            height=34,
            width=90,
            fg_color=COLOR_SECONDARY,
            hover_color=COLOR_SECONDARY[0],
            corner_radius=CORNER_RADIUS_FORMAL,
            command=self.destroy
        )
        btn_cancel.pack(side="right", padx=(8, 0))

        btn_save = ctk.CTkButton(
            btn_bar,
            text="Save Record",
            font=FONT_BODY_BOLD,
            height=34,
            width=110,
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            corner_radius=CORNER_RADIUS_FORMAL,
            command=self._handle_save
        )
        btn_save.pack(side="right")

        # Initial field layout for Passport
        self._on_type_changed(DocumentType.PASSPORT.value)

    def _on_type_changed(self, selected_type: str):
        """Reconstructs dynamic fields when document type changes."""
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()

        if selected_type == DocumentType.PASSPORT.value:
            self.num_lbl.configure(text="Passport Number *")
            self.num_entry.configure(placeholder_text="e.g. A1234567 (1 letter + 7 digits)")

            # Issue Date
            ctk.CTkLabel(self.dynamic_frame, text="Issue Date (YYYY-MM-DD) *", font=FONT_BODY_BOLD, anchor="w").pack(fill="x", pady=(4, 2))
            self.entry_issue_date = ctk.CTkEntry(self.dynamic_frame, placeholder_text="YYYY-MM-DD", height=34, font=FONT_BODY)
            self.entry_issue_date.pack(fill="x", pady=(0, 10))

            # Expiry Date
            ctk.CTkLabel(self.dynamic_frame, text="Expiry Date (YYYY-MM-DD) *", font=FONT_BODY_BOLD, anchor="w").pack(fill="x", pady=(4, 2))
            self.entry_expiry_date = ctk.CTkEntry(self.dynamic_frame, placeholder_text="YYYY-MM-DD", height=34, font=FONT_BODY)
            self.entry_expiry_date.pack(fill="x", pady=(0, 10))

            # Reminder Window
            ctk.CTkLabel(self.dynamic_frame, text="Reminder Period (Days before expiry) *", font=FONT_BODY_BOLD, anchor="w").pack(fill="x", pady=(4, 2))
            self.combo_reminder_days = ctk.CTkComboBox(
                self.dynamic_frame,
                values=["180", "90", "60", "30"],
                height=34,
                font=FONT_BODY
            )
            self.combo_reminder_days.set("180")
            self.combo_reminder_days.pack(fill="x", pady=(0, 10))

            self.entry_review_date = None

        elif selected_type == DocumentType.AADHAAR.value:
            self.num_lbl.configure(text="Aadhaar Number *")
            self.num_entry.configure(placeholder_text="12-digit number e.g. 1234 5678 9012")

            # Notice that Aadhaar does not expire
            notice_box = ctk.CTkFrame(self.dynamic_frame, fg_color=COLOR_BORDER, corner_radius=CORNER_RADIUS_FORMAL)
            notice_box.pack(fill="x", pady=(4, 10))
            ctk.CTkLabel(
                notice_box,
                text="Aadhaar cards have lifetime validity and do not expire. You may schedule an optional review reminder.",
                font=FONT_SMALL,
                text_color=COLOR_TEXT_PRIMARY,
                wraplength=460
            ).pack(padx=10, pady=8)

            # Optional Review Reminder Date
            ctk.CTkLabel(self.dynamic_frame, text="Optional Review / Update Reminder Date (YYYY-MM-DD)", font=FONT_BODY_BOLD, anchor="w").pack(fill="x", pady=(4, 2))
            self.entry_review_date = ctk.CTkEntry(self.dynamic_frame, placeholder_text="Optional (YYYY-MM-DD)", height=34, font=FONT_BODY)
            self.entry_review_date.pack(fill="x", pady=(0, 10))

            # Reminder Period
            ctk.CTkLabel(self.dynamic_frame, text="Review Reminder Notice (Days before review)", font=FONT_BODY_BOLD, anchor="w").pack(fill="x", pady=(4, 2))
            self.combo_reminder_days = ctk.CTkComboBox(
                self.dynamic_frame,
                values=["30", "60", "90"],
                height=34,
                font=FONT_BODY
            )
            self.combo_reminder_days.set("30")
            self.combo_reminder_days.pack(fill="x", pady=(0, 10))

            self.entry_issue_date = None
            self.entry_expiry_date = None

        elif selected_type == DocumentType.PAN.value:
            self.num_lbl.configure(text="PAN Number *")
            self.num_entry.configure(placeholder_text="10 characters e.g. ABCDE1234F")

            # Notice that PAN does not expire
            notice_box = ctk.CTkFrame(self.dynamic_frame, fg_color=COLOR_BORDER, corner_radius=CORNER_RADIUS_FORMAL)
            notice_box.pack(fill="x", pady=(4, 10))
            ctk.CTkLabel(
                notice_box,
                text="Permanent Account Numbers (PAN) do not expire. You may schedule an optional review reminder.",
                font=FONT_SMALL,
                text_color=COLOR_TEXT_PRIMARY,
                wraplength=460
            ).pack(padx=10, pady=8)

            # Optional Review Reminder Date
            ctk.CTkLabel(self.dynamic_frame, text="Optional Review / Verification Reminder Date (YYYY-MM-DD)", font=FONT_BODY_BOLD, anchor="w").pack(fill="x", pady=(4, 2))
            self.entry_review_date = ctk.CTkEntry(self.dynamic_frame, placeholder_text="Optional (YYYY-MM-DD)", height=34, font=FONT_BODY)
            self.entry_review_date.pack(fill="x", pady=(0, 10))

            # Reminder Period
            ctk.CTkLabel(self.dynamic_frame, text="Review Reminder Notice (Days before review)", font=FONT_BODY_BOLD, anchor="w").pack(fill="x", pady=(4, 2))
            self.combo_reminder_days = ctk.CTkComboBox(
                self.dynamic_frame,
                values=["30", "60", "90"],
                height=34,
                font=FONT_BODY
            )
            self.combo_reminder_days.set("30")
            self.combo_reminder_days.pack(fill="x", pady=(0, 10))

            self.entry_issue_date = None
            self.entry_expiry_date = None

    def _populate_existing(self):
        """Fills form with existing document details."""
        if not self.doc:
            return

        self.type_combo.set(self.doc.document_type)
        self._on_type_changed(self.doc.document_type)
        self.type_combo.configure(state="disabled")  # Type cannot be changed during edit

        # Decrypt document number
        try:
            raw_number = self.doc_service.decrypt_document_number(self.doc, self.dek)
            self.num_entry.insert(0, raw_number)
        except Exception:
            self.num_entry.insert(0, self.doc.document_number_masked)

        if self.doc.document_type == DocumentType.PASSPORT.value:
            if self.doc.issue_date and self.entry_issue_date:
                self.entry_issue_date.insert(0, self.doc.issue_date)
            if self.doc.expiry_date and self.entry_expiry_date:
                self.entry_expiry_date.insert(0, self.doc.expiry_date)
            if self.combo_reminder_days:
                self.combo_reminder_days.set(str(self.doc.reminder_days))
        else:
            if self.doc.reminder_date and self.entry_review_date:
                self.entry_review_date.insert(0, self.doc.reminder_date)
            if self.combo_reminder_days:
                self.combo_reminder_days.set(str(self.doc.reminder_days))

        if self.doc.file_reference:
            self.file_name_lbl.configure(text=f"Attached: {self.doc.file_original_name} (Encrypted)")
            self.btn_clear_file.pack(side="right", padx=5)

    def _browse_file(self):
        chosen = filedialog.askopenfilename(
            title="Select Supporting Document (PDF or Image)",
            filetypes=[("PDF and Images", "*.pdf;*.jpg;*.jpeg;*.png")]
        )
        if chosen:
            ok, err_or_mime, fsize, fname = validate_file(chosen)
            if not ok:
                messagebox.showerror("Invalid File", err_or_mime)
                return
            self.selected_file_path = chosen
            self.detach_existing_file = False
            mb_size = fsize / (1024 * 1024)
            self.file_name_lbl.configure(text=f"Selected: {fname} ({mb_size:.2f} MB)")
            self.btn_clear_file.pack(side="right", padx=5)

    def _clear_selected_file(self):
        self.selected_file_path = None
        self.detach_existing_file = True
        self.file_name_lbl.configure(text="No file selected")
        self.btn_clear_file.pack_forget()

    def _handle_save(self):
        doc_type = self.type_combo.get()
        doc_number = self.num_entry.get().strip()

        issue_date = self.entry_issue_date.get().strip() if self.entry_issue_date else None
        expiry_date = self.entry_expiry_date.get().strip() if self.entry_expiry_date else None
        reminder_date = self.entry_review_date.get().strip() if self.entry_review_date else None

        # Clean empty strings to None
        issue_date = issue_date if issue_date else None
        expiry_date = expiry_date if expiry_date else None
        reminder_date = reminder_date if reminder_date else None

        reminder_days = int(self.combo_reminder_days.get() or "180")

        # Validate inputs
        ok, issues = validate_document_input(
            doc_type=doc_type,
            doc_number=doc_number,
            issue_date=issue_date,
            expiry_date=expiry_date,
            reminder_date=reminder_date,
            reminder_days=reminder_days
        )
        if not ok:
            self.status_lbl.configure(text="Error: " + " ".join(issues), text_color=COLOR_STATUS_EXPIRED)
            return

        try:
            if not self.is_edit:
                # Add mode
                new_doc = self.doc_service.add_document(
                    user_id=self.user_id,
                    dek=self.dek,
                    doc_type=doc_type,
                    doc_number=doc_number,
                    issue_date=issue_date,
                    expiry_date=expiry_date,
                    reminder_date=reminder_date,
                    reminder_days=reminder_days
                )

                # Attach file if selected
                if self.selected_file_path:
                    self.file_service.attach_file_to_document(
                        document_id=new_doc.document_id,
                        user_id=self.user_id,
                        dek=self.dek,
                        source_file_path=self.selected_file_path
                    )
            else:
                # Edit mode
                self.doc_service.update_document(
                    document_id=self.doc.document_id,
                    user_id=self.user_id,
                    dek=self.dek,
                    doc_type=doc_type,
                    doc_number=doc_number,
                    issue_date=issue_date,
                    expiry_date=expiry_date,
                    reminder_date=reminder_date,
                    reminder_days=reminder_days
                )

                if self.detach_existing_file and self.doc.file_reference:
                    self.file_service.detach_file_from_document(
                        document_id=self.doc.document_id,
                        user_id=self.user_id,
                        dek=self.dek
                    )
                elif self.selected_file_path:
                    self.file_service.attach_file_to_document(
                        document_id=self.doc.document_id,
                        user_id=self.user_id,
                        dek=self.dek,
                        source_file_path=self.selected_file_path
                    )

            self.on_saved()
            self.destroy()

        except Exception as e:
            self.status_lbl.configure(text=f"Save failed: {str(e)}", text_color=COLOR_STATUS_EXPIRED)
