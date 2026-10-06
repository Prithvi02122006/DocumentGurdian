"""
My Documents table view for Document Guardian.
Lists user documents in a formal, information-first data table with search,
type filtering, status filtering, and actions (View, Edit, Delete).
"""

import customtkinter as ctk
from typing import Callable, Optional, List
from tkinter import messagebox
from ui.theme import (
    FONT_TITLE, FONT_SUBTITLE, FONT_BODY, FONT_BODY_BOLD, FONT_SMALL,
    COLOR_PRIMARY, COLOR_PRIMARY_HOVER, COLOR_SECONDARY, COLOR_BORDER, COLOR_SURFACE,
    COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY, COLOR_STATUS_VALID, COLOR_STATUS_ATTENTION,
    COLOR_STATUS_EXPIRED, COLOR_STATUS_REVIEW, CORNER_RADIUS_FORMAL, BORDER_WIDTH_FORMAL
)
from services.document_service import DocumentService
from models.document import Document, DocumentStatus, DocumentType


class DocumentsFrame(ctk.CTkFrame):
    """My Documents section featuring formal data table and search/filter controls."""

    def __init__(
        self,
        master,
        document_service: DocumentService,
        on_add_document: Callable[[], None],
        on_edit_document: Callable[[Document], None],
        on_view_document: Callable[[Document], None],
        **kwargs
    ):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.doc_service = document_service
        self.on_add_document = on_add_document
        self.on_edit_document = on_edit_document
        self.on_view_document = on_view_document
        self.user_id: Optional[int] = None

        self._build_ui()

    def _build_ui(self):
        # 1. Page Header Bar
        header_bar = ctk.CTkFrame(self, fg_color="transparent")
        header_bar.pack(fill="x", padx=25, pady=(15, 10))

        title_lbl = ctk.CTkLabel(
            header_bar,
            text="MY DOCUMENTS",
            font=FONT_TITLE,
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w"
        )
        title_lbl.pack(side="left")

        btn_add = ctk.CTkButton(
            header_bar,
            text="+ Add Document",
            font=FONT_BODY_BOLD,
            height=32,
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            corner_radius=CORNER_RADIUS_FORMAL,
            command=self.on_add_document
        )
        btn_add.pack(side="right")

        # 2. Search & Filter Bar
        filter_bar = ctk.CTkFrame(
            self,
            fg_color=COLOR_SURFACE,
            corner_radius=CORNER_RADIUS_FORMAL,
            border_width=BORDER_WIDTH_FORMAL,
            border_color=COLOR_BORDER
        )
        filter_bar.pack(fill="x", padx=25, pady=(0, 15))

        # Search entry
        self.search_entry = ctk.CTkEntry(
            filter_bar,
            placeholder_text="Search by number, filename, or type...",
            height=32,
            width=280,
            corner_radius=CORNER_RADIUS_FORMAL,
            font=FONT_BODY
        )
        self.search_entry.pack(side="left", padx=(12, 10), pady=10)
        self.search_entry.bind("<KeyRelease>", lambda event: self.refresh())

        # Type filter dropdown
        ctk.CTkLabel(filter_bar, text="Type:", font=FONT_SMALL, text_color=COLOR_TEXT_SECONDARY).pack(side="left", padx=(5, 4))
        self.type_filter = ctk.CTkComboBox(
            filter_bar,
            values=["All Types", "Passport", "Aadhaar", "PAN"],
            width=130,
            height=32,
            corner_radius=CORNER_RADIUS_FORMAL,
            font=FONT_BODY,
            command=lambda val: self.refresh()
        )
        self.type_filter.set("All Types")
        self.type_filter.pack(side="left", padx=(0, 12))

        # Status filter dropdown
        ctk.CTkLabel(filter_bar, text="Status:", font=FONT_SMALL, text_color=COLOR_TEXT_SECONDARY).pack(side="left", padx=(5, 4))
        self.status_filter = ctk.CTkComboBox(
            filter_bar,
            values=["All Statuses", "Valid", "Attention Required", "Expired", "Review Due"],
            width=150,
            height=32,
            corner_radius=CORNER_RADIUS_FORMAL,
            font=FONT_BODY,
            command=lambda val: self.refresh()
        )
        self.status_filter.set("All Statuses")
        self.status_filter.pack(side="left", padx=(0, 12))

        btn_clear = ctk.CTkButton(
            filter_bar,
            text="Reset Filters",
            font=FONT_SMALL,
            width=90,
            height=30,
            fg_color=COLOR_SECONDARY,
            hover_color=COLOR_SECONDARY[0],
            corner_radius=CORNER_RADIUS_FORMAL,
            command=self._reset_filters
        )
        btn_clear.pack(side="right", padx=(0, 12), pady=10)

        # 3. Documents Data Table Container
        self.table_card = ctk.CTkFrame(
            self,
            fg_color=COLOR_SURFACE,
            corner_radius=CORNER_RADIUS_FORMAL,
            border_width=BORDER_WIDTH_FORMAL,
            border_color=COLOR_BORDER
        )
        self.table_card.pack(fill="both", expand=True, padx=25, pady=(0, 20))

        # Table Header
        tbl_hdr = ctk.CTkFrame(self.table_card, fg_color=COLOR_BORDER, corner_radius=0, height=34)
        tbl_hdr.pack(fill="x", padx=0, pady=0)

        ctk.CTkLabel(tbl_hdr, text="Document Type", font=FONT_BODY_BOLD, width=120, anchor="w").pack(side="left", padx=(15, 5), pady=7)
        ctk.CTkLabel(tbl_hdr, text="Masked Number", font=FONT_BODY_BOLD, width=160, anchor="w").pack(side="left", padx=5, pady=7)
        ctk.CTkLabel(tbl_hdr, text="Relevant Date", font=FONT_BODY_BOLD, width=130, anchor="w").pack(side="left", padx=5, pady=7)
        ctk.CTkLabel(tbl_hdr, text="Status", font=FONT_BODY_BOLD, width=150, anchor="w").pack(side="left", padx=5, pady=7)
        ctk.CTkLabel(tbl_hdr, text="Attachment", font=FONT_BODY_BOLD, width=130, anchor="w").pack(side="left", padx=5, pady=7)
        ctk.CTkLabel(tbl_hdr, text="Actions", font=FONT_BODY_BOLD, width=190, anchor="e").pack(side="right", padx=(5, 15), pady=7)

        # Scrollable Rows
        self.rows_frame = ctk.CTkScrollableFrame(self.table_card, fg_color="transparent")
        self.rows_frame.pack(fill="both", expand=True, padx=0, pady=0)

    def load_user(self, user_id: int):
        self.user_id = user_id
        self.refresh()

    def _reset_filters(self):
        self.search_entry.delete(0, "end")
        self.type_filter.set("All Types")
        self.status_filter.set("All Statuses")
        self.refresh()

    def refresh(self):
        """Fetches and displays documents matching active filters."""
        if not self.user_id:
            return

        search_q = self.search_entry.get().strip()
        type_val = self.type_filter.get()
        doc_type = None if type_val == "All Types" else type_val

        status_val = self.status_filter.get()
        status_filter = None if status_val == "All Statuses" else status_val

        docs: List[Document] = self.doc_service.get_documents(
            user_id=self.user_id,
            doc_type=doc_type,
            status_filter=status_filter,
            search_query=search_q if search_q else None
        )

        for widget in self.rows_frame.winfo_children():
            widget.destroy()

        if not docs:
            empty_lbl = ctk.CTkLabel(
                self.rows_frame,
                text="No documents found matching the search and filter criteria.",
                font=FONT_BODY,
                text_color=COLOR_TEXT_SECONDARY,
                anchor="center"
            )
            empty_lbl.pack(fill="x", pady=40)
            return

        for idx, doc in enumerate(docs):
            self._render_row(doc, idx)

    def _render_row(self, doc: Document, idx: int):
        row_bg = COLOR_SURFACE if idx % 2 == 0 else COLOR_BORDER
        row_frame = ctk.CTkFrame(self.rows_frame, fg_color=row_bg, corner_radius=0, height=42)
        row_frame.pack(fill="x", padx=0, pady=1)

        # Relevant date display
        if doc.document_type == DocumentType.PASSPORT:
            date_str = f"Exp: {doc.expiry_date}" if doc.expiry_date else "N/A"
        else:
            date_str = f"Rev: {doc.reminder_date}" if doc.reminder_date else "Lifetime (No review)"

        # Status text color
        status_val = doc.status
        if status_val == DocumentStatus.EXPIRED:
            s_color = COLOR_STATUS_EXPIRED
        elif status_val in (DocumentStatus.ATTENTION_REQUIRED, DocumentStatus.REVIEW_DUE):
            s_color = COLOR_STATUS_ATTENTION
        else:
            s_color = COLOR_STATUS_VALID

        ctk.CTkLabel(row_frame, text=doc.document_type, font=FONT_BODY_BOLD, width=120, anchor="w").pack(side="left", padx=(15, 5))
        ctk.CTkLabel(row_frame, text=doc.document_number_masked, font=FONT_BODY, width=160, anchor="w").pack(side="left", padx=5)
        ctk.CTkLabel(row_frame, text=date_str, font=FONT_BODY, width=130, anchor="w").pack(side="left", padx=5)
        ctk.CTkLabel(row_frame, text=status_val.value, font=FONT_BODY_BOLD, text_color=s_color, width=150, anchor="w").pack(side="left", padx=5)

        attachment_text = doc.file_original_name if doc.file_reference else "None"
        if len(attachment_text) > 16:
            attachment_text = attachment_text[:14] + "..."
        ctk.CTkLabel(row_frame, text=attachment_text, font=FONT_SMALL, text_color=COLOR_TEXT_SECONDARY, width=130, anchor="w").pack(side="left", padx=5)

        # Actions Frame on Right
        act_frame = ctk.CTkFrame(row_frame, fg_color="transparent")
        act_frame.pack(side="right", padx=(5, 15), pady=6)

        # Delete Action
        btn_del = ctk.CTkButton(
            act_frame,
            text="Delete",
            font=FONT_SMALL,
            width=55,
            height=26,
            fg_color="#7F1D1D",
            hover_color="#991B1B",
            corner_radius=CORNER_RADIUS_FORMAL,
            command=lambda d=doc: self._handle_delete(d)
        )
        btn_del.pack(side="right", padx=2)

        # Edit Action
        btn_edit = ctk.CTkButton(
            act_frame,
            text="Edit",
            font=FONT_SMALL,
            width=50,
            height=26,
            fg_color=COLOR_SECONDARY,
            hover_color=COLOR_SECONDARY_HOVER[0],
            corner_radius=CORNER_RADIUS_FORMAL,
            command=lambda d=doc: self.on_edit_document(d)
        )
        btn_edit.pack(side="right", padx=2)

        # View Action
        btn_view = ctk.CTkButton(
            act_frame,
            text="View",
            font=FONT_SMALL,
            width=50,
            height=26,
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            corner_radius=CORNER_RADIUS_FORMAL,
            command=lambda d=doc: self.on_view_document(d)
        )
        btn_view.pack(side="right", padx=2)

    def _handle_delete(self, doc: Document):
        """Prompts for confirmation before deleting."""
        confirm = messagebox.askyesno(
            title="Confirm Deletion",
            message=(
                f"Are you sure you want to permanently delete this {doc.document_type} record "
                f"({doc.document_number_masked})?\n\n"
                f"Any associated encrypted vault files will also be permanently removed."
            )
        )
        if confirm:
            try:
                self.doc_service.delete_document(doc.document_id, self.user_id)
                self.refresh()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete document: {e}")
