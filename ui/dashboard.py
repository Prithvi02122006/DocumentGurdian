"""
Dashboard view for Document Guardian.
Presents formal summary statistics and the Documents Requiring Attention table.
Strictly avoids flashy cards, gradients, or glowing elements.
"""

import customtkinter as ctk
from typing import Callable, Optional
from ui.theme import (
    FONT_FAMILY, FONT_TITLE, FONT_SUBTITLE, FONT_SECTION, FONT_BODY, FONT_BODY_BOLD, FONT_SMALL,
    COLOR_PRIMARY, COLOR_PRIMARY_HOVER, COLOR_SECONDARY, COLOR_BORDER, COLOR_SURFACE,
    COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY, COLOR_STATUS_VALID, COLOR_STATUS_ATTENTION,
    COLOR_STATUS_EXPIRED, COLOR_STATUS_REVIEW, CORNER_RADIUS_FORMAL, BORDER_WIDTH_FORMAL
)
from services.expiry_service import ExpiryService, DashboardSummary, DocumentExpiryInfo
from models.document import DocumentStatus


class DashboardFrame(ctk.CTkFrame):
    """Formal information-first dashboard view."""

    def __init__(
        self,
        master,
        expiry_service: ExpiryService,
        on_navigate_to_doc: Callable[[int], None],
        on_add_doc: Callable[[], None],
        **kwargs
    ):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.expiry_service = expiry_service
        self.on_navigate_to_doc = on_navigate_to_doc
        self.on_add_doc = on_add_doc
        self.user_id: Optional[int] = None

        self._build_ui()

    def _build_ui(self):
        # 1. Page Header
        header_bar = ctk.CTkFrame(self, fg_color="transparent")
        header_bar.pack(fill="x", padx=25, pady=(15, 10))

        title_lbl = ctk.CTkLabel(
            header_bar,
            text="SYSTEM DASHBOARD",
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
            command=self.on_add_doc
        )
        btn_add.pack(side="right", padx=(10, 0))

        btn_refresh = ctk.CTkButton(
            header_bar,
            text="Refresh",
            font=FONT_BODY,
            height=32,
            width=80,
            fg_color=COLOR_SECONDARY,
            hover_color=COLOR_SECONDARY[0],
            corner_radius=CORNER_RADIUS_FORMAL,
            command=self.refresh
        )
        btn_refresh.pack(side="right")

        # 2. Modern Summary Metrics Panel (Individual rounded KPI cards)
        self.stats_container = ctk.CTkFrame(self, fg_color="transparent")
        self.stats_container.pack(fill="x", padx=25, pady=(0, 15))

        self.lbl_stat_total = self._create_stat_cell(self.stats_container, "Total Documents", "0", 0, None, "📄")
        self.lbl_stat_valid = self._create_stat_cell(self.stats_container, "Valid", "0", 1, COLOR_STATUS_VALID, "🟢")
        self.lbl_stat_attention = self._create_stat_cell(self.stats_container, "Attention Required", "0", 2, COLOR_STATUS_ATTENTION, "⚠️")
        self.lbl_stat_review = self._create_stat_cell(self.stats_container, "Review Due", "0", 3, COLOR_STATUS_REVIEW, "🔄")
        self.lbl_stat_expired = self._create_stat_cell(self.stats_container, "Expired", "0", 4, COLOR_STATUS_EXPIRED, "🔴")

        # 3. Documents Requiring Attention Section
        sec_bar = ctk.CTkFrame(self, fg_color="transparent")
        sec_bar.pack(fill="x", padx=25, pady=(10, 5))

        sec_lbl = ctk.CTkLabel(
            sec_bar,
            text="Documents Requiring Attention",
            font=FONT_SUBTITLE,
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w"
        )
        sec_lbl.pack(side="left")

        sec_sub = ctk.CTkLabel(
            self,
            text="Records below require periodic review, renewal, or updated details.",
            font=FONT_SMALL,
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w"
        )
        sec_sub.pack(fill="x", padx=25, pady=(0, 8))

        # Table container
        self.table_card = ctk.CTkFrame(
            self,
            fg_color=COLOR_SURFACE,
            corner_radius=CORNER_RADIUS_FORMAL,
            border_width=BORDER_WIDTH_FORMAL,
            border_color=COLOR_BORDER
        )
        self.table_card.pack(fill="both", expand=True, padx=25, pady=(0, 20))

        # Table Header Row
        tbl_hdr = ctk.CTkFrame(self.table_card, fg_color=COLOR_BORDER, corner_radius=0, height=32)
        tbl_hdr.pack(fill="x", padx=0, pady=0)

        ctk.CTkLabel(tbl_hdr, text="Document", font=FONT_BODY_BOLD, width=120, anchor="w").pack(side="left", padx=(15, 5), pady=6)
        ctk.CTkLabel(tbl_hdr, text="Masked Number", font=FONT_BODY_BOLD, width=150, anchor="w").pack(side="left", padx=5, pady=6)
        ctk.CTkLabel(tbl_hdr, text="Milestone", font=FONT_BODY_BOLD, width=120, anchor="w").pack(side="left", padx=5, pady=6)
        ctk.CTkLabel(tbl_hdr, text="Status", font=FONT_BODY_BOLD, width=150, anchor="w").pack(side="left", padx=5, pady=6)
        ctk.CTkLabel(tbl_hdr, text="Details", font=FONT_BODY_BOLD, width=220, anchor="w").pack(side="left", padx=5, pady=6)
        ctk.CTkLabel(tbl_hdr, text="Action", font=FONT_BODY_BOLD, width=90, anchor="e").pack(side="right", padx=(5, 15), pady=6)

        # Scrollable rows frame
        self.rows_frame = ctk.CTkScrollableFrame(self.table_card, fg_color="transparent")
        self.rows_frame.pack(fill="both", expand=True, padx=0, pady=0)

    def _create_stat_cell(self, parent, label_text: str, value_text: str, col_idx: int, color_val=None, icon: str = "📄"):
        card = ctk.CTkFrame(
            parent,
            fg_color=COLOR_SURFACE,
            corner_radius=10,
            border_width=BORDER_WIDTH_FORMAL,
            border_color=COLOR_BORDER
        )
        card.grid(row=0, column=col_idx, sticky="nsew", padx=5, pady=4)
        parent.grid_columnconfigure(col_idx, weight=1)

        val_color = color_val if color_val else COLOR_TEXT_PRIMARY

        hdr_frame = ctk.CTkFrame(card, fg_color="transparent")
        hdr_frame.pack(fill="x", padx=12, pady=(10, 2))

        ctk.CTkLabel(hdr_frame, text=icon, font=(FONT_FAMILY, 13)).pack(side="left")
        txt_lbl = ctk.CTkLabel(
            hdr_frame,
            text=f" {label_text.upper()}",
            font=(FONT_FAMILY, 9, "bold"),
            text_color=COLOR_TEXT_SECONDARY
        )
        txt_lbl.pack(side="left")

        val_lbl = ctk.CTkLabel(
            card,
            text=value_text,
            font=(FONT_FAMILY, 22, "bold"),
            text_color=val_color
        )
        val_lbl.pack(anchor="w", padx=14, pady=(2, 10))

        return val_lbl

    def load_user(self, user_id: int):
        """Loads data for active user."""
        self.user_id = user_id
        self.refresh()

    def refresh(self):
        """Refreshes summary statistics and attention table."""
        if not self.user_id:
            return

        summary: DashboardSummary = self.expiry_service.get_user_dashboard_summary(self.user_id)

        # Update metric labels
        self.lbl_stat_total.configure(text=str(summary.total_documents))
        self.lbl_stat_valid.configure(text=str(summary.valid_count))
        self.lbl_stat_attention.configure(text=str(summary.attention_count))
        self.lbl_stat_review.configure(text=str(summary.review_due_count))
        self.lbl_stat_expired.configure(text=str(summary.expired_count))

        # Clear existing rows
        for widget in self.rows_frame.winfo_children():
            widget.destroy()

        if not summary.attention_documents:
            empty_lbl = ctk.CTkLabel(
                self.rows_frame,
                text="No documents currently require attention. All records are up to date.",
                font=FONT_BODY,
                text_color=COLOR_STATUS_VALID,
                anchor="center"
            )
            empty_lbl.pack(fill="x", pady=40)
            return

        # Populate rows
        for idx, item in enumerate(summary.attention_documents):
            self._render_row(item, idx)

    def _render_row(self, item: DocumentExpiryInfo, idx: int):
        doc = item.document
        row_bg = COLOR_SURFACE if idx % 2 == 0 else COLOR_BORDER
        row_frame = ctk.CTkFrame(self.rows_frame, fg_color=row_bg, corner_radius=0, height=40)
        row_frame.pack(fill="x", padx=0, pady=1)

        # Status text color
        if item.status == DocumentStatus.EXPIRED:
            status_color = COLOR_STATUS_EXPIRED
        elif item.status in (DocumentStatus.ATTENTION_REQUIRED, DocumentStatus.REVIEW_DUE):
            status_color = COLOR_STATUS_ATTENTION
        else:
            status_color = COLOR_STATUS_VALID

        ctk.CTkLabel(row_frame, text=doc.document_type, font=FONT_BODY_BOLD, width=120, anchor="w").pack(side="left", padx=(15, 5))
        ctk.CTkLabel(row_frame, text=doc.document_number_masked, font=FONT_BODY, width=150, anchor="w").pack(side="left", padx=5)
        ctk.CTkLabel(row_frame, text=item.relevant_date or "N/A", font=FONT_BODY, width=120, anchor="w").pack(side="left", padx=5)
        ctk.CTkLabel(row_frame, text=item.status.value, font=FONT_BODY_BOLD, text_color=status_color, width=150, anchor="w").pack(side="left", padx=5)
        ctk.CTkLabel(row_frame, text=item.days_remaining_display, font=FONT_BODY, text_color=COLOR_TEXT_SECONDARY, width=220, anchor="w").pack(side="left", padx=5)

        btn_view = ctk.CTkButton(
            row_frame,
            text="View",
            font=FONT_SMALL,
            width=70,
            height=26,
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            corner_radius=CORNER_RADIUS_FORMAL,
            command=lambda d_id=doc.document_id: self.on_navigate_to_doc(d_id)
        )
        btn_view.pack(side="right", padx=(5, 15), pady=6)
