"""
Dedicated Reminders screen for Document Guardian.
Organizes documents into clear text categories: Expired, Review Due, and Attention Required.
"""

import customtkinter as ctk
from typing import Callable, Optional, List
from ui.theme import (
    FONT_TITLE, FONT_SUBTITLE, FONT_SECTION, FONT_BODY, FONT_BODY_BOLD, FONT_SMALL,
    COLOR_PRIMARY, COLOR_PRIMARY_HOVER, COLOR_SECONDARY, COLOR_BORDER, COLOR_SURFACE,
    COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY, COLOR_STATUS_EXPIRED, COLOR_STATUS_ATTENTION,
    COLOR_STATUS_REVIEW, COLOR_STATUS_VALID, CORNER_RADIUS_FORMAL, BORDER_WIDTH_FORMAL
)
from services.expiry_service import ExpiryService, DocumentExpiryInfo
from services.reminder_service import ReminderService
from models.document import DocumentStatus


class RemindersFrame(ctk.CTkFrame):
    """Categorized reminders view for expired, review due, and expiring soon documents."""

    def __init__(
        self,
        master,
        expiry_service: ExpiryService,
        reminder_service: ReminderService,
        on_view_document: Callable[[int], None],
        **kwargs
    ):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.expiry_service = expiry_service
        self.reminder_service = reminder_service
        self.on_view_document = on_view_document
        self.user_id: Optional[int] = None

        self._build_ui()

    def _build_ui(self):
        # 1. Header Bar
        header_bar = ctk.CTkFrame(self, fg_color="transparent")
        header_bar.pack(fill="x", padx=25, pady=(15, 10))

        title_lbl = ctk.CTkLabel(
            header_bar,
            text="DOCUMENT REMINDERS",
            font=FONT_TITLE,
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w"
        )
        title_lbl.pack(side="left")

        btn_scan = ctk.CTkButton(
            header_bar,
            text="Check Notifications",
            font=FONT_BODY_BOLD,
            height=32,
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            corner_radius=CORNER_RADIUS_FORMAL,
            command=self._handle_manual_scan
        )
        btn_scan.pack(side="right", padx=(8, 0))

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

        # Scrollable container for categorized sections
        self.scroll_container = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll_container.pack(fill="both", expand=True, padx=25, pady=(0, 20))

    def load_user(self, user_id: int):
        self.user_id = user_id
        self.refresh()

    def refresh(self):
        """Fetches reminders and renders three distinct sections."""
        if not self.user_id:
            return

        for widget in self.scroll_container.winfo_children():
            widget.destroy()

        reminders: List[DocumentExpiryInfo] = self.expiry_service.get_reminders_list(self.user_id)

        expired_list = [r for r in reminders if r.status == DocumentStatus.EXPIRED]
        review_due_list = [r for r in reminders if r.status == DocumentStatus.REVIEW_DUE]
        attention_list = [r for r in reminders if r.status == DocumentStatus.ATTENTION_REQUIRED]

        # 1. Expired Section
        self._build_category_card(
            title="Expired Documents",
            subtitle="Documents whose official validity has expired. Immediate renewal required.",
            items=expired_list,
            accent_color=COLOR_STATUS_EXPIRED
        )

        # 2. Review Due Section
        self._build_category_card(
            title="Review Due Documents",
            subtitle="Documents that have reached or passed their user-scheduled review date.",
            items=review_due_list,
            accent_color=COLOR_STATUS_REVIEW
        )

        # 3. Attention Required Section
        self._build_category_card(
            title="Attention Required / Expiring Soon",
            subtitle="Documents approaching expiration or review milestone within their reminder window.",
            items=attention_list,
            accent_color=COLOR_STATUS_ATTENTION
        )

    def _build_category_card(
        self,
        title: str,
        subtitle: str,
        items: List[DocumentExpiryInfo],
        accent_color
    ):
        card = ctk.CTkFrame(
            self.scroll_container,
            fg_color=COLOR_SURFACE,
            corner_radius=CORNER_RADIUS_FORMAL,
            border_width=BORDER_WIDTH_FORMAL,
            border_color=COLOR_BORDER
        )
        card.pack(fill="x", pady=(0, 16))

        # Category Header
        hdr = ctk.CTkFrame(card, fg_color=COLOR_BORDER, corner_radius=0, height=36)
        hdr.pack(fill="x")

        title_lbl = ctk.CTkLabel(
            hdr,
            text=f"{title} ({len(items)})",
            font=FONT_SECTION,
            text_color=accent_color,
            anchor="w"
        )
        title_lbl.pack(side="left", padx=15, pady=6)

        sub_lbl = ctk.CTkLabel(
            card,
            text=subtitle,
            font=FONT_SMALL,
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w"
        )
        sub_lbl.pack(fill="x", padx=15, pady=(6, 8))

        if not items:
            empty_lbl = ctk.CTkLabel(
                card,
                text="No records in this category.",
                font=FONT_SMALL,
                text_color=COLOR_TEXT_SECONDARY,
                anchor="w"
            )
            empty_lbl.pack(fill="x", padx=15, pady=(0, 12))
            return

        # Table rows for items
        tbl_frame = ctk.CTkFrame(card, fg_color="transparent")
        tbl_frame.pack(fill="x", padx=10, pady=(0, 10))

        for idx, item in enumerate(items):
            row_bg = COLOR_SURFACE if idx % 2 == 0 else COLOR_BORDER
            row = ctk.CTkFrame(tbl_frame, fg_color=row_bg, corner_radius=0, height=38)
            row.pack(fill="x", pady=1)

            doc = item.document
            ctk.CTkLabel(row, text=doc.document_type, font=FONT_BODY_BOLD, width=120, anchor="w").pack(side="left", padx=(10, 5))
            ctk.CTkLabel(row, text=doc.document_number_masked, font=FONT_BODY, width=150, anchor="w").pack(side="left", padx=5)
            ctk.CTkLabel(row, text=f"{item.relevant_date_label}: {item.relevant_date or 'N/A'}", font=FONT_BODY, width=170, anchor="w").pack(side="left", padx=5)
            ctk.CTkLabel(row, text=item.days_remaining_display, font=FONT_BODY_BOLD, text_color=accent_color, width=220, anchor="w").pack(side="left", padx=5)

            btn_open = ctk.CTkButton(
                row,
                text="View",
                font=FONT_SMALL,
                width=65,
                height=26,
                fg_color=COLOR_PRIMARY,
                hover_color=COLOR_PRIMARY_HOVER,
                corner_radius=CORNER_RADIUS_FORMAL,
                command=lambda d_id=doc.document_id: self.on_view_document(d_id)
            )
            btn_open.pack(side="right", padx=(5, 10), pady=6)

    def _handle_manual_scan(self):
        """Manually runs reminder scan and sends notifications for unnotified documents."""
        if self.user_id:
            self.reminder_service.check_reminders_for_user(self.user_id, notify=True)
            self.refresh()
