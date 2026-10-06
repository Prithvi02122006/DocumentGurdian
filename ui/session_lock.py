"""
Session Lock screen for Document Guardian.
Protects sensitive document data in RAM when user is inactive or manually locks.
Requires master password to resume session.
"""

import customtkinter as ctk
from typing import Callable, Optional
from ui.theme import (
    FONT_TITLE, FONT_SUBTITLE, FONT_BODY, FONT_BODY_BOLD, FONT_SMALL,
    COLOR_PRIMARY, COLOR_PRIMARY_HOVER, COLOR_SECONDARY, COLOR_BORDER, COLOR_SURFACE,
    COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY, COLOR_STATUS_EXPIRED, COLOR_HEADER_BG,
    CORNER_RADIUS_FORMAL, BORDER_WIDTH_FORMAL
)
from security.session import SessionManager


class SessionLockFrame(ctk.CTkFrame):
    """Full-frame lock screen requiring master password to restore access."""

    def __init__(
        self,
        master,
        session_manager: SessionManager,
        on_unlocked: Callable[[], None],
        on_logout: Callable[[], None],
        **kwargs
    ):
        super().__init__(master, fg_color=COLOR_HEADER_BG, corner_radius=0, **kwargs)
        self.session_manager = session_manager
        self.on_unlocked = on_unlocked
        self.on_logout = on_logout

        self._build_ui()

    def _build_ui(self):
        # Center Card
        card = ctk.CTkFrame(
            self,
            fg_color=COLOR_SURFACE,
            corner_radius=CORNER_RADIUS_FORMAL,
            border_width=BORDER_WIDTH_FORMAL,
            border_color=COLOR_BORDER,
            width=460,
            height=380
        )
        card.place(relx=0.5, rely=0.5, anchor="center")
        card.pack_propagate(False)

        # Title
        lbl_title = ctk.CTkLabel(
            card,
            text="SESSION LOCKED",
            font=FONT_TITLE,
            text_color=COLOR_TEXT_PRIMARY
        )
        lbl_title.pack(pady=(25, 4))

        self.user_badge = ctk.CTkLabel(
            card,
            text="",
            font=FONT_BODY_BOLD,
            text_color=COLOR_PRIMARY[0]
        )
        self.user_badge.pack(pady=(0, 10))

        lbl_desc = ctk.CTkLabel(
            card,
            text=(
                "Your vault session is locked to prevent unauthorized access.\n"
                "Please enter your master password to unlock."
            ),
            font=FONT_SMALL,
            text_color=COLOR_TEXT_SECONDARY,
            justify="center",
            wraplength=380
        )
        lbl_desc.pack(pady=(0, 15))

        # Password Entry
        self.pwd_entry = ctk.CTkEntry(
            card,
            placeholder_text="Enter master password",
            show="*",
            height=38,
            corner_radius=CORNER_RADIUS_FORMAL,
            font=FONT_BODY
        )
        self.pwd_entry.pack(fill="x", padx=40, pady=(0, 6))
        self.pwd_entry.bind("<Return>", lambda event: self._handle_unlock())

        # Error status
        self.err_lbl = ctk.CTkLabel(
            card,
            text="",
            font=FONT_SMALL,
            text_color=COLOR_STATUS_EXPIRED
        )
        self.err_lbl.pack(pady=(0, 12))

        # Action Buttons
        btn_unlock = ctk.CTkButton(
            card,
            text="Unlock Session",
            font=FONT_BODY_BOLD,
            height=38,
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            corner_radius=CORNER_RADIUS_FORMAL,
            command=self._handle_unlock
        )
        btn_unlock.pack(fill="x", padx=40, pady=(0, 10))

        btn_logout = ctk.CTkButton(
            card,
            text="Sign Out",
            font=FONT_BODY,
            height=32,
            fg_color="transparent",
            hover_color=COLOR_BORDER,
            text_color=COLOR_TEXT_SECONDARY,
            corner_radius=CORNER_RADIUS_FORMAL,
            command=self.on_logout
        )
        btn_logout.pack(fill="x", padx=40, pady=(0, 15))

    def set_user(self, username: str):
        self.user_badge.configure(text=f"Account: {username}")
        self.pwd_entry.delete(0, "end")
        self.err_lbl.configure(text="")

    def _handle_unlock(self):
        password = self.pwd_entry.get()
        if not password:
            self.err_lbl.configure(text="Please enter your master password.")
            return

        success = self.session_manager.unlock_session(password)
        if success:
            self.pwd_entry.delete(0, "end")
            self.err_lbl.configure(text="")
            self.on_unlocked()
        else:
            self.err_lbl.configure(text="Incorrect password. Please try again.")
            self.pwd_entry.delete(0, "end")
