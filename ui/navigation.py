"""
Top navigation bar for Document Guardian.
Formal, restrained public-service header layout with section tabs, user badge,
quick session lock, and secure logout.
"""

import customtkinter as ctk
from typing import Callable, Optional
from ui.theme import (
    FONT_TITLE, FONT_SUBTITLE, FONT_BODY_BOLD, FONT_SMALL,
    COLOR_PRIMARY, COLOR_PRIMARY_HOVER, COLOR_SECONDARY, COLOR_SECONDARY_HOVER,
    COLOR_HEADER_BG, COLOR_TEXT_PRIMARY, COLOR_BORDER, COLOR_DISCLAIMER_BG,
    COLOR_DISCLAIMER_TEXT, CORNER_RADIUS_FORMAL
)


class NavigationBar(ctk.CTkFrame):
    """Restrained public-service top navigation header."""

    def __init__(
        self,
        master,
        on_navigate: Callable[[str], None],
        on_lock: Callable[[], None],
        on_logout: Callable[[], None],
        current_username: str = "",
        **kwargs
    ):
        super().__init__(master, fg_color=COLOR_HEADER_BG, corner_radius=0, height=60, **kwargs)
        self.on_navigate = on_navigate
        self.on_lock = on_lock
        self.on_logout = on_logout
        self.current_username = current_username
        self.active_tab = "Dashboard"

        self._buttons = {}
        self._build_ui()

    def _build_ui(self):
        # 1. Left: Branding & Tag
        brand_frame = ctk.CTkFrame(self, fg_color="transparent")
        brand_frame.pack(side="left", padx=(20, 24), pady=8)

        lbl_app = ctk.CTkLabel(
            brand_frame,
            text="🛡️ DOCUMENT GUARDIAN",
            font=FONT_SUBTITLE,
            text_color="#FFFFFF"
        )
        lbl_app.pack(anchor="w")

        lbl_sub = ctk.CTkLabel(
            brand_frame,
            text="AES-256 Encrypted Personal Vault",
            font=FONT_SMALL,
            text_color="#94A3B8"
        )
        lbl_sub.pack(anchor="w")

        # 2. Middle: Navigation Tabs
        nav_tabs = ["Dashboard", "My Documents", "Reminders", "Settings"]
        self.nav_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.nav_frame.pack(side="left", padx=10, pady=10)

        for tab in nav_tabs:
            btn = ctk.CTkButton(
                self.nav_frame,
                text=tab,
                font=FONT_BODY_BOLD,
                height=34,
                width=115,
                corner_radius=8,
                fg_color=COLOR_PRIMARY if tab == self.active_tab else "transparent",
                text_color="#FFFFFF",
                hover_color=COLOR_PRIMARY_HOVER,
                command=lambda t=tab: self._handle_click(t)
            )
            btn.pack(side="left", padx=4)
            self._buttons[tab] = btn

        # 3. Right: User info, idle timer & Actions
        right_frame = ctk.CTkFrame(self, fg_color="transparent")
        right_frame.pack(side="right", padx=(10, 20), pady=10)

        # Idle countdown timer badge
        self.timer_lbl = ctk.CTkLabel(
            right_frame,
            text="⏱️ 15:00",
            font=FONT_SMALL,
            text_color="#38BDF8"
        )
        self.timer_lbl.pack(side="left", padx=(0, 12))

        self.user_lbl = ctk.CTkLabel(
            right_frame,
            text=f"User: {self.current_username}",
            font=FONT_BODY_BOLD,
            text_color="#F1F5F9"
        )
        self.user_lbl.pack(side="left", padx=(0, 14))

        # Quick Lock Button
        btn_lock = ctk.CTkButton(
            right_frame,
            text="🔒 Lock",
            font=FONT_BODY_BOLD,
            width=70,
            height=32,
            fg_color="#334155",
            hover_color="#1E293B",
            corner_radius=8,
            command=self.on_lock
        )
        btn_lock.pack(side="left", padx=4)

        # Logout Button
        btn_logout = ctk.CTkButton(
            right_frame,
            text="Sign Out",
            font=FONT_BODY_BOLD,
            width=75,
            height=32,
            fg_color="#DC2626",
            hover_color="#B91C1C",
            corner_radius=8,
            command=self.on_logout
        )
        btn_logout.pack(side="left", padx=4)

    def set_timer_text(self, text: str):
        if hasattr(self, "timer_lbl"):
            self.timer_lbl.configure(text=text)

    def set_user(self, username: str):
        self.current_username = username
        self.user_lbl.configure(text=f"User: {username}")

    def set_active(self, tab_name: str):
        self.active_tab = tab_name
        for name, btn in self._buttons.items():
            if name == tab_name:
                btn.configure(fg_color=COLOR_PRIMARY)
            else:
                btn.configure(fg_color="transparent")

    def _handle_click(self, tab_name: str):
        self.set_active(tab_name)
        self.on_navigate(tab_name)
