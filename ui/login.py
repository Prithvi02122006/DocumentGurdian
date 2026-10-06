"""
Login and Registration UI for Document Guardian.
Professional, accessible, information-first public-service layout.
Includes strong password checklist, lockout alerts, and student project disclaimer.
"""

import customtkinter as ctk
from typing import Callable, Optional
from ui.theme import (
    FONT_TITLE, FONT_SUBTITLE, FONT_BODY, FONT_BODY_BOLD, FONT_SMALL,
    COLOR_PRIMARY, COLOR_PRIMARY_HOVER, COLOR_BORDER, COLOR_SURFACE,
    COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY, COLOR_STATUS_EXPIRED,
    COLOR_STATUS_VALID, COLOR_DISCLAIMER_BG, COLOR_DISCLAIMER_TEXT,
    CORNER_RADIUS_FORMAL, BORDER_WIDTH_FORMAL, DISCLAIMER_TEXT
)
from security.authentication import AuthenticationService, AuthResult
from models.user import User


class LoginFrame(ctk.CTkFrame):
    """Container holding login and registration tabs with formal public-service styling."""

    def __init__(
        self,
        master,
        auth_service: AuthenticationService,
        on_auth_success: Callable[[User, bytes], None],
        **kwargs
    ):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.auth_service = auth_service
        self.on_auth_success = on_auth_success

        self._build_ui()

    def _build_ui(self):
        # Outer card container
        # Outer card container
        self.card = ctk.CTkFrame(
            self,
            fg_color=COLOR_SURFACE,
            corner_radius=14,
            border_width=BORDER_WIDTH_FORMAL,
            border_color=COLOR_BORDER
        )
        self.card.pack(expand=True, fill="both", padx=50, pady=30)

        # 1. Header Banner
        header_frame = ctk.CTkFrame(self.card, fg_color=COLOR_PRIMARY, corner_radius=14)
        header_frame.pack(fill="x", padx=12, pady=(12, 6))

        title_lbl = ctk.CTkLabel(
            header_frame,
            text="🛡️ DOCUMENT GUARDIAN",
            font=FONT_TITLE,
            text_color="#FFFFFF"
        )
        title_lbl.pack(pady=(16, 2))

        sub_lbl = ctk.CTkLabel(
            header_frame,
            text="Zero-Knowledge Personal Privacy & Encrypted Vault",
            font=FONT_SUBTITLE,
            text_color="#E2E8F0"
        )
        sub_lbl.pack(pady=(0, 16))

        # 2. Disclaimer Notice Pill
        disc_frame = ctk.CTkFrame(self.card, fg_color=COLOR_DISCLAIMER_BG, corner_radius=8)
        disc_frame.pack(fill="x", padx=25, pady=(10, 8))

        disc_lbl = ctk.CTkLabel(
            disc_frame,
            text=f"[NOTICE] {DISCLAIMER_TEXT}",
            font=FONT_SMALL,
            text_color=COLOR_DISCLAIMER_TEXT,
            wraplength=620,
            justify="center"
        )
        disc_lbl.pack(padx=12, pady=6)

        # 3. Tabview for Sign In vs Register
        self.tabview = ctk.CTkTabview(
            self.card,
            corner_radius=10,
            segmented_button_selected_color=COLOR_PRIMARY,
            segmented_button_selected_hover_color=COLOR_PRIMARY_HOVER
        )
        self.tabview.pack(fill="both", expand=True, padx=25, pady=(5, 20))

        self.tab_login = self.tabview.add("Sign In")
        self.tab_register = self.tabview.add("Create Account")

        self._build_login_tab()
        self._build_register_tab()

    def _build_login_tab(self):
        tab = self.tab_login

        lbl_instruct = ctk.CTkLabel(
            tab,
            text="Sign in to access your personal document vault",
            font=FONT_BODY,
            text_color=COLOR_TEXT_SECONDARY
        )
        lbl_instruct.pack(pady=(12, 16))

        # Username
        lbl_user = ctk.CTkLabel(tab, text="Username", font=FONT_BODY_BOLD, text_color=COLOR_TEXT_PRIMARY, anchor="w")
        lbl_user.pack(fill="x", padx=30, pady=(4, 2))

        self.login_user_entry = ctk.CTkEntry(
            tab,
            placeholder_text="Enter username",
            height=36,
            corner_radius=CORNER_RADIUS_FORMAL,
            font=FONT_BODY
        )
        self.login_user_entry.pack(fill="x", padx=30, pady=(0, 12))

        # Password
        lbl_pwd = ctk.CTkLabel(tab, text="Master Password", font=FONT_BODY_BOLD, text_color=COLOR_TEXT_PRIMARY, anchor="w")
        lbl_pwd.pack(fill="x", padx=30, pady=(4, 2))

        self.login_pwd_entry = ctk.CTkEntry(
            tab,
            placeholder_text="Enter master password",
            show="*",
            height=36,
            corner_radius=CORNER_RADIUS_FORMAL,
            font=FONT_BODY
        )
        self.login_pwd_entry.pack(fill="x", padx=30, pady=(0, 6))

        # Show password toggle
        self.login_show_pwd = ctk.CTkCheckBox(
            tab,
            text="Show Password",
            font=FONT_SMALL,
            command=self._toggle_login_pwd_visibility,
            corner_radius=CORNER_RADIUS_FORMAL
        )
        self.login_show_pwd.pack(anchor="w", padx=30, pady=(0, 14))

        # Error / Status Label
        self.login_status_lbl = ctk.CTkLabel(
            tab,
            text="",
            font=FONT_BODY,
            text_color=COLOR_STATUS_EXPIRED,
            wraplength=450
        )
        self.login_status_lbl.pack(pady=(0, 10))

        # Submit Button
        self.btn_signin = ctk.CTkButton(
            tab,
            text="Sign In",
            font=FONT_BODY_BOLD,
            height=38,
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            corner_radius=CORNER_RADIUS_FORMAL,
            command=self._handle_login
        )
        self.btn_signin.pack(fill="x", padx=30, pady=(0, 15))

        # Bind Enter key to submit
        self.login_pwd_entry.bind("<Return>", lambda event: self._handle_login())
        self.login_user_entry.bind("<Return>", lambda event: self._handle_login())

    def _build_register_tab(self):
        tab = self.tab_register

        lbl_instruct = ctk.CTkLabel(
            tab,
            text="Register a new personal document vault account",
            font=FONT_BODY,
            text_color=COLOR_TEXT_SECONDARY
        )
        lbl_instruct.pack(pady=(8, 12))

        # Username
        lbl_user = ctk.CTkLabel(tab, text="Username", font=FONT_BODY_BOLD, text_color=COLOR_TEXT_PRIMARY, anchor="w")
        lbl_user.pack(fill="x", padx=30, pady=(2, 1))

        self.reg_user_entry = ctk.CTkEntry(
            tab,
            placeholder_text="Choose a unique username",
            height=34,
            corner_radius=CORNER_RADIUS_FORMAL,
            font=FONT_BODY
        )
        self.reg_user_entry.pack(fill="x", padx=30, pady=(0, 8))

        # Password
        lbl_pwd = ctk.CTkLabel(tab, text="Master Password", font=FONT_BODY_BOLD, text_color=COLOR_TEXT_PRIMARY, anchor="w")
        lbl_pwd.pack(fill="x", padx=30, pady=(2, 1))

        self.reg_pwd_entry = ctk.CTkEntry(
            tab,
            placeholder_text="Enter strong master password",
            show="*",
            height=34,
            corner_radius=CORNER_RADIUS_FORMAL,
            font=FONT_BODY
        )
        self.reg_pwd_entry.pack(fill="x", padx=30, pady=(0, 4))

        # Dynamic Password Strength Bar & Label
        strength_frame = ctk.CTkFrame(tab, fg_color="transparent")
        strength_frame.pack(fill="x", padx=30, pady=(0, 6))

        self.strength_bar = ctk.CTkProgressBar(strength_frame, height=6, corner_radius=3)
        self.strength_bar.set(0)
        self.strength_bar.configure(progress_color="#EF4444")
        self.strength_bar.pack(fill="x", side="top", pady=(0, 2))

        self.strength_lbl = ctk.CTkLabel(
            strength_frame,
            text="Strength: Enter master password",
            font=FONT_SMALL,
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w"
        )
        self.strength_lbl.pack(anchor="w")

        self.reg_pwd_entry.bind("<KeyRelease>", self._update_reg_pwd_strength)

        # Confirm Password
        lbl_confirm = ctk.CTkLabel(tab, text="Confirm Master Password", font=FONT_BODY_BOLD, text_color=COLOR_TEXT_PRIMARY, anchor="w")
        lbl_confirm.pack(fill="x", padx=30, pady=(2, 1))

        self.reg_confirm_entry = ctk.CTkEntry(
            tab,
            placeholder_text="Re-enter master password",
            show="*",
            height=34,
            corner_radius=CORNER_RADIUS_FORMAL,
            font=FONT_BODY
        )
        self.reg_confirm_entry.pack(fill="x", padx=30, pady=(0, 6))

        # Show password toggle
        self.reg_show_pwd = ctk.CTkCheckBox(
            tab,
            text="Show Passwords",
            font=FONT_SMALL,
            command=self._toggle_reg_pwd_visibility,
            corner_radius=CORNER_RADIUS_FORMAL
        )
        self.reg_show_pwd.pack(anchor="w", padx=30, pady=(0, 8))

        # Requirements Checklist Box
        req_box = ctk.CTkFrame(tab, fg_color=COLOR_BORDER, corner_radius=CORNER_RADIUS_FORMAL)
        req_box.pack(fill="x", padx=30, pady=(0, 10))

        req_title = ctk.CTkLabel(
            req_box,
            text="Password Requirements:",
            font=FONT_BODY_BOLD,
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w"
        )
        req_title.pack(anchor="w", padx=10, pady=(6, 2))

        requirements_text = (
            "- Minimum 10 characters in length\n"
            "- At least one uppercase letter (A-Z)\n"
            "- At least one lowercase letter (a-z)\n"
            "- At least one numeric digit (0-9)\n"
            "- At least one special symbol (!@#$%^&*...)"
        )
        req_lbl = ctk.CTkLabel(
            req_box,
            text=requirements_text,
            font=FONT_SMALL,
            text_color=COLOR_TEXT_SECONDARY,
            justify="left",
            anchor="w"
        )
        req_lbl.pack(anchor="w", padx=10, pady=(0, 6))

        # Error / Status Label
        self.reg_status_lbl = ctk.CTkLabel(
            tab,
            text="",
            font=FONT_BODY,
            text_color=COLOR_STATUS_EXPIRED,
            wraplength=450
        )
        self.reg_status_lbl.pack(pady=(0, 8))

        # Submit Button
        self.btn_register = ctk.CTkButton(
            tab,
            text="Create Vault Account",
            font=FONT_BODY_BOLD,
            height=38,
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            corner_radius=CORNER_RADIUS_FORMAL,
            command=self._handle_register
        )
        self.btn_register.pack(fill="x", padx=30, pady=(0, 12))

    def _toggle_login_pwd_visibility(self):
        show_char = "" if self.login_show_pwd.get() else "*"
        self.login_pwd_entry.configure(show=show_char)

    def _toggle_reg_pwd_visibility(self):
        show_char = "" if self.reg_show_pwd.get() else "*"
        self.reg_pwd_entry.configure(show=show_char)
        self.reg_confirm_entry.configure(show=show_char)

    def _update_reg_pwd_strength(self, event=None):
        pwd = self.reg_pwd_entry.get()
        if not pwd:
            self.strength_bar.set(0)
            self.strength_lbl.configure(text="Strength: Enter master password", text_color=COLOR_TEXT_SECONDARY)
            return

        score = 0
        if len(pwd) >= 10:
            score += 1
        if any(c.isupper() for c in pwd):
            score += 1
        if any(c.islower() for c in pwd):
            score += 1
        if any(c.isdigit() for c in pwd):
            score += 1
        if any(not c.isalnum() for c in pwd):
            score += 1

        val = score / 5.0
        self.strength_bar.set(val)
        if score <= 2:
            self.strength_bar.configure(progress_color="#EF4444")
            self.strength_lbl.configure(text=f"Strength: Weak ({score}/5)", text_color="#EF4444")
        elif score <= 4:
            self.strength_bar.configure(progress_color="#F59E0B")
            self.strength_lbl.configure(text=f"Strength: Moderate ({score}/5)", text_color="#F59E0B")
        else:
            self.strength_bar.configure(progress_color="#10B981")
            self.strength_lbl.configure(text="Strength: Strong (All criteria met)", text_color="#10B981")

    def _handle_login(self):
        username = self.login_user_entry.get().strip()
        password = self.login_pwd_entry.get()

        if not username or not password:
            self.login_status_lbl.configure(text="Please enter both username and password.", text_color=COLOR_STATUS_EXPIRED)
            return

        self.login_status_lbl.configure(text="Authenticating...", text_color=COLOR_TEXT_SECONDARY)
        self.update_idletasks()

        res: AuthResult = self.auth_service.login(username, password)
        if res.success and res.user and res.dek:
            self.login_status_lbl.configure(text="Success. Opening vault...", text_color=COLOR_STATUS_VALID)
            self.login_pwd_entry.delete(0, "end")
            self.on_auth_success(res.user, res.dek)
        else:
            self.login_status_lbl.configure(text=res.error_message or "Authentication failed.", text_color=COLOR_STATUS_EXPIRED)

    def _handle_register(self):
        username = self.reg_user_entry.get().strip()
        password = self.reg_pwd_entry.get()
        confirm = self.reg_confirm_entry.get()

        if not username or not password or not confirm:
            self.reg_status_lbl.configure(text="All fields are required.", text_color=COLOR_STATUS_EXPIRED)
            return

        self.reg_status_lbl.configure(text="Creating account and generating vault key...", text_color=COLOR_TEXT_SECONDARY)
        self.update_idletasks()

        res: AuthResult = self.auth_service.register(username, password, confirm)
        if res.success and res.user and res.dek:
            self.reg_status_lbl.configure(text="Account created successfully!", text_color=COLOR_STATUS_VALID)
            self.reg_pwd_entry.delete(0, "end")
            self.reg_confirm_entry.delete(0, "end")
            self.on_auth_success(res.user, res.dek)
        else:
            self.reg_status_lbl.configure(text=res.error_message or "Registration failed.", text_color=COLOR_STATUS_EXPIRED)

    def reset_fields(self):
        """Clears sensitive form fields."""
        self.login_pwd_entry.delete(0, "end")
        self.login_status_lbl.configure(text="")
        self.reg_pwd_entry.delete(0, "end")
        self.reg_confirm_entry.delete(0, "end")
        self.reg_status_lbl.configure(text="")
