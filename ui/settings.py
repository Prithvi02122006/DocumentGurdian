"""
Settings and Audit Log viewer for Document Guardian.
Covers Security (Change Password, Session Timeout), Appearance (Light/Dark theme),
Data Management (CSV Export), and Security Audit Trail Viewer.
"""

import customtkinter as ctk
from tkinter import messagebox, filedialog
from typing import Callable, Optional, List
from ui.theme import (
    FONT_TITLE, FONT_SUBTITLE, FONT_SECTION, FONT_BODY, FONT_BODY_BOLD, FONT_SMALL, FONT_MONO,
    COLOR_PRIMARY, COLOR_PRIMARY_HOVER, COLOR_SECONDARY, COLOR_BORDER, COLOR_SURFACE,
    COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY, COLOR_STATUS_EXPIRED, COLOR_STATUS_VALID,
    COLOR_STATUS_ATTENTION, CORNER_RADIUS_FORMAL, BORDER_WIDTH_FORMAL, DISCLAIMER_TEXT
)
from security.authentication import AuthenticationService, AuthResult
from security.session import SessionManager
from services.export_service import ExportService
from services.audit_service import AuditService
from models.audit import AuditLog


class SettingsFrame(ctk.CTkFrame):
    """Settings view for configuring security, appearance, exports, and viewing audit logs."""

    def __init__(
        self,
        master,
        auth_service: AuthenticationService,
        session_manager: SessionManager,
        export_service: Optional[ExportService] = None,
        audit_service: Optional[AuditService] = None,
        **kwargs
    ):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.auth_service = auth_service
        self.session_manager = session_manager
        self.export_service = export_service or ExportService()
        self.audit_service = audit_service or AuditService()
        self.user_id: Optional[int] = None

        self._build_ui()

    def _build_ui(self):
        # 1. Header Bar
        header_bar = ctk.CTkFrame(self, fg_color="transparent")
        header_bar.pack(fill="x", padx=25, pady=(15, 10))

        title_lbl = ctk.CTkLabel(
            header_bar,
            text="SETTINGS, AUDIT & EXPORT",
            font=FONT_TITLE,
            text_color=COLOR_TEXT_PRIMARY,
            anchor="w"
        )
        title_lbl.pack(side="left")

        # Scrollable settings container
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=25, pady=(0, 20))

        # 2. Security Section (Change Password)
        sec_card = ctk.CTkFrame(
            scroll,
            fg_color=COLOR_SURFACE,
            corner_radius=CORNER_RADIUS_FORMAL,
            border_width=BORDER_WIDTH_FORMAL,
            border_color=COLOR_BORDER
        )
        sec_card.pack(fill="x", pady=(0, 15))

        sec_hdr = ctk.CTkFrame(sec_card, fg_color=COLOR_BORDER, corner_radius=0, height=36)
        sec_hdr.pack(fill="x")
        ctk.CTkLabel(sec_hdr, text="Security: Change Master Password", font=FONT_SECTION, text_color=COLOR_TEXT_PRIMARY).pack(side="left", padx=15, pady=6)

        sec_body = ctk.CTkFrame(sec_card, fg_color="transparent")
        sec_body.pack(fill="x", padx=20, pady=12)

        ctk.CTkLabel(sec_body, text="Current Password", font=FONT_BODY_BOLD, anchor="w").pack(fill="x", pady=(2, 1))
        self.curr_pwd_entry = ctk.CTkEntry(sec_body, show="*", height=32, font=FONT_BODY)
        self.curr_pwd_entry.pack(fill="x", pady=(0, 8))

        ctk.CTkLabel(sec_body, text="New Master Password (min 10 chars, uppercase, lowercase, digit, symbol)", font=FONT_BODY_BOLD, anchor="w").pack(fill="x", pady=(2, 1))
        self.new_pwd_entry = ctk.CTkEntry(sec_body, show="*", height=32, font=FONT_BODY)
        self.new_pwd_entry.pack(fill="x", pady=(0, 8))

        ctk.CTkLabel(sec_body, text="Confirm New Master Password", font=FONT_BODY_BOLD, anchor="w").pack(fill="x", pady=(2, 1))
        self.confirm_pwd_entry = ctk.CTkEntry(sec_body, show="*", height=32, font=FONT_BODY)
        self.confirm_pwd_entry.pack(fill="x", pady=(0, 8))

        self.pwd_status_lbl = ctk.CTkLabel(sec_body, text="", font=FONT_SMALL, text_color=COLOR_STATUS_EXPIRED)
        self.pwd_status_lbl.pack(pady=(0, 8))

        btn_change_pwd = ctk.CTkButton(
            sec_body,
            text="Update Password & Re-encrypt Vault Key",
            font=FONT_BODY_BOLD,
            height=34,
            width=260,
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            corner_radius=CORNER_RADIUS_FORMAL,
            command=self._handle_change_password
        )
        btn_change_pwd.pack(anchor="w")

        # 3. Inactivity Timeout Section
        timeout_card = ctk.CTkFrame(
            scroll,
            fg_color=COLOR_SURFACE,
            corner_radius=CORNER_RADIUS_FORMAL,
            border_width=BORDER_WIDTH_FORMAL,
            border_color=COLOR_BORDER
        )
        timeout_card.pack(fill="x", pady=(0, 15))

        t_hdr = ctk.CTkFrame(timeout_card, fg_color=COLOR_BORDER, corner_radius=0, height=36)
        t_hdr.pack(fill="x")
        ctk.CTkLabel(t_hdr, text="Security: Inactivity Session Timeout", font=FONT_SECTION, text_color=COLOR_TEXT_PRIMARY).pack(side="left", padx=15, pady=6)

        t_body = ctk.CTkFrame(timeout_card, fg_color="transparent")
        t_body.pack(fill="x", padx=20, pady=12)

        ctk.CTkLabel(
            t_body,
            text="Automatically lock the vault session after a specified period of inactivity:",
            font=FONT_SMALL,
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w"
        ).pack(fill="x", pady=(0, 6))

        self.timeout_combo = ctk.CTkComboBox(
            t_body,
            values=["5 Minutes", "10 Minutes (Default)", "15 Minutes", "30 Minutes"],
            height=32,
            width=200,
            font=FONT_BODY,
            command=self._handle_timeout_change
        )
        self.timeout_combo.set("10 Minutes (Default)")
        self.timeout_combo.pack(anchor="w")

        # 4. Data Export Section (CSV)
        export_card = ctk.CTkFrame(
            scroll,
            fg_color=COLOR_SURFACE,
            corner_radius=CORNER_RADIUS_FORMAL,
            border_width=BORDER_WIDTH_FORMAL,
            border_color=COLOR_BORDER
        )
        export_card.pack(fill="x", pady=(0, 15))

        exp_hdr = ctk.CTkFrame(export_card, fg_color=COLOR_BORDER, corner_radius=0, height=36)
        exp_hdr.pack(fill="x")
        ctk.CTkLabel(exp_hdr, text="Data Management: Export Document Records", font=FONT_SECTION, text_color=COLOR_TEXT_PRIMARY).pack(side="left", padx=15, pady=6)

        exp_body = ctk.CTkFrame(export_card, fg_color="transparent")
        exp_body.pack(fill="x", padx=20, pady=12)

        ctk.CTkLabel(
            exp_body,
            text="Export your document metadata, milestone dates, and statuses to a CSV spreadsheet file.",
            font=FONT_SMALL,
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w"
        ).pack(fill="x", pady=(0, 8))

        self.cb_include_decrypted = ctk.CTkCheckBox(
            exp_body,
            text="Include full decrypted document numbers in export (Default is masked for security)",
            font=FONT_SMALL,
            corner_radius=CORNER_RADIUS_FORMAL
        )
        self.cb_include_decrypted.pack(anchor="w", pady=(0, 12))

        btn_export = ctk.CTkButton(
            exp_body,
            text="Export Records to CSV...",
            font=FONT_BODY_BOLD,
            height=34,
            width=180,
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            corner_radius=CORNER_RADIUS_FORMAL,
            command=self._handle_csv_export
        )
        btn_export.pack(anchor="w")

        # 5. Security Audit Trail Viewer Section
        audit_card = ctk.CTkFrame(
            scroll,
            fg_color=COLOR_SURFACE,
            corner_radius=CORNER_RADIUS_FORMAL,
            border_width=BORDER_WIDTH_FORMAL,
            border_color=COLOR_BORDER
        )
        audit_card.pack(fill="x", pady=(0, 15))

        aud_hdr = ctk.CTkFrame(audit_card, fg_color=COLOR_BORDER, corner_radius=0, height=36)
        aud_hdr.pack(fill="x")
        ctk.CTkLabel(aud_hdr, text="Security Audit Trail", font=FONT_SECTION, text_color=COLOR_TEXT_PRIMARY).pack(side="left", padx=15, pady=6)

        btn_refresh_audit = ctk.CTkButton(
            aud_hdr,
            text="Refresh Logs",
            font=FONT_SMALL,
            width=90,
            height=26,
            fg_color=COLOR_SECONDARY,
            hover_color=COLOR_SECONDARY[0],
            corner_radius=CORNER_RADIUS_FORMAL,
            command=self._refresh_audit_logs
        )
        btn_refresh_audit.pack(side="right", padx=10, pady=5)

        aud_body = ctk.CTkFrame(audit_card, fg_color="transparent")
        aud_body.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(
            aud_body,
            text="Chronological security log of authentication, document modifications, and vault activity:",
            font=FONT_SMALL,
            text_color=COLOR_TEXT_SECONDARY,
            anchor="w"
        ).pack(fill="x", pady=(0, 6))

        # Audit logs table
        self.audit_table_frame = ctk.CTkScrollableFrame(aud_body, fg_color=COLOR_BORDER, height=180)
        self.audit_table_frame.pack(fill="x", expand=True)

        # 6. Appearance Section
        theme_card = ctk.CTkFrame(
            scroll,
            fg_color=COLOR_SURFACE,
            corner_radius=CORNER_RADIUS_FORMAL,
            border_width=BORDER_WIDTH_FORMAL,
            border_color=COLOR_BORDER
        )
        theme_card.pack(fill="x", pady=(0, 15))

        th_hdr = ctk.CTkFrame(theme_card, fg_color=COLOR_BORDER, corner_radius=0, height=36)
        th_hdr.pack(fill="x")
        ctk.CTkLabel(th_hdr, text="Appearance: Application Theme", font=FONT_SECTION, text_color=COLOR_TEXT_PRIMARY).pack(side="left", padx=15, pady=6)

        th_body = ctk.CTkFrame(theme_card, fg_color="transparent")
        th_body.pack(fill="x", padx=20, pady=12)

        self.theme_combo = ctk.CTkComboBox(
            th_body,
            values=["Light", "Dark", "System"],
            height=32,
            width=150,
            font=FONT_BODY,
            command=self._handle_theme_change
        )
        self.theme_combo.set("Light")
        self.theme_combo.pack(anchor="w")

        # 7. About & Legal Notice Section
        about_card = ctk.CTkFrame(
            scroll,
            fg_color=COLOR_SURFACE,
            corner_radius=CORNER_RADIUS_FORMAL,
            border_width=BORDER_WIDTH_FORMAL,
            border_color=COLOR_BORDER
        )
        about_card.pack(fill="x", pady=(0, 15))

        ab_hdr = ctk.CTkFrame(about_card, fg_color=COLOR_BORDER, corner_radius=0, height=36)
        ab_hdr.pack(fill="x")
        ctk.CTkLabel(ab_hdr, text="About Document Guardian", font=FONT_SECTION, text_color=COLOR_TEXT_PRIMARY).pack(side="left", padx=15, pady=6)

        ab_body = ctk.CTkFrame(about_card, fg_color="transparent")
        ab_body.pack(fill="x", padx=20, pady=12)

        about_text = (
            "DOCUMENT GUARDIAN : Secure Personal Document Management System\n"
            "Version: 1.0.0 (Academic Edition)\n\n"
            f"[LEGAL NOTICE]\n{DISCLAIMER_TEXT}\n\n"
            "Security Architecture:\n"
            "- Key Derivation: RFC 9106 Argon2id (64MB memory cost, 4 lanes)\n"
            "- Symmetric Encryption: AES-256-GCM envelope encryption for records and vault files\n"
            "- Local Storage: SQLite with foreign key enforcement and encrypted file vault\n"
            "- Audit Integrity: Append-only security audit log with redaction of sensitive credentials"
        )
        ctk.CTkLabel(
            ab_body,
            text=about_text,
            font=FONT_SMALL,
            text_color=COLOR_TEXT_SECONDARY,
            justify="left",
            anchor="w"
        ).pack(fill="x")

    def load_user(self, user_id: int):
        self.user_id = user_id
        self.curr_pwd_entry.delete(0, "end")
        self.new_pwd_entry.delete(0, "end")
        self.confirm_pwd_entry.delete(0, "end")
        self.pwd_status_lbl.configure(text="")
        self._refresh_audit_logs()

    def _refresh_audit_logs(self):
        """Loads user audit logs into the table frame."""
        for widget in self.audit_table_frame.winfo_children():
            widget.destroy()

        if not self.user_id:
            return

        logs: List[AuditLog] = self.audit_service.get_logs_for_user(self.user_id, limit=50)
        if not logs:
            ctk.CTkLabel(
                self.audit_table_frame,
                text="No audit events recorded yet.",
                font=FONT_SMALL,
                text_color=COLOR_TEXT_SECONDARY
            ).pack(pady=10)
            return

        for idx, log in enumerate(logs):
            row_bg = COLOR_SURFACE if idx % 2 == 0 else COLOR_BORDER
            row = ctk.CTkFrame(self.audit_table_frame, fg_color=row_bg, corner_radius=0, height=28)
            row.pack(fill="x", pady=1)

            ts = log.timestamp[:19].replace("T", " ")
            ctk.CTkLabel(row, text=ts, font=FONT_MONO, width=140, anchor="w").pack(side="left", padx=8)
            ctk.CTkLabel(row, text=log.action, font=FONT_BODY_BOLD, width=160, anchor="w").pack(side="left", padx=5)
            ctk.CTkLabel(row, text=log.details or "-", font=FONT_SMALL, text_color=COLOR_TEXT_SECONDARY, anchor="w").pack(side="left", fill="x", expand=True, padx=5)

    def _handle_change_password(self):
        if not self.user_id:
            return

        current = self.curr_pwd_entry.get()
        new_pwd = self.new_pwd_entry.get()
        confirm = self.confirm_pwd_entry.get()

        res: AuthResult = self.auth_service.change_password(
            user_id=self.user_id,
            current_password=current,
            new_password=new_pwd,
            confirm_password=confirm
        )

        if res.success:
            self.pwd_status_lbl.configure(text="Password successfully changed and vault key re-wrapped!", text_color=COLOR_STATUS_VALID)
            self.curr_pwd_entry.delete(0, "end")
            self.new_pwd_entry.delete(0, "end")
            self.confirm_pwd_entry.delete(0, "end")
            self._refresh_audit_logs()
            messagebox.showinfo("Success", "Master password has been updated successfully.")
        else:
            self.pwd_status_lbl.configure(text=res.error_message or "Failed to change password.", text_color=COLOR_STATUS_EXPIRED)

    def _handle_csv_export(self):
        if not self.user_id:
            return

        dest = filedialog.asksaveasfilename(
            title="Export Records to CSV",
            initialfile="DocumentGuardian_Records.csv",
            defaultextension=".csv",
            filetypes=[("CSV Spreadsheet", "*.csv"), ("All Files", "*.*")]
        )
        if not dest:
            return

        include_decrypted = bool(self.cb_include_decrypted.get())
        dek = None
        if include_decrypted:
            try:
                dek = self.session_manager.get_dek()
            except Exception:
                messagebox.showerror("Error", "Session is locked. Cannot decrypt numbers.")
                return

        try:
            count = self.export_service.export_documents_to_csv(
                user_id=self.user_id,
                destination_csv_path=dest,
                include_decrypted_numbers=include_decrypted,
                dek=dek
            )
            self._refresh_audit_logs()
            messagebox.showinfo(
                "Export Complete",
                f"Successfully exported {count} document record(s) to:\n{dest}"
            )
        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not export records: {str(e)}")

    def _handle_timeout_change(self, value: str):
        minutes_map = {
            "5 Minutes": 5,
            "10 Minutes (Default)": 10,
            "15 Minutes": 15,
            "30 Minutes": 30
        }
        mins = minutes_map.get(value, 10)
        self.session_manager.timeout_minutes = mins
        messagebox.showinfo("Timeout Updated", f"Inactivity timeout set to {mins} minutes.")

    def _handle_theme_change(self, mode: str):
        ctk.set_appearance_mode(mode)
