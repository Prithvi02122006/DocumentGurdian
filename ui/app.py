"""
Main Application Coordinator for Document Guardian.
Integrates CustomTkinter GUI with SessionManager, at-rest encryption,
automated inactivity locking, desktop notifications, and CRUD views.
"""

import customtkinter as ctk
import logging
from typing import Optional

from ui.theme import (
    COLOR_BG, COLOR_HEADER_BG, FONT_FAMILY
)
from database.database import get_db, DatabaseManager
from services.audit_service import AuditService
from security.authentication import AuthenticationService
from security.session import SessionManager, get_session
from services.document_service import DocumentService
from services.expiry_service import ExpiryService
from services.notification_service import NotificationService
from services.reminder_service import ReminderService
from services.file_service import FileService
from services.export_service import ExportService
from models.user import User
from models.document import Document

from ui.login import LoginFrame
from ui.navigation import NavigationBar
from ui.dashboard import DashboardFrame
from ui.documents import DocumentsFrame
from ui.reminders import RemindersFrame
from ui.settings import SettingsFrame
from ui.session_lock import SessionLockFrame
from ui.add_document import DocumentModal
from ui.view_document import ViewDocumentModal

logger = logging.getLogger(__name__)


class DocumentGuardianApp(ctk.CTk):
    """Main desktop application window and view controller."""

    def __init__(self, db: Optional[DatabaseManager] = None):
        super().__init__()

        # Window Configuration
        self.title("Document Guardian - Secure Personal Document Management System")
        self.geometry("1120x740")
        self.minsize(980, 620)
        ctk.set_appearance_mode("Light")
        self.configure(fg_color=COLOR_BG)

        # Initialize Services Subsystem
        self.db = db or get_db()
        self.audit = AuditService(self.db)
        self.auth_service = AuthenticationService(self.db, self.audit)
        self.session_manager = get_session(self.audit)
        self.doc_service = DocumentService(self.db, self.audit)
        self.expiry_service = ExpiryService(self.db, self.doc_service)
        self.notifier = NotificationService()
        self.reminder_service = ReminderService(self.expiry_service, self.notifier, self.audit)
        self.file_service = FileService(db=self.db, audit_service=self.audit, document_service=self.doc_service)
        self.export_service = ExportService(db=self.db, document_service=self.doc_service, expiry_service=self.expiry_service, audit_service=self.audit)

        # State
        self.active_user: Optional[User] = None
        self.active_dek: Optional[bytes] = None

        # UI Shell Layout
        self._build_shell()

        # Connect Session Callbacks
        self.session_manager.add_on_lock_listener(self._on_session_locked)
        self.session_manager.add_on_logout_listener(self._on_session_logout)

        # Global Inactivity Activity Monitors
        self.bind_all("<Any-KeyPress>", lambda e: self.session_manager.record_activity())
        self.bind_all("<Button-1>", lambda e: self.session_manager.record_activity())

        # Start periodic inactivity check loop
        self._schedule_inactivity_check()

    def _build_shell(self):
        # 1. Top Navigation Bar (Hidden until logged in)
        self.navbar = NavigationBar(
            self,
            on_navigate=self._switch_view,
            on_lock=self._handle_manual_lock,
            on_logout=self._handle_logout
        )

        # 2. Main Content Container
        self.content_container = ctk.CTkFrame(self, fg_color="transparent")
        self.content_container.pack(fill="both", expand=True)

        # 3. Instantiate Screens
        self.view_login = LoginFrame(
            self.content_container,
            auth_service=self.auth_service,
            on_auth_success=self._on_auth_success
        )

        self.view_dashboard = DashboardFrame(
            self.content_container,
            expiry_service=self.expiry_service,
            on_navigate_to_doc=self._open_document_by_id,
            on_add_doc=self.open_add_modal
        )

        self.view_documents = DocumentsFrame(
            self.content_container,
            document_service=self.doc_service,
            on_add_document=self.open_add_modal,
            on_edit_document=self.open_edit_modal,
            on_view_document=self.open_view_modal
        )

        self.view_reminders = RemindersFrame(
            self.content_container,
            expiry_service=self.expiry_service,
            reminder_service=self.reminder_service,
            on_view_document=self._open_document_by_id
        )

        self.view_settings = SettingsFrame(
            self.content_container,
            auth_service=self.auth_service,
            session_manager=self.session_manager,
            export_service=self.export_service,
            audit_service=self.audit
        )

        self.view_lock = SessionLockFrame(
            self.content_container,
            session_manager=self.session_manager,
            on_unlocked=self._on_session_unlocked,
            on_logout=self._handle_logout
        )

        # Show Login Screen by default
        self._show_login_screen()

    def _show_login_screen(self):
        self.navbar.pack_forget()
        self._hide_all_views()
        self.view_login.reset_fields()
        self.view_login.pack(fill="both", expand=True)

    def _hide_all_views(self):
        for view in (
            self.view_login, self.view_dashboard, self.view_documents,
            self.view_reminders, self.view_settings, self.view_lock
        ):
            view.pack_forget()

    def _switch_view(self, view_name: str):
        if not self.session_manager.is_authenticated or self.session_manager.is_locked:
            return

        self._hide_all_views()
        self.navbar.set_active(view_name)

        if view_name == "Dashboard":
            self.view_dashboard.refresh()
            self.view_dashboard.pack(fill="both", expand=True)
        elif view_name == "My Documents":
            self.view_documents.refresh()
            self.view_documents.pack(fill="both", expand=True)
        elif view_name == "Reminders":
            self.view_reminders.refresh()
            self.view_reminders.pack(fill="both", expand=True)
        elif view_name == "Settings":
            self.view_settings.pack(fill="both", expand=True)

    def _on_auth_success(self, user: User, dek: bytes):
        """Called when user logs in or registers successfully."""
        self.active_user = user
        self.active_dek = dek

        # Start session
        self.session_manager.start_session(user, dek)

        # Update Navigation & views with user context
        self.navbar.set_user(user.username)
        self.navbar.pack(fill="x", before=self.content_container)

        self.view_dashboard.load_user(user.user_id)
        self.view_documents.load_user(user.user_id)
        self.view_reminders.load_user(user.user_id)
        self.view_settings.load_user(user.user_id)

        # Start background reminder scanner
        self.reminder_service.start_background_scanner(user.user_id, interval_seconds=3600)

        # Initial reminder check
        self.reminder_service.check_reminders_for_user(user.user_id, notify=True)

        # Show Dashboard
        self._switch_view("Dashboard")

    def _handle_manual_lock(self):
        self.session_manager.lock_session(reason="User manual lock")

    def _on_session_locked(self):
        """Called by SessionManager event listener when session locks."""
        self.navbar.pack_forget()
        self._hide_all_views()
        username = self.active_user.username if self.active_user else "User"
        self.view_lock.set_user(username)
        self.view_lock.pack(fill="both", expand=True)

    def _on_session_unlocked(self):
        """Called when unlock password succeeds."""
        try:
            self.active_dek = self.session_manager.get_dek()
        except Exception:
            pass

        self.navbar.pack(fill="x", before=self.content_container)
        self._switch_view("Dashboard")

    def _handle_logout(self):
        self.reminder_service.stop_background_scanner()
        self.session_manager.logout()

    def _on_session_logout(self):
        """Called by SessionManager event listener upon logout."""
        self.active_user = None
        self.active_dek = None
        self._show_login_screen()

    def _schedule_inactivity_check(self):
        """Periodically checks inactivity timeout every 1 second and updates live navbar timer."""
        try:
            self.session_manager.check_inactivity()
            if self.session_manager.is_authenticated and not self.session_manager.is_locked:
                import time
                elapsed = time.time() - self.session_manager.last_activity_time
                remaining = max(0, int(self.session_manager.timeout_seconds - elapsed))
                mins, secs = divmod(remaining, 60)
                self.navbar.set_timer_text(f"⏱️ {mins:02d}:{secs:02d}")
        except Exception as e:
            logger.error(f"Error checking inactivity: {e}")
        self.after(1000, self._schedule_inactivity_check)

    # Modal Handlers
    def open_add_modal(self):
        if not self.active_user or not self.active_dek:
            return
        DocumentModal(
            master=self,
            user_id=self.active_user.user_id,
            dek=self.active_dek,
            doc_service=self.doc_service,
            file_service=self.file_service,
            on_saved=self._on_document_data_changed
        )

    def open_edit_modal(self, doc: Document):
        if not self.active_user or not self.active_dek:
            return
        DocumentModal(
            master=self,
            user_id=self.active_user.user_id,
            dek=self.active_dek,
            doc_service=self.doc_service,
            file_service=self.file_service,
            on_saved=self._on_document_data_changed,
            editing_document=doc
        )

    def open_view_modal(self, doc: Document):
        if not self.active_user or not self.active_dek:
            return
        ViewDocumentModal(
            master=self,
            document=doc,
            user_id=self.active_user.user_id,
            dek=self.active_dek,
            doc_service=self.doc_service,
            file_service=self.file_service
        )

    def _open_document_by_id(self, document_id: int):
        if not self.active_user or not self.active_dek:
            return
        doc = self.doc_service.get_document_by_id(document_id, self.active_user.user_id)
        if doc:
            self.open_view_modal(doc)

    def _on_document_data_changed(self):
        """Refreshes active views after add/edit."""
        if self.view_dashboard.winfo_ismapped():
            self.view_dashboard.refresh()
        if self.view_documents.winfo_ismapped():
            self.view_documents.refresh()
        if self.view_reminders.winfo_ismapped():
            self.view_reminders.refresh()
