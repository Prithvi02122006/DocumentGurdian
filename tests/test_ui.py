"""
Unit and integration tests for CustomTkinter UI subsystem:
Screen creation, view transitions, authentication events, locking, and modal generation.
"""

import pytest
import customtkinter as ctk
from database.database import DatabaseManager
from security.authentication import AuthenticationService
from ui.app import DocumentGuardianApp
from ui.add_document import DocumentModal
from ui.theme import DISCLAIMER_TEXT
from models.document import DocumentType


@pytest.fixture
def ui_app(memory_db):
    """Instantiates DocumentGuardianApp with an in-memory database."""
    app = DocumentGuardianApp(db=memory_db)
    # Hide window from appearing on screen during automated test run
    app.withdraw()
    yield app
    try:
        app.destroy()
    except Exception:
        pass


def test_ui_initialization_and_disclaimer(ui_app):
    """Verifies that the application initializes cleanly and displays the academic disclaimer."""
    assert ui_app.title() == "Document Guardian - Secure Personal Document Management System"

    # Verify all views are instantiated
    assert ui_app.view_login is not None
    assert ui_app.view_dashboard is not None
    assert ui_app.view_documents is not None
    assert ui_app.view_reminders is not None
    assert ui_app.view_settings is not None
    assert ui_app.view_lock is not None
    assert ui_app.navbar is not None

    # Check disclaimer in theme
    assert "STUDENT ACADEMIC PROJECT" in DISCLAIMER_TEXT


def test_ui_authentication_and_view_switching(ui_app, memory_db):
    """Verifies that logging in transitions the shell to the Dashboard and enables navigation."""
    auth = AuthenticationService(memory_db)
    reg_res = auth.register("ui_citizen", "UiMasterPass#2026", "UiMasterPass#2026")
    assert reg_res.success

    # Trigger login success
    ui_app._on_auth_success(reg_res.user, reg_res.dek)

    # Check active state
    assert ui_app.active_user == reg_res.user
    assert ui_app.active_dek == reg_res.dek
    assert ui_app.navbar.current_username == "ui_citizen"
    assert ui_app.navbar.active_tab == "Dashboard"

    # Switch views
    ui_app._switch_view("My Documents")
    assert ui_app.navbar.active_tab == "My Documents"

    ui_app._switch_view("Reminders")
    assert ui_app.navbar.active_tab == "Reminders"

    ui_app._switch_view("Settings")
    assert ui_app.navbar.active_tab == "Settings"


def test_ui_session_lock_and_unlock_flow(ui_app, memory_db):
    """Verifies that locking displays the lock screen and unlocking restores the view."""
    auth = AuthenticationService(memory_db)
    reg_res = auth.register("lock_tester", "LockMasterPass#2026", "LockMasterPass#2026")
    ui_app._on_auth_success(reg_res.user, reg_res.dek)

    # 1. Trigger lock
    ui_app._handle_manual_lock()
    assert ui_app.session_manager.is_locked is True

    # 2. Unlock with wrong password
    ui_app.view_lock.pwd_entry.insert(0, "WrongPassword#123")
    ui_app.view_lock._handle_unlock()
    assert ui_app.session_manager.is_locked is True

    # 3. Unlock with correct password
    ui_app.view_lock.pwd_entry.insert(0, "LockMasterPass#2026")
    ui_app.view_lock._handle_unlock()
    assert ui_app.session_manager.is_locked is False


def test_add_document_modal_dynamic_fields(ui_app, memory_db):
    """Verifies that DocumentModal dynamically configures fields for Passport vs Aadhaar vs PAN."""
    auth = AuthenticationService(memory_db)
    reg_res = auth.register("modal_tester", "ModalMasterPass#2026", "ModalMasterPass#2026")

    modal = DocumentModal(
        master=ui_app,
        user_id=reg_res.user.user_id,
        dek=reg_res.dek,
        doc_service=ui_app.doc_service,
        file_service=ui_app.file_service,
        on_saved=lambda: None
    )
    modal.withdraw()

    # 1. Default Passport
    assert modal.type_combo.get() == DocumentType.PASSPORT.value
    assert modal.entry_issue_date is not None
    assert modal.entry_expiry_date is not None

    # 2. Switch to Aadhaar -> Expiry date removed, review reminder present
    modal.type_combo.set(DocumentType.AADHAAR.value)
    modal._on_type_changed(DocumentType.AADHAAR.value)
    assert modal.entry_expiry_date is None
    assert modal.entry_review_date is not None

    # 3. Switch to PAN -> Expiry date removed, review reminder present
    modal.type_combo.set(DocumentType.PAN.value)
    modal._on_type_changed(DocumentType.PAN.value)
    assert modal.entry_expiry_date is None
    assert modal.entry_review_date is not None

    modal.destroy()
