"""UI package exports for Document Guardian."""
from ui.theme import (
    FONT_TITLE, FONT_SUBTITLE, FONT_BODY, FONT_BODY_BOLD, FONT_SMALL,
    COLOR_PRIMARY, COLOR_PRIMARY_HOVER, COLOR_SECONDARY, COLOR_BORDER, COLOR_SURFACE,
    COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY, COLOR_STATUS_VALID, COLOR_STATUS_ATTENTION,
    COLOR_STATUS_EXPIRED, DISCLAIMER_TEXT
)
from ui.login import LoginFrame
from ui.navigation import NavigationBar
from ui.dashboard import DashboardFrame
from ui.documents import DocumentsFrame
from ui.reminders import RemindersFrame
from ui.settings import SettingsFrame
from ui.session_lock import SessionLockFrame
from ui.add_document import DocumentModal
from ui.view_document import ViewDocumentModal
from ui.app import DocumentGuardianApp

__all__ = [
    "DocumentGuardianApp",
    "LoginFrame",
    "NavigationBar",
    "DashboardFrame",
    "DocumentsFrame",
    "RemindersFrame",
    "SettingsFrame",
    "SessionLockFrame",
    "DocumentModal",
    "ViewDocumentModal",
]
