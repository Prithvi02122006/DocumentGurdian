"""
Reminder engine for Document Guardian.
Identifies expiring and review-due documents, prevents duplicate notifications,
and dispatches local desktop alerts.
"""

import threading
import time
import logging
from datetime import date
from typing import Optional, List, Set
from models.document import DocumentStatus
from services.expiry_service import ExpiryService, DocumentExpiryInfo
from services.notification_service import NotificationService
from services.audit_service import AuditService

logger = logging.getLogger(__name__)


class ReminderService:
    """Manages reminder scans, de-duplication, and notification dispatch."""

    def __init__(
        self,
        expiry_service: Optional[ExpiryService] = None,
        notification_service: Optional[NotificationService] = None,
        audit_service: Optional[AuditService] = None
    ):
        self.expiry_service = expiry_service or ExpiryService()
        self.notifier = notification_service or NotificationService()
        self.audit = audit_service

        self._notified_cache: Set[str] = set()
        self._cache_lock = threading.Lock()

        # Background thread control
        self._stop_event = threading.Event()
        self._bg_thread: Optional[threading.Thread] = None

    def check_reminders_for_user(
        self,
        user_id: int,
        notify: bool = True,
        reference_date: Optional[date] = None
    ) -> List[DocumentExpiryInfo]:
        """
        Scans all documents for a user, identifies those requiring attention,
        and optionally dispatches de-duplicated desktop notifications.
        """
        reminders = self.expiry_service.get_reminders_list(user_id, reference_date=reference_date)

        if not notify:
            return reminders

        for item in reminders:
            doc = item.document
            cache_key = f"{doc.document_id}:{item.status.value}:{item.relevant_date}"

            with self._cache_lock:
                if cache_key in self._notified_cache:
                    continue
                self._notified_cache.add(cache_key)

            # Build formal, public-service style notification
            title = f"Document Guardian: {item.status.value}"
            if item.status == DocumentStatus.EXPIRED:
                msg = (
                    f"Notice: Your {doc.document_type} ({doc.document_number_masked}) "
                    f"{item.days_remaining_display}. Please arrange for renewal."
                )
            elif item.status == DocumentStatus.REVIEW_DUE:
                msg = (
                    f"Notice: Your {doc.document_type} ({doc.document_number_masked}) "
                    f"{item.days_remaining_display}. Please verify document details."
                )
            elif item.status == DocumentStatus.ATTENTION_REQUIRED:
                msg = (
                    f"Reminder: Your {doc.document_type} ({doc.document_number_masked}) "
                    f"{item.days_remaining_display}."
                )
            else:
                msg = f"Reminder: Your {doc.document_type} ({doc.document_number_masked}) requires attention."

            self.notifier.notify(
                title=title,
                message=msg,
                app_name="Document Guardian",
                timeout=10
            )

        return reminders

    def start_background_scanner(self, user_id: int, interval_seconds: int = 3600) -> None:
        """Starts a background daemon thread that periodically scans for reminders."""
        self.stop_background_scanner()
        self._stop_event.clear()

        def _worker():
            logger.info(f"Background reminder scanner started for user {user_id} (interval: {interval_seconds}s)")
            while not self._stop_event.is_set():
                try:
                    self.check_reminders_for_user(user_id, notify=True)
                except Exception as e:
                    logger.error(f"Error in background reminder scanner: {e}")

                # Wait in small increments so stop_event is responsive
                slept = 0
                while slept < interval_seconds and not self._stop_event.is_set():
                    time.sleep(min(1.0, interval_seconds - slept))
                    slept += 1.0

        self._bg_thread = threading.Thread(target=_worker, daemon=True)
        self._bg_thread.start()

    def stop_background_scanner(self) -> None:
        """Stops the background scanner thread gracefully."""
        self._stop_event.set()
        if self._bg_thread and self._bg_thread.is_alive():
            self._bg_thread.join(timeout=2.0)
        self._bg_thread = None

    def clear_cache(self) -> None:
        """Clears notification deduplication cache."""
        with self._cache_lock:
            self._notified_cache.clear()
