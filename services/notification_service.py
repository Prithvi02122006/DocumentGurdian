"""
Desktop notification service for Document Guardian.
Uses Plyer for native desktop notifications with defensive fallbacks.
Guarantees the application never crashes if the OS notification daemon fails.
"""

import logging
from typing import Optional, List, Dict
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

try:
    from plyer import notification
    HAS_PLYER = True
except ImportError:
    HAS_PLYER = False
    logger.warning("Plyer not found. Using internal fallback notification dispatcher.")


class NotificationService:
    """Dispatches cross-platform desktop notifications with delivery tracking and fallbacks."""

    def __init__(self, enable_os_notifications: bool = True):
        self.enable_os_notifications = enable_os_notifications
        self._history: List[Dict[str, str]] = []

    def notify(
        self,
        title: str,
        message: str,
        app_name: str = "Document Guardian",
        timeout: int = 10
    ) -> bool:
        """
        Sends a native desktop notification.
        Returns True if successful, False if dispatch failed.
        Never raises exceptions to caller.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        record = {
            "title": title,
            "message": message,
            "app_name": app_name,
            "timestamp": timestamp,
            "delivered": False
        }

        if not self.enable_os_notifications:
            record["delivered"] = True
            self._history.append(record)
            return True

        if HAS_PLYER:
            try:
                notification.notify(
                    title=title,
                    message=message,
                    app_name=app_name,
                    timeout=timeout
                )
                record["delivered"] = True
                logger.info(f"Desktop notification delivered: '{title}'")
            except Exception as e:
                logger.warning(f"OS notification dispatch failed: {e}. Falling back to internal log.")
                record["error"] = str(e)
        else:
            logger.info(f"Fallback notification logged: {title} - {message}")
            record["delivered"] = True

        self._history.append(record)
        return record["delivered"]

    def get_history(self) -> List[Dict[str, str]]:
        """Returns log of all notifications dispatched during runtime."""
        return list(self._history)

    def clear_history(self) -> None:
        self._history.clear()
