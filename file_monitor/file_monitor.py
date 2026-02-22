"""
File System Monitoring Agent — Zero-Day Prevention System
Monitors a directory for file creation, modification, and deletion events
using the watchdog library.
"""

import logging
import time
from datetime import datetime, timezone

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

import config

logger = logging.getLogger(__name__)


class _AlertHandler(FileSystemEventHandler):
    """Log file system events with a UTC timestamp."""

    def _log_event(self, event_type: str, path: str) -> None:
        """Emit a log entry for a file-system event.

        Args:
            event_type: Human-readable event type ('CREATED', 'MODIFIED', 'DELETED').
            path:       Absolute path of the affected file.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        logger.info("File %s | %s | %s", event_type, path, timestamp)

    def on_created(self, event) -> None:
        """Handle file-creation events (directories are ignored)."""
        if not event.is_directory:
            self._log_event("CREATED", event.src_path)

    def on_modified(self, event) -> None:
        """Handle file-modification events (directories are ignored)."""
        if not event.is_directory:
            self._log_event("MODIFIED", event.src_path)

    def on_deleted(self, event) -> None:
        """Handle file-deletion events (directories are ignored)."""
        if not event.is_directory:
            self._log_event("DELETED", event.src_path)


def start_file_monitor(path: str) -> None:
    """
    Start monitoring *path* for file-system events.

    Blocks until a KeyboardInterrupt is received, then cleanly stops the observer.

    Args:
        path: The directory path to monitor recursively.
    """
    logger.info("File monitor started on: %s", path)
    event_handler = _AlertHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logger.info("File monitor stopped.")
    observer.join()


if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL),
        format=config.LOG_FORMAT,
        datefmt=config.LOG_DATE_FORMAT,
    )
    monitor_path = sys.argv[1] if len(sys.argv) > 1 else "."
    start_file_monitor(monitor_path)
