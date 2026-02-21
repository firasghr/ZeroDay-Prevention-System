"""
File System Monitoring Agent
Monitors a directory for file creation, modification, and deletion events
using the watchdog library.
"""

import time
from datetime import datetime, timezone

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class _AlertHandler(FileSystemEventHandler):
    """Log file system events to stdout with a timestamp."""

    def _log_event(self, event_type, path):
        timestamp = datetime.now(timezone.utc).isoformat()
        print(f"[FILE MONITOR] Event: {event_type} | Path: {path} | Timestamp: {timestamp}")

    def on_created(self, event):
        if not event.is_directory:
            self._log_event("CREATED", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._log_event("MODIFIED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._log_event("DELETED", event.src_path)


def start_file_monitor(path):
    """
    Start monitoring *path* for file system events.

    Blocks until a KeyboardInterrupt is received, then cleanly stops the observer.
    """
    print(f"[*] File monitor started on: {path}")
    event_handler = _AlertHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("[*] File monitor stopped.")
    observer.join()


if __name__ == "__main__":
    import sys
    monitor_path = sys.argv[1] if len(sys.argv) > 1 else "."
    start_file_monitor(monitor_path)
