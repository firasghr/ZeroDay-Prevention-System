"""
Main Controller — Zero-Day Prevention System
Starts the process monitor, file monitor, network monitor, and web dashboard
in separate threads, keeping the program alive until interrupted.
"""

import os
import threading

from agent import process_monitor
from dashboard.app import app as dashboard_app
from file_monitor import file_monitor
from network import network_monitor

MONITOR_PATH = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_PORT = 5001


def _run_dashboard():
    """Start the Flask dashboard (blocking, runs in its own thread)."""
    dashboard_app.run(debug=False, host="0.0.0.0", port=DASHBOARD_PORT, use_reloader=False)


def main():
    """Launch all monitoring agents and the web dashboard in separate daemon threads."""
    threads = [
        threading.Thread(target=process_monitor.monitor_processes, name="ProcessMonitor", daemon=True),
        threading.Thread(target=file_monitor.start_file_monitor, args=(MONITOR_PATH,), name="FileMonitor", daemon=True),
        threading.Thread(target=network_monitor.monitor_network, name="NetworkMonitor", daemon=True),
        threading.Thread(target=_run_dashboard, name="Dashboard", daemon=True),
    ]

    for thread in threads:
        thread.start()
        print(f"[*] Started thread: {thread.name}")

    print(f"[*] Dashboard available at http://localhost:{DASHBOARD_PORT}")
    print("[*] Zero-day prevention system running. Press Ctrl+C to stop.")
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print("\n[*] Shutting down zero-day prevention system.")


if __name__ == "__main__":
    main()
