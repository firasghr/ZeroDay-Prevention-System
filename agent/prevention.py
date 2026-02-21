"""
Prevention Module
Handles alert logging and process termination.
"""

import json
import os
from datetime import datetime, timezone

import psutil

LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
ALERTS_FILE = os.path.join(LOGS_DIR, "alerts.json")


def log_alert(process_info):
    """
    Append a suspicious process alert to logs/alerts.json.

    Creates the logs directory and alerts file if they do not exist.
    Each alert includes a UTC timestamp alongside the process details.
    """
    os.makedirs(LOGS_DIR, exist_ok=True)

    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pid": process_info.get("pid"),
        "name": process_info.get("name"),
        "cpu": process_info.get("cpu"),
        "memory": process_info.get("memory"),
        "path": process_info.get("path"),
    }

    alerts = []
    if os.path.isfile(ALERTS_FILE):
        try:
            with open(ALERTS_FILE, "r", encoding="utf-8") as f:
                alerts = json.load(f)
        except (json.JSONDecodeError, IOError):
            alerts = []

    alerts.append(alert)

    with open(ALERTS_FILE, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)

    print(f"[LOG] Alert saved for process: {process_info.get('name')} (PID: {process_info.get('pid')})")


def kill_process(pid):
    """
    Safely terminate a process by PID using psutil.

    Handles NoSuchProcess, AccessDenied, and ZombieProcess exceptions
    without crashing the program.
    """
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        print(f"[PREVENTION] Successfully terminated process with PID: {pid}")
    except psutil.NoSuchProcess:
        print(f"[PREVENTION] Process PID {pid} does not exist.")
    except psutil.AccessDenied:
        print(f"[PREVENTION] Access denied when attempting to terminate PID {pid}.")
    except psutil.ZombieProcess:
        print(f"[PREVENTION] Process PID {pid} is a zombie process and cannot be terminated.")
    except Exception as exc:  # pylint: disable=broad-except
        print(f"[PREVENTION] Failed to terminate PID {pid}: {exc}")
