"""
Prevention Module — Zero-Day Prevention System
Handles alert logging, process termination, CSV export, and email alerting.
"""

import csv
import json
import logging
import os
import smtplib
import threading
from datetime import datetime, timezone
from email.mime.text import MIMEText

import psutil

import config

logger = logging.getLogger(__name__)

LOGS_DIR: str = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
ALERTS_FILE: str = os.path.join(LOGS_DIR, "alerts.json")

# Threading lock to prevent concurrent writes to alerts.json
_ALERTS_LOCK = threading.Lock()


def log_alert(process_info: dict, *, threat_level: str = "unknown", score: int = 0) -> None:
    """
    Append a suspicious process alert to logs/alerts.json.

    Creates the logs directory and alerts file if they do not exist.
    Each alert includes a UTC timestamp, threat level, and threat score.
    Uses a threading lock to prevent file corruption under concurrent access.

    Args:
        process_info: Dictionary containing process details (pid, name, cpu, memory, path).
        threat_level: Pre-computed risk level ('high', 'medium', 'low', or 'unknown').
        score:        Pre-computed threat score (0–100).
    """
    os.makedirs(LOGS_DIR, exist_ok=True)

    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pid": process_info.get("pid"),
        "name": process_info.get("name"),
        "cpu": process_info.get("cpu"),
        "memory": process_info.get("memory"),
        "path": process_info.get("path"),
        "threat_level": threat_level,
        "threat_score": score,
    }

    with _ALERTS_LOCK:
        alerts: list = []
        if os.path.isfile(ALERTS_FILE):
            try:
                with open(ALERTS_FILE, "r", encoding="utf-8") as f:
                    alerts = json.load(f)
            except (json.JSONDecodeError, IOError):
                logger.warning("alerts.json was corrupted — starting fresh.")
                alerts = []

        alerts.append(alert)

        with open(ALERTS_FILE, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2)

    logger.info(
        "Alert saved — process: %s (PID: %s) | level: %s | score: %d",
        process_info.get("name"),
        process_info.get("pid"),
        threat_level,
        score,
    )

    if config.EMAIL_ALERTS_ENABLED:
        send_email_alert(process_info, threat_level=threat_level, score=score)


def kill_process(pid: int) -> None:
    """
    Safely terminate a process by PID using psutil.

    Handles NoSuchProcess, AccessDenied, and ZombieProcess exceptions
    without crashing the program.

    Args:
        pid: The process ID to terminate.
    """
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        logger.info("Successfully terminated process with PID: %d", pid)
    except psutil.NoSuchProcess:
        logger.warning("Process PID %d does not exist.", pid)
    except psutil.AccessDenied:
        logger.warning("Access denied when attempting to terminate PID %d.", pid)
    except psutil.ZombieProcess:
        logger.warning("Process PID %d is a zombie and cannot be terminated.", pid)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Failed to terminate PID %d: %s", pid, exc)


def export_alerts_to_csv(output_path: str) -> str:
    """
    Export all recorded alerts from alerts.json to a CSV file.

    Args:
        output_path: Destination path for the CSV file.

    Returns:
        The absolute path to the generated CSV file.
    """
    with _ALERTS_LOCK:
        alerts: list = []
        if os.path.isfile(ALERTS_FILE):
            try:
                with open(ALERTS_FILE, "r", encoding="utf-8") as f:
                    alerts = json.load(f)
            except (json.JSONDecodeError, IOError) as exc:
                logger.error("Failed to read alerts.json for CSV export: %s", exc)
                alerts = []

    fieldnames = ["timestamp", "pid", "name", "cpu", "memory", "path", "threat_level", "threat_score"]

    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(alerts)

    logger.info("Exported %d alerts to %s", len(alerts), output_path)
    return os.path.abspath(output_path)


def send_email_alert(
    process_info: dict,
    *,
    threat_level: str = "unknown",
    score: int = 0,
) -> None:
    """
    Send an SMTP email notification for a suspicious process (placeholder).

    Configure SMTP settings in config.py and set EMAIL_ALERTS_ENABLED = True.
    In production, store credentials in environment variables rather than
    plain-text config.

    Args:
        process_info: Dictionary containing process details.
        threat_level: Risk level string ('high', 'medium', or 'low').
        score:        Numeric threat score.
    """
    if not config.EMAIL_ALERTS_ENABLED:
        return

    subject = (
        f"[ZDP Alert] {threat_level.upper()} risk process detected — "
        f"{process_info.get('name')} (PID {process_info.get('pid')})"
    )
    body = (
        f"Zero-Day Prevention System — Threat Alert\n\n"
        f"Process  : {process_info.get('name')}\n"
        f"PID      : {process_info.get('pid')}\n"
        f"Path     : {process_info.get('path')}\n"
        f"CPU      : {process_info.get('cpu')} %\n"
        f"Memory   : {process_info.get('memory')} MB\n"
        f"Level    : {threat_level.upper()}\n"
        f"Score    : {score}/100\n"
        f"Time     : {datetime.now(timezone.utc).isoformat()}\n"
    )

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = config.EMAIL_SENDER
    msg["To"] = config.EMAIL_RECIPIENT

    try:
        with smtplib.SMTP(config.EMAIL_SMTP_HOST, config.EMAIL_SMTP_PORT, timeout=10) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(config.EMAIL_USERNAME, config.EMAIL_PASSWORD)
            smtp.sendmail(config.EMAIL_SENDER, [config.EMAIL_RECIPIENT], msg.as_string())
        logger.info("Email alert sent for process %s", process_info.get("name"))
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Failed to send email alert: %s", exc)
