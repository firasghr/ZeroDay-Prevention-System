"""
Centralized Configuration — Zero-Day Prevention System
All tuneable parameters live here so they can be adjusted without touching
business-logic code.
"""

import os

# ── Process Monitor ──────────────────────────────────────────────────────────
PROCESS_MONITOR_INTERVAL: int = 2       # seconds between process-scan cycles

# ── Network Monitor ──────────────────────────────────────────────────────────
NETWORK_MONITOR_INTERVAL: int = 5       # seconds between connection-scan cycles

# ── Detection Engine ─────────────────────────────────────────────────────────
CPU_THRESHOLD: float = 85.0             # % — flag a process if CPU exceeds this
MEMORY_THRESHOLD: float = 800.0         # MB — flag a process if RSS exceeds this

# ── Threat Scoring ────────────────────────────────────────────────────────────
THREAT_HIGH_SCORE: int = 70             # score >= this → HIGH risk
THREAT_MEDIUM_SCORE: int = 30           # score >= this → MEDIUM risk (else LOW)

# ── Trusted Directories ───────────────────────────────────────────────────────
# Processes whose executable lives under these paths are never flagged.
_USER_LIBRARY: str = os.path.join(os.path.expanduser("~"), "Library") + "/"
TRUSTED_DIRS: tuple = (
    "/System/",
    "/usr/",
    "/Applications/",
    "/Library/",
    "/opt/homebrew/",
    _USER_LIBRARY,
)

# ── Suspicious Directories ────────────────────────────────────────────────────
# Processes whose executable lives under these paths are always flagged.
SUSPICIOUS_DIRS: tuple = (
    "/tmp/",
    "/var/tmp/",
    "/private/tmp/",
)

# ── Dashboard ────────────────────────────────────────────────────────────────
DASHBOARD_HOST: str = "0.0.0.0"
DASHBOARD_PORT: int = 5001
DASHBOARD_REFRESH_INTERVAL: int = 5     # seconds (used in front-end JS)

# ── Auto-Prevention Mode ──────────────────────────────────────────────────────
# When True, HIGH-risk processes are automatically terminated.
# Use with caution in production environments.
AUTO_PREVENTION_ENABLED: bool = False

# ── Email Alerts (SMTP placeholder) ──────────────────────────────────────────
EMAIL_ALERTS_ENABLED: bool = False
EMAIL_SMTP_HOST: str = "smtp.gmail.com"
EMAIL_SMTP_PORT: int = 587
EMAIL_SENDER: str = "alerts@yourdomain.com"
EMAIL_RECIPIENT: str = "admin@yourdomain.com"
EMAIL_USERNAME: str = ""                # SMTP auth username
EMAIL_PASSWORD: str = ""                # Use an env-var or secrets manager in production

# ── Logging ──────────────────────────────────────────────────────────────────
LOG_LEVEL: str = "INFO"
LOG_FORMAT: str = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
LOG_DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"
