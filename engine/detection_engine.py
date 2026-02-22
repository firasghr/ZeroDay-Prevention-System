"""
Detection Engine — Zero-Day Prevention System

Loads a process whitelist and evaluates whether a process is suspicious.
Also provides a numeric threat-scoring function for risk prioritisation.

Design (EDR-style):
  1. Trusted-path fast-path  → never flag macOS/system/homebrew processes
  2. Browser-helper bypass   → never flag common renderer/GPU helpers
  3. Suspicious-path check   → always flag execution from temp / Downloads
  4. Whitelist / path check  → flag if name unknown AND path not trusted
  5. Resource thresholds     → flag runaway CPU / memory
"""

import json
import logging
import os

import config

# ---------------------------------------------------------------------------
# Module logger
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration — imported from config.py; re-exported so that existing
# callers (and tests) can still reference detection_engine.CPU_THRESHOLD etc.
# ---------------------------------------------------------------------------

WHITELIST_PATH: str = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "whitelist.json"
)

CPU_THRESHOLD: float = config.CPU_THRESHOLD
MEMORY_THRESHOLD: float = config.MEMORY_THRESHOLD
TRUSTED_DIRS: tuple = config.TRUSTED_DIRS
SUSPICIOUS_DIRS: tuple = config.SUSPICIOUS_DIRS

# Sub-strings in a process name that identify safe browser/OS helpers
BROWSER_HELPER_PATTERNS: tuple = (
    "Helper",
    "Renderer",
    "GPU",
    "WebKit",
    "mdworker",
)

# ---------------------------------------------------------------------------
# Whitelist cache (reloaded only when the file changes on disk)
# ---------------------------------------------------------------------------

_whitelist_cache: set = set()
_whitelist_mtime: float = 0.0


def load_whitelist() -> set:
    """
    Load the process whitelist from whitelist.json.

    Caches the result and only re-reads the file when its mtime changes,
    avoiding redundant disk I/O on every call.
    Falls back to the last good cache (or empty set) on any error.
    """
    global _whitelist_cache, _whitelist_mtime  # pylint: disable=global-statement
    try:
        mtime = os.path.getmtime(WHITELIST_PATH)
        if mtime == _whitelist_mtime:
            return _whitelist_cache
        with open(WHITELIST_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        _whitelist_cache = set(data.get("whitelist", []))
        _whitelist_mtime = mtime
    except (FileNotFoundError, json.JSONDecodeError, IOError) as exc:
        logger.warning("Could not load whitelist: %s", exc)
    return _whitelist_cache


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def is_trusted_path(path: str | None) -> bool:
    """
    Return True if *path* starts with one of the well-known trusted
    macOS / Homebrew directories.

    A None or empty path is never trusted.
    """
    if not path:
        return False
    return any(path.startswith(d) for d in TRUSTED_DIRS)


def _is_suspicious_path(path: str | None) -> bool:
    """
    Return True if *path* indicates execution from a high-risk location
    (temp directory, user Downloads folder).
    """
    if not path:
        return True  # missing path is itself suspicious

    # Standard temp locations
    if any(path.startswith(d) for d in SUSPICIOUS_DIRS):
        return True

    # User Downloads folder  (~/Downloads/...)
    downloads = os.path.join(os.path.expanduser("~"), "Downloads")
    if path.startswith(downloads + os.sep) or path.startswith(downloads + "/"):
        return True

    return False


def _is_browser_helper(name: str) -> bool:
    """Return True if the process name matches a known browser/OS helper pattern."""
    return any(pattern in name for pattern in BROWSER_HELPER_PATTERNS)


def _path_is_accessible(path: str | None) -> bool:
    """Return True if *path* points to a real, readable file."""
    if not path:
        return False
    try:
        return os.path.isfile(path) and os.access(path, os.R_OK)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Primary detection function
# ---------------------------------------------------------------------------

def is_process_suspicious(process_info: dict) -> bool:
    """
    Determine whether a process should be flagged as suspicious.

    Evaluation priority (highest → lowest):
      1. Trusted-path fast-path   – immediately return False
      2. Browser-helper patterns  – immediately return False
      3. Accessible path check    – well-formed, readable paths are benign
      4. Suspicious-path check    – temp / Downloads → immediately return True
      5. Whitelist / path guard   – unknown name outside trusted dirs → True
      6. Resource thresholds      – runaway CPU or memory → True

    Returns True only when there is genuine cause for suspicion.
    Never raises an exception.
    """
    try:
        name   = process_info.get("name", "") or ""
        cpu    = process_info.get("cpu",  0)   or 0
        memory = process_info.get("memory", 0) or 0
        path   = process_info.get("path")

        # ------------------------------------------------------------------
        # 1. Trusted-path fast-path
        #    Processes living in /System/, /usr/, /Applications/, /Library/,
        #    or /opt/homebrew/ are always safe – skip all further checks.
        # ------------------------------------------------------------------
        if is_trusted_path(path):
            return False

        # ------------------------------------------------------------------
        # 2. Browser / macOS helper bypass
        #    Renderer, GPU, WebKit, and mdworker processes are legitimate
        #    children of browsers and macOS daemons.
        # ------------------------------------------------------------------
        if _is_browser_helper(name):
            return False

        # ------------------------------------------------------------------
        # 3. Accessible-path sanity check
        #    A process with a real, readable executable path that also lives
        #    in a non-suspicious location is treated as benign at this stage.
        # ------------------------------------------------------------------
        if _path_is_accessible(path) and not _is_suspicious_path(path):
            whitelist = load_whitelist()
            # If the name is known-good, it is clean regardless of threshold.
            # (Thresholds are still applied below for *unknown* names.)
            if name in whitelist:
                # Still flag runaway resource usage even for whitelisted names
                if cpu > CPU_THRESHOLD:
                    return True
                if memory > MEMORY_THRESHOLD:
                    return True
                return False

        # ------------------------------------------------------------------
        # 4. Suspicious-path check
        #    Execution from /tmp/, /var/tmp/, /private/tmp/, or ~/Downloads
        #    is always suspicious, regardless of name.
        # ------------------------------------------------------------------
        if _is_suspicious_path(path):
            return True

        # ------------------------------------------------------------------
        # 5. Whitelist / path guard
        #    If the process name is not in the whitelist AND its path is not
        #    in a trusted directory, flag it.
        # ------------------------------------------------------------------
        whitelist = load_whitelist()
        if name not in whitelist and not is_trusted_path(path):
            return True

        # ------------------------------------------------------------------
        # 6. Resource thresholds
        #    A known-good process that suddenly spikes CPU or RAM is still
        #    worth flagging (possible injection / cryptominer behavior).
        # ------------------------------------------------------------------
        if cpu > CPU_THRESHOLD:
            return True
        if memory > MEMORY_THRESHOLD:
            return True

        return False

    except Exception as exc:  # pylint: disable=broad-except
        # Safety net: log and return False to avoid disruptive false positives
        logger.error("is_process_suspicious raised an unexpected error: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Threat Scoring
# ---------------------------------------------------------------------------

def calculate_threat_score(process_info: dict) -> int:
    """
    Compute a numeric threat score (0–100) for a process.

    Scoring criteria (additive):
      - Executed from a suspicious directory (/tmp/, etc.) : +40
      - Process name not found in whitelist                : +30
      - No executable path available                       : +20
      - CPU usage exceeds CPU_THRESHOLD                    : +30
      - Memory usage exceeds MEMORY_THRESHOLD              : +20

    Returns an integer clamped to [0, 100].
    """
    try:
        name   = process_info.get("name", "") or ""
        cpu    = process_info.get("cpu",  0)   or 0
        memory = process_info.get("memory", 0) or 0
        path   = process_info.get("path")

        score = 0

        # Suspicious execution path
        if _is_suspicious_path(path):
            score += 40

        # Not in whitelist
        whitelist = load_whitelist()
        if name not in whitelist:
            score += 30

        # Missing executable path
        if not path:
            score += 20

        # Runaway CPU
        if cpu > CPU_THRESHOLD:
            score += 30

        # Runaway memory
        if memory > MEMORY_THRESHOLD:
            score += 20

        return min(score, 100)

    except Exception as exc:  # pylint: disable=broad-except
        logger.error("calculate_threat_score raised an unexpected error: %s", exc)
        return 0


def get_threat_level(score: int) -> str:
    """
    Translate a numeric threat score into a human-readable risk level.

    Returns 'high', 'medium', or 'low'.
    """
    if score >= config.THREAT_HIGH_SCORE:
        return "high"
    if score >= config.THREAT_MEDIUM_SCORE:
        return "medium"
    return "low"
