"""
Detection Engine
Loads a process whitelist and evaluates whether a process is suspicious.

Design (EDR-style):
  1. Trusted-path fast-path  → never flag macOS/system/homebrew processes
  2. Browser-helper bypass   → never flag common renderer/GPU helpers
  3. Suspicious-path check   → always flag execution from temp / Downloads
  4. Whitelist / path check  → flag if name unknown AND path not trusted
  5. Resource thresholds     → flag runaway CPU / memory
"""

import json
import os

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WHITELIST_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "whitelist.json"
)

CPU_THRESHOLD    = 85    # percent  – raised to reduce false positives
MEMORY_THRESHOLD = 800   # MB       – raised to reduce false positives

# Directories whose processes are unconditionally trusted
_USER_LIBRARY = os.path.join(os.path.expanduser("~"), "Library") + "/"
TRUSTED_DIRS: tuple[str, ...] = (
    "/System/",
    "/usr/",
    "/Applications/",
    "/Library/",
    "/opt/homebrew/",
    _USER_LIBRARY,                # e.g. /Users/<name>/Library/ — covers vendor auto-updaters
)

# Sub-strings in a process name that identify safe browser/OS helpers
BROWSER_HELPER_PATTERNS: tuple[str, ...] = (
    "Helper",
    "Renderer",
    "GPU",
    "WebKit",
    "mdworker",
)

# Directories from which a binary is always treated as suspicious
SUSPICIOUS_DIRS: tuple[str, ...] = (
    "/tmp/",
    "/var/tmp/",
    "/private/tmp/",
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
        print(f"[WARNING] Could not load whitelist: {exc}")
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
        print(f"[ERROR] is_process_suspicious raised an unexpected error: {exc}")
        return False
