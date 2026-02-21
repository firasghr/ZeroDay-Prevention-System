"""
Detection Engine
Loads a process whitelist and evaluates whether a process is suspicious.
"""

import json
import os

WHITELIST_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "whitelist.json"
)

CPU_THRESHOLD = 80        # percent
MEMORY_THRESHOLD = 500    # MB

_whitelist_cache: set = set()
_whitelist_mtime: float = 0.0


def load_whitelist():
    """
    Load the process whitelist from whitelist.json.

    The result is cached and only reloaded when the file modification time
    changes, avoiding redundant disk I/O on every call.
    Returns a set of whitelisted process names.
    Falls back to an empty set if the file is missing or malformed.
    """
    global _whitelist_cache, _whitelist_mtime  # pylint: disable=global-statement
    try:
        mtime = os.path.getmtime(WHITELIST_PATH)
        if mtime == _whitelist_mtime:
            return _whitelist_cache
        with open(WHITELIST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        _whitelist_cache = set(data.get("whitelist", []))
        _whitelist_mtime = mtime
        return _whitelist_cache
    except (FileNotFoundError, json.JSONDecodeError, IOError) as exc:
        print(f"[WARNING] Could not load whitelist: {exc}")
        return _whitelist_cache


def is_process_suspicious(process_info):
    """
    Determine whether a process is suspicious.

    A process is considered suspicious if ANY of the following is true:
      - Its name is not in the whitelist
      - Its CPU usage exceeds CPU_THRESHOLD percent
      - Its memory usage exceeds MEMORY_THRESHOLD MB
      - Its executable path is None or empty

    Returns True if suspicious, False otherwise.
    """
    whitelist = load_whitelist()

    name = process_info.get("name", "")
    cpu = process_info.get("cpu", 0)
    memory = process_info.get("memory", 0)
    path = process_info.get("path")

    if name not in whitelist:
        return True
    if cpu > CPU_THRESHOLD:
        return True
    if memory > MEMORY_THRESHOLD:
        return True
    if not path:
        return True

    return False
