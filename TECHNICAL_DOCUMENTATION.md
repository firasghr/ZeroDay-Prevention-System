# Technical Documentation — Zero-Day Prevention System

## 1. Overview

The Zero-Day Prevention System is a multi-threaded, user-space Endpoint Detection and Response (EDR) tool implemented entirely in Python. It provides real-time visibility into process execution, file-system activity, and outgoing network connections, and classifies detected events using a behaviour-based detection engine with a numeric threat-scoring model.

---

## 2. Architecture

### 2.1 Thread Model

`main.py` spawns four long-lived **daemon threads**:

| Thread | Module | Interval |
|---|---|---|
| `ProcessMonitor` | `agent/process_monitor.py` | 2 s (configurable) |
| `FileMonitor` | `file_monitor/file_monitor.py` | event-driven (watchdog) |
| `NetworkMonitor` | `network/network_monitor.py` | 5 s (configurable) |
| `Dashboard` | `dashboard/app.py` | request-driven (Flask) |

All threads share the same process space. Alert data is exchanged via the file system (`logs/alerts.json`) protected by a `threading.Lock()` in `agent/prevention.py`.

### 2.2 Component Interaction

```
main.py
  │
  ├─ process_monitor.monitor_processes()
  │     │
  │     ├─ psutil.process_iter()           [OS interface]
  │     ├─ detection_engine.is_process_suspicious()
  │     ├─ detection_engine.calculate_threat_score()
  │     └─ prevention.log_alert()
  │            └─ logs/alerts.json         [shared state]
  │
  ├─ file_monitor.start_file_monitor()
  │     └─ watchdog.Observer               [OS interface]
  │
  ├─ network_monitor.monitor_network()
  │     └─ psutil.net_connections()        [OS interface]
  │
  └─ dashboard_app.run()
        └─ Flask routes
              ├─ GET /           → render index.html
              ├─ GET /api/alerts → read logs/alerts.json
              └─ GET /api/stats  → aggregate statistics
```

---

## 3. Detection Logic

### 3.1 `is_process_suspicious(process_info)`

The detection engine evaluates each new process through a prioritised decision chain:

```
Priority 1: Trusted-path fast-path
  if path starts with /System/, /usr/, /Applications/, /Library/,
     /opt/homebrew/, or ~/Library/  →  return False  (never flag system processes)

Priority 2: Browser / OS helper bypass
  if name contains "Helper", "Renderer", "GPU", "WebKit", "mdworker"
                                         →  return False

Priority 3: Accessible-path check
  if executable exists on disk AND path is not suspicious:
    if name in whitelist:
      if cpu > CPU_THRESHOLD OR memory > MEMORY_THRESHOLD  →  return True
      else                                                  →  return False

Priority 4: Suspicious-path check
  if path starts with /tmp/, /var/tmp/, /private/tmp/ OR ~/Downloads/
                                         →  return True

Priority 5: Whitelist / path guard
  if name NOT in whitelist AND path NOT in trusted dirs  →  return True

Priority 6: Resource thresholds
  if cpu > CPU_THRESHOLD OR memory > MEMORY_THRESHOLD   →  return True

Default: return False
```

This layered approach minimises false positives for legitimate system processes while ensuring that processes executing from high-risk locations are always flagged.

### 3.2 Whitelist Cache

`whitelist.json` is loaded lazily and cached using the file's `mtime`. On each call to `load_whitelist()`, the engine compares the current mtime against the cached value. If the file has not changed, the in-memory set is returned immediately — avoiding redundant disk I/O during high-frequency monitoring.

---

## 4. Threat Scoring

### 4.1 `calculate_threat_score(process_info)`

The scoring function assigns additive penalty points and clamps the result to [0, 100]:

| Criterion | Points |
|---|---|
| Executable in suspicious directory (`/tmp/`, etc.) | +40 |
| Process name not in whitelist | +30 |
| No executable path available | +20 |
| CPU usage exceeds `CPU_THRESHOLD` | +30 |
| Memory usage exceeds `MEMORY_THRESHOLD` | +20 |

**Maximum possible score: 140 → clamped to 100.**

### 4.2 `get_threat_level(score)`

| Score Range | Level |
|---|---|
| ≥ 70 | `high` |
| 30 – 69 | `medium` |
| 0 – 29 | `low` |

Thresholds are configurable via `config.THREAT_HIGH_SCORE` and `config.THREAT_MEDIUM_SCORE`.

---

## 5. Prevention Module

### 5.1 Alert Persistence

`prevention.log_alert()` appends a JSON record to `logs/alerts.json`. Concurrent writes from multiple threads are serialised using `_ALERTS_LOCK`, a module-level `threading.Lock()`.

Each alert record contains:

```json
{
  "timestamp": "<ISO-8601 UTC>",
  "pid": 1234,
  "name": "process_name",
  "cpu": 95.3,
  "memory": 612.1,
  "path": "/tmp/evil",
  "threat_level": "high",
  "threat_score": 90
}
```

Corrupted `alerts.json` (e.g., power failure mid-write) is handled gracefully: the file is reset to a fresh array and the current alert is written as the first entry.

### 5.2 Process Termination

`prevention.kill_process(pid)` calls `psutil.Process.terminate()`, which sends `SIGTERM` on POSIX systems. All psutil exceptions (`NoSuchProcess`, `AccessDenied`, `ZombieProcess`) are caught and logged without raising.

### 5.3 CSV Export

`prevention.export_alerts_to_csv(output_path)` reads `alerts.json` under the alerts lock and writes a comma-separated file with columns:

```
timestamp, pid, name, cpu, memory, path, threat_level, threat_score
```

### 5.4 Email Alerts (SMTP)

`prevention.send_email_alert()` uses Python's `smtplib` (standard library) to send a plain-text notification over STARTTLS. It is gated by `config.EMAIL_ALERTS_ENABLED` and silently logs errors rather than crashing the monitor.

---

## 6. Auto-Prevention Mode

When `config.AUTO_PREVENTION_ENABLED = True` (or `--auto-prevent` CLI flag):

1. After logging an alert, the process monitor checks whether `threat_level == "high"`.
2. If so, `prevention.kill_process(pid)` is called immediately.
3. A `CRITICAL` log entry records the termination.

This mode is disabled by default to avoid accidental termination of legitimate processes in misconfigured environments.

---

## 7. Dashboard

### 7.1 Server (`dashboard/app.py`)

- `GET /` — serves `index.html`
- `GET /api/alerts` — reads `alerts.json`, back-fills `threat_score` / `threat_level` for older alerts that predate the scoring feature, returns JSON array
- `GET /api/stats` — returns `{total, high, medium, low, last_timestamp, auto_prevention}`

### 7.2 Front-End (`dashboard/static/script.js`)

- `fetchAlerts()` is called on page load and every `REFRESH_INTERVAL_MS` (5 s) via `setInterval`
- Alerts are sorted newest-first by default
- `getThreatLevel(alert)` derives the visual badge from `alert.threat_level` (set by server) or falls back to client-side heuristics for backward compatibility
- Search filtering iterates over `tr.dataset.search` (pre-built lowercase concat string) for O(n) matching

---

## 8. Configuration

All tuneable parameters are defined as typed module-level constants in `config.py`. Importing modules read from `config` once at module load time; runtime changes to `config.*` attributes (e.g., enabling auto-prevention via CLI flag) are reflected immediately since Python module attributes are mutable references.

---

## 9. Logging

The Python `logging` module is used throughout. Each module creates its own named logger:

```python
logger = logging.getLogger(__name__)
```

The root logger is configured in `main.py` (`logging.basicConfig`) and propagates to all child loggers. Log levels used:

| Level | Usage |
|---|---|
| `DEBUG` | Per-process scan details (disabled by default) |
| `INFO` | Thread startup, new connections, alert saves |
| `WARNING` | Whitelist load failures, suspicious activity detected |
| `ERROR` | Unexpected exceptions, SMTP failures |
| `CRITICAL` | Auto-prevention actions (process termination) |

---

## 10. Design Decisions

| Decision | Rationale |
|---|---|
| Daemon threads | A single `Ctrl+C` shuts down all monitors cleanly without explicit stop events |
| File-based alert storage | Simplicity and language-agnostic; JSON is directly consumed by the dashboard |
| `threading.Lock` for file writes | Same-process concurrency; cross-process safety is not required since a single `main.py` owns all writers |
| Whitelist mtime caching | Avoids redundant `open()` calls on every 2-second process scan cycle |
| Score capped at 100 | Provides a bounded, intuitive scale for analysts |
| False-positive guard for system paths | `/System/`, `/usr/`, etc. hard-coded as trusted to avoid flagging macOS/Linux system daemons |

---

## 11. Security Considerations

- **Privilege escalation**: The monitor runs as a regular user. An attacker with root access can terminate the monitor before it detects the threat. Kernel-level (eBPF) hooks would eliminate this gap.
- **TOCTOU on path checks**: A binary in `/tmp/` could be replaced between the path check and execution — acceptable risk at this monitoring level.
- **SMTP credentials**: `config.py` includes placeholder SMTP credentials. In production, use environment variables or a secrets manager (`os.environ.get("SMTP_PASSWORD")`).
- **alerts.json permissions**: The file is created with default umask permissions. Restrict to `600` in production to prevent unprivileged read access to alert data.

---

## 12. Test Coverage

39 pytest tests across three test files:

| File | Tests | Coverage |
|---|---|---|
| `tests/test_detection_engine.py` | 20 | `load_whitelist`, `is_process_suspicious`, `calculate_threat_score`, `get_threat_level` |
| `tests/test_prevention.py` | 9 | `log_alert`, `kill_process`, `export_alerts_to_csv` |
| `tests/test_dashboard.py` | 11 | `_load_alerts`, Flask routes, `/api/stats` |

Run with:

```bash
pytest tests/ -v
```
