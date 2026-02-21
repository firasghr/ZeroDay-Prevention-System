# Zero-Day Prevention System

A lightweight, real-time threat-detection and prevention system written in Python. It monitors running processes, file system activity, and outgoing network connections, flags suspicious behaviour, and exposes a web dashboard for reviewing alerts.

---

## Table of Contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Usage](#usage)
7. [Dashboard](#dashboard)
8. [Project Structure](#project-structure)
9. [How Detection Works](#how-detection-works)
10. [Extending the System](#extending-the-system)

---

## Features

| Feature | Description |
|---|---|
| **Process Monitor** | Detects newly spawned processes every 2 s and evaluates them for suspicious activity |
| **File Monitor** | Watches the project directory tree for file creations, modifications and deletions |
| **Network Monitor** | Tracks outgoing TCP/UDP connections every 5 s and reports new ones |
| **Detection Engine** | Whitelist-based + threshold-based analysis (CPU %, RAM MB) |
| **Prevention Module** | Persists alerts to `logs/alerts.json`; can forcibly terminate a process |
| **Web Dashboard** | Flask app showing all alerts in a table with auto-refresh every 10 s |

---

## Architecture

```
┌──────────────────────────────────────────────┐
│                  main.py                     │
│  (launches all monitors + dashboard thread)  │
└─────────┬──────────┬──────────┬──────────────┘
          │          │          │
  ┌───────▼──┐ ┌─────▼────┐ ┌──▼──────────┐  ┌──────────────┐
  │ Process  │ │  File    │ │  Network    │  │  Dashboard   │
  │ Monitor  │ │ Monitor  │ │  Monitor   │  │  (Flask :5000│
  └───────┬──┘ └──────────┘ └─────┬───────┘  └──────────────┘
          │                       │
          ▼                       ▼
   ┌─────────────┐         logs alerts (future)
   │  Detection  │
   │   Engine    │
   └──────┬──────┘
          │ suspicious?
          ▼
   ┌─────────────┐
   │  Prevention │──► logs/alerts.json
   │   Module    │
   └─────────────┘
```

All monitors run as daemon threads inside `main.py` so a single `Ctrl+C` shuts everything down cleanly.

---

## Requirements

- Python 3.9+
- Linux / macOS (Windows support is limited — `psutil.net_connections` requires elevated privileges on Windows)

Python dependencies (see `requirements.txt`):

```
psutil>=5.9.0
watchdog>=3.0.0
flask>=3.0.0
```

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/firasghr/cyberproject.git
cd cyberproject

# 2. Create and activate a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Configuration

### Whitelist — `whitelist.json`

The detection engine loads a list of trusted process names from `whitelist.json` at the project root. Any new process whose name is **not** in this list is immediately flagged as suspicious.

```json
{
  "whitelist": [
    "bash",
    "python3",
    "nginx",
    "sshd"
  ]
}
```

The whitelist is **hot-reloaded**: the engine checks the file's modification time on every evaluation, so you can edit `whitelist.json` while the system is running without restarting it.

### Detection Thresholds — `engine/detection_engine.py`

Two numeric thresholds can be adjusted at the top of the file:

| Constant | Default | Meaning |
|---|---|---|
| `CPU_THRESHOLD` | `80` | Flag a process if its CPU usage exceeds this percentage |
| `MEMORY_THRESHOLD` | `500` | Flag a process if its RSS memory exceeds this value in MB |

---

## Usage

### Run the full system (monitors + dashboard)

```bash
python main.py
```

The system starts four daemon threads:

| Thread | Purpose |
|---|---|
| `ProcessMonitor` | New-process detection |
| `FileMonitor` | File system watcher |
| `NetworkMonitor` | Outgoing connection tracker |
| `Dashboard` | Flask web UI on port 5000 |

Press **Ctrl+C** to shut everything down.

### Run only the dashboard

```bash
python dashboard/app.py
```

Then open <http://localhost:5000> in a browser.

### Run individual monitors

```bash
python agent/process_monitor.py
python file_monitor/file_monitor.py [path]   # defaults to current directory
python network/network_monitor.py
```

---

## Dashboard

The web dashboard auto-refreshes every **10 seconds** and displays all recorded alerts.

![dashboard screenshot placeholder](https://via.placeholder.com/800x300?text=Zero-Day+Dashboard)

It also exposes a REST endpoint for programmatic access:

```
GET /api/alerts          → JSON array of all alert objects
```

Example response:

```json
[
  {
    "timestamp": "2024-01-15T12:34:56.789012+00:00",
    "pid": 1234,
    "name": "suspicious_proc",
    "cpu": 95.3,
    "memory": 612.1,
    "path": "/tmp/suspicious_proc"
  }
]
```

---

## Project Structure

```
cyberproject/
├── main.py                   # Entry point — starts all threads
├── requirements.txt          # Python dependencies
├── whitelist.json            # Trusted process names
├── agent/
│   ├── __init__.py
│   ├── process_monitor.py    # Detects new processes
│   └── prevention.py         # Logs alerts, can terminate processes
├── engine/
│   ├── __init__.py
│   └── detection_engine.py   # Whitelist + threshold analysis
├── file_monitor/
│   ├── __init__.py
│   └── file_monitor.py       # Watchdog-based FS watcher
├── network/
│   ├── __init__.py
│   └── network_monitor.py    # psutil-based connection tracker
├── dashboard/
│   ├── __init__.py
│   └── app.py                # Flask web dashboard
└── logs/
    └── alerts.json           # Persisted alert records (auto-created)
```

---

## How Detection Works

### Process Detection (`engine/detection_engine.py`)

`is_process_suspicious(process_info)` returns `True` if **any** of the following conditions hold:

1. The process **name is not in the whitelist**
2. CPU usage > `CPU_THRESHOLD` (default 80 %)
3. Memory usage > `MEMORY_THRESHOLD` (default 500 MB)
4. Executable **path is missing** (e.g. the binary was deleted after launch)

### Alert Lifecycle

1. `process_monitor.monitor_processes()` spots a new PID.
2. It calls `detection_engine.is_process_suspicious()`.
3. If suspicious → `prevention.log_alert()` appends a JSON record to `logs/alerts.json`.
4. The Flask dashboard reads `logs/alerts.json` on each page load.

### Terminating a Process

The `prevention.kill_process(pid)` helper is available for automated response:

```python
from agent.prevention import kill_process
kill_process(1234)
```

It uses `psutil.Process.terminate()` and handles `NoSuchProcess`, `AccessDenied`, and `ZombieProcess` gracefully.

---

## Extending the System

### Add a new monitor

1. Create a new module (e.g. `usb_monitor/usb_monitor.py`) with a blocking `monitor_*()` function.
2. Import and add a `threading.Thread` for it in `main.py`.

### Persist network / file alerts

The network and file monitors currently print events to stdout only. To persist them, import `prevention.log_alert` and call it with a dict containing at least `name`, `pid`, `cpu`, `memory`, and `path`.

### Change alert storage

`prevention.py` writes to `logs/alerts.json`. Replace the read/write logic there to send alerts to a database, syslog, or SIEM of your choice.
