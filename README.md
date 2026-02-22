# Zero-Day Prevention System

> A production-grade, behaviour-based threat detection and auto-prevention platform written in Python.

---

## Abstract

The **Zero-Day Prevention System** is a lightweight Endpoint Detection and Response (EDR) tool that monitors a Linux or macOS host in real-time.  
It inspects running processes, file-system activity, and outgoing network connections simultaneously, classifies suspicious activity using a configurable threat-scoring engine, and surfaces all findings through a browser-based security dashboard.

Because detection is based on **process behaviour** (execution path, resource usage, whitelist deviation) rather than signature matching, the system can catch previously unknown threats — including zero-day exploits — without requiring antivirus-style signature updates.

---

## Features

| Feature | Description |
|---|---|
| **Process Monitor** | Scans all new processes every 2 s and evaluates them against the detection engine |
| **File Monitor** | Watches the project directory tree for file creations, modifications, and deletions |
| **Network Monitor** | Tracks outgoing TCP/UDP connections every 5 s and reports new ones |
| **Detection Engine** | Whitelist + path + resource-threshold analysis (EDR-style multi-layered logic) |
| **Threat Scoring** | Assigns a numeric score (0–100) and a risk level (High / Medium / Low) to every alert |
| **Auto-Prevention** | Optionally auto-terminates HIGH-risk processes (`--auto-prevent` flag or `config.py`) |
| **Web Dashboard** | Flask EDR dashboard with live alerts table, threat badges, search, and sort |
| **Alert Persistence** | All alerts stored in `logs/alerts.json` with UTC timestamps |
| **CSV Export** | Export the full alert history to CSV with `--export-csv <path>` |
| **Email Alerts** | SMTP placeholder — configure credentials in `config.py` to enable |
| **Centralized Config** | All thresholds and toggles in a single `config.py` — no code changes needed |
| **Logging** | Structured logging (INFO / WARNING / ERROR / CRITICAL) via Python `logging` module |
| **Unit Tests** | 39 pytest tests covering detection, prevention, scoring, export, and dashboard |

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                          main.py                                │
│         (parses CLI args, configures logging, spawns threads)   │
└──────┬──────────┬────────────────┬──────────────────────────────┘
       │          │                │                    │
┌──────▼───┐ ┌───▼─────┐ ┌────────▼──────┐  ┌──────────▼──────────┐
│ Process  │ │  File   │ │   Network     │  │  Dashboard (Flask)  │
│ Monitor  │ │ Monitor │ │   Monitor     │  │  http://host:5001   │
│ (2 s)    │ │(watchdog│ │    (5 s)      │  │  /api/alerts        │
│          │ │ events) │ │               │  │  /api/stats         │
└──────┬───┘ └─────────┘ └───────────────┘  └─────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│                    Detection Engine                          │
│  1. Trusted-path fast-path  (/System/, /usr/, /opt/homebrew/)│
│  2. Browser/OS helper bypass (Renderer, GPU, WebKit, ...)    │
│  3. Suspicious-path check   (/tmp/, /var/tmp/, ~/Downloads/) │
│  4. Whitelist check         (whitelist.json)                 │
│  5. Resource thresholds     (CPU > 85%, RAM > 800 MB)        │
│  ─────────────────────────────────────────────────────────── │
│  calculate_threat_score()   → 0-100 numeric score            │
│  get_threat_level()         → high / medium / low            │
└──────────────────────────────┬───────────────────────────────┘
                               │  suspicious?
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                    Prevention Module                         │
│  log_alert()          → append to logs/alerts.json           │
│  kill_process()       → psutil.terminate() (if auto-prevent) │
│  export_alerts_to_csv()→ write CSV file                      │
│  send_email_alert()   → SMTP notification (optional)         │
└──────────────────────────────────────────────────────────────┘
```

All monitors run as **daemon threads** inside `main.py`.  A single `Ctrl+C` shuts everything down cleanly.

---

## Requirements

- Python 3.10+
- Linux / macOS  
  *(Windows: `psutil.net_connections` requires elevated privileges)*

Python dependencies (`requirements.txt`):

```
psutil>=5.9.0
watchdog>=3.0.0
flask>=3.0.0
pytest>=7.0.0
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

## Usage

### Run the full system

```bash
python main.py
```

### CLI Options

```
usage: main.py [-h] [--port PORT] [--log-level LEVEL] [--auto-prevent] [--export-csv PATH]

options:
  --port PORT           Dashboard port (default: 5001)
  --log-level LEVEL     DEBUG | INFO | WARNING | ERROR | CRITICAL (default: INFO)
  --auto-prevent        Automatically terminate HIGH-risk processes
  --export-csv PATH     Export current alerts to a CSV file and exit
```

### Examples

```bash
# Start with debug logging
python main.py --log-level DEBUG

# Enable auto-prevention mode
python main.py --auto-prevent

# Export alerts to CSV and exit
python main.py --export-csv /tmp/alerts_export.csv

# Run on a custom port
python main.py --port 8080
```

### Run individual modules

```bash
python agent/process_monitor.py
python file_monitor/file_monitor.py [path]
python network/network_monitor.py
python dashboard/app.py
```

---

## Dashboard

Open **http://localhost:5001** after starting the system.

The dashboard:
- Auto-refreshes every **5 seconds** via JavaScript `fetch`
- Shows all alerts in a sortable, searchable table
- Colour-codes rows by threat level (High / Medium / Low)
- Displays a numeric **Threat Score** (0–100) for each alert
- Exposes a REST API for programmatic access

### API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/alerts` | Full alert list as JSON array (with enriched threat scores) |
| `GET /api/stats` | Summary statistics: totals by level, last detection timestamp |

#### `/api/alerts` example response

```json
[
  {
    "timestamp": "2024-01-15T12:34:56.789012+00:00",
    "pid": 1234,
    "name": "evil_proc",
    "cpu": 95.3,
    "memory": 612.1,
    "path": "/tmp/evil_proc",
    "threat_level": "high",
    "threat_score": 90
  }
]
```

---

## Screenshots

*[Dashboard screenshot placeholder — run the system and capture the live dashboard]*

---

## Configuration

All parameters live in **`config.py`**:

| Parameter | Default | Description |
|---|---|---|
| `CPU_THRESHOLD` | `85.0` | Flag a process whose CPU exceeds this % |
| `MEMORY_THRESHOLD` | `800.0` | Flag a process whose RAM exceeds this MB |
| `THREAT_HIGH_SCORE` | `70` | Score ≥ this → HIGH risk |
| `THREAT_MEDIUM_SCORE` | `30` | Score ≥ this → MEDIUM risk |
| `AUTO_PREVENTION_ENABLED` | `False` | Auto-kill HIGH-risk processes |
| `DASHBOARD_PORT` | `5001` | Flask dashboard port |
| `PROCESS_MONITOR_INTERVAL` | `2` | Seconds between process scans |
| `NETWORK_MONITOR_INTERVAL` | `5` | Seconds between network scans |
| `EMAIL_ALERTS_ENABLED` | `False` | Send SMTP email on each alert |
| `LOG_LEVEL` | `"INFO"` | Logging verbosity |

### Whitelist — `whitelist.json`

```json
{
  "whitelist": ["bash", "python3", "nginx", "sshd"]
}
```

The whitelist is **hot-reloaded**: the engine checks the file's mtime on every evaluation, so you can edit it while the system is running.

---

## Project Structure

```
cyberproject/
├── main.py                    # Entry point — CLI args, logging, thread launcher
├── config.py                  # Centralized configuration
├── requirements.txt           # Python dependencies
├── whitelist.json             # Trusted process names
├── Dockerfile                 # Container image definition
├── README.md                  # This file
├── TECHNICAL_DOCUMENTATION.md # Architecture & design decisions
├── REPORT_SUMMARY.md          # Academic capstone summary
├── agent/
│   ├── __init__.py
│   ├── process_monitor.py     # New-process detection + auto-prevention
│   └── prevention.py          # Alert logging, kill, CSV export, email
├── engine/
│   ├── __init__.py
│   └── detection_engine.py    # Whitelist + threat scoring analysis
├── file_monitor/
│   ├── __init__.py
│   └── file_monitor.py        # Watchdog-based file-system watcher
├── network/
│   ├── __init__.py
│   └── network_monitor.py     # psutil-based outgoing connection tracker
├── dashboard/
│   ├── __init__.py
│   ├── app.py                 # Flask routes (/  /api/alerts  /api/stats)
│   ├── templates/
│   │   └── index.html         # EDR dashboard HTML
│   └── static/
│       ├── script.js          # Live-refresh fetch logic, threat scoring
│       └── style.css          # Dashboard CSS
├── logs/
│   └── alerts.json            # Persisted alert records (auto-created)
└── tests/
    ├── test_dashboard.py      # Flask route and helper tests
    ├── test_detection_engine.py  # Detection + scoring tests
    └── test_prevention.py     # Alert logging, kill, CSV export tests
```

---

## Technologies Used

| Technology | Purpose |
|---|---|
| Python 3.10+ | Core implementation language |
| psutil | Process inspection and network connection enumeration |
| watchdog | File-system event monitoring |
| Flask | Web dashboard and REST API |
| pytest | Unit test framework |
| Python `logging` | Structured application logging |
| Python `threading` | Concurrent monitor execution |
| Python `csv` / `json` | Alert persistence and export |
| Python `smtplib` | Email alert delivery (SMTP) |
| HTML / CSS / JavaScript | Dashboard front-end |

---

## Security Model

### Behaviour-Based Detection

Rather than maintaining a signature database, the system evaluates **process behaviour** at runtime:

1. **Execution path analysis** — processes spawned from `/tmp/`, `/var/tmp/`, or `~/Downloads` are always treated as high-risk, regardless of name.
2. **Whitelist deviation** — any process not listed in `whitelist.json` is flagged unless its executable lives in a trusted system directory.
3. **Resource abuse detection** — processes consuming abnormal CPU or memory trigger alerts even if they are otherwise whitelisted (cryptominer / code-injection scenario).
4. **Multi-layered scoring** — a numeric threat score aggregates all risk factors to prioritise analyst attention.

### Zero-Day Prevention Explanation

A zero-day exploit targets an unknown vulnerability for which no patch or signature exists.  
Traditional AV tools cannot detect it because there is no known signature to match.

This system detects zero-days by analysing **what a process does**, not what it is called:
- A malicious binary dropped in `/tmp/` by an exploit will be flagged the moment it executes.
- A compromised legitimate process that starts consuming excessive CPU (e.g., crypto-miner injected via memory corruption) will be flagged by the resource threshold.
- Auto-prevention can terminate the offending process before it causes damage.

---

## Limitations

- **Single host** — the system monitors only the host it runs on; it is not a network-wide SIEM.
- **No kernel-level hooks** — running as a user-space daemon means an adversary with root access can potentially bypass monitoring by terminating the process.
- **macOS network visibility** — `psutil.net_connections()` requires `sudo` on macOS; run with elevated privileges for full network monitoring.
- **File-system monitoring scope** — the file monitor watches the project directory by default; configure `MONITOR_PATH` in `main.py` to watch critical system directories.
- **Whitelist cold-start** — at first run, many legitimate processes are flagged until `whitelist.json` is tuned to the environment.

---

## Future Improvements

- Kernel-level hooks via eBPF for tamper-resistant monitoring
- SIEM integration (Splunk, Elastic) via structured JSON log forwarding
- Machine-learning anomaly detection as a secondary scoring layer
- Windows support with Win32 API / WMI event subscriptions
- Multi-host centralised alert collection
- Automated whitelist learning mode
- Dashboard authentication layer

---

## Running Tests

```bash
pytest tests/ -v
```

Expected: **39 tests passed**.

---

## Docker

```bash
docker build -t zero-day-prevention .
docker run -p 5001:5001 zero-day-prevention
```

---

## Author

**Firas Ghr**  
Cybersecurity Engineering Capstone Project  
Academic Year 2024–2025


---
