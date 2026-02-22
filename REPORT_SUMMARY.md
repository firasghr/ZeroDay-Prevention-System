# Report Summary — Zero-Day Prevention System

**Capstone Project | Cybersecurity Engineering**  
**Academic Year 2024–2025**  
**Author: Firas Ghr**

---

## 1. Problem Statement

### 1.1 Context

Signature-based antivirus solutions protect against known threats by comparing file or behaviour fingerprints against a database of previously catalogued malware. They fail entirely against **zero-day exploits** — attacks that exploit vulnerabilities for which no patch or signature yet exists.

According to industry research (Ponemon Institute, 2023), zero-day attacks account for a disproportionate share of high-impact breaches, yet traditional endpoint protection tools provide no detection capability until a signature is released — often days or weeks after initial exploitation.

### 1.2 Challenge

Design and implement an endpoint security tool that can detect and optionally prevent malicious process activity **without relying on pre-existing signatures**, using only runtime behavioural indicators.

### 1.3 Research Questions

1. Can a lightweight, user-space daemon reliably distinguish malicious process behaviour from legitimate system activity on a modern Linux/macOS host?
2. What combination of heuristics (execution path, resource consumption, whitelist deviation) minimises false positives while maintaining high detection sensitivity?
3. Can a numeric threat-scoring model provide actionable prioritisation for security analysts?

---

## 2. Methodology

### 2.1 Threat Model

The system targets the following attack scenarios:

- **Dropped binary execution**: A compromised process writes a malicious binary to `/tmp/` and executes it.
- **Resource hijacking**: A legitimate process is compromised via memory corruption and begins consuming abnormal CPU (cryptominer, denial-of-service payload).
- **Unknown binary**: An attacker uploads and executes a binary with an unrecognised name that is not present on the system whitelist.
- **Downloads-folder social engineering**: A user is tricked into executing a malicious binary from `~/Downloads/`.

### 2.2 Detection Heuristics

The detection engine implements five ordered heuristics evaluated as a priority chain:

| Priority | Heuristic | Rationale |
|---|---|---|
| 1 | Trusted system path | Eliminates OS-level false positives |
| 2 | Browser / helper pattern | Eliminates high-volume browser subprocess noise |
| 3 | Accessible path + whitelist | Legitimate processes with known-good executables |
| 4 | Suspicious execution path | /tmp/ drops are high-confidence indicators |
| 5 | Whitelist + resource thresholds | Catch unknown binaries and compromised whitelisted processes |

### 2.3 Threat Scoring Model

A scoring model was designed to aggregate multiple risk factors into a single [0–100] integer:

```
score = 0
if suspicious_path:         score += 40   # highest weight: path-based anomaly
if name_not_in_whitelist:   score += 30   # second: identity anomaly
if no_executable_path:      score += 20   # third: evasion indicator
if cpu > threshold:         score += 30   # resource abuse
if memory > threshold:      score += 20   # resource abuse
score = min(score, 100)
```

Risk levels derived from score:
- **High**: ≥ 70  
- **Medium**: ≥ 30  
- **Low**: < 30

### 2.4 Implementation Platform

- **Language**: Python 3.10+
- **Process inspection**: `psutil` library
- **File monitoring**: `watchdog` library
- **Web dashboard**: Flask
- **Concurrency**: Python `threading` module
- **Testing**: `pytest`

---

## 3. Implementation

### 3.1 System Components

The final system consists of six primary modules coordinated by `main.py`:

| Module | Function |
|---|---|
| `agent/process_monitor.py` | Polls `psutil.process_iter()` every 2 s; evaluates new PIDs |
| `engine/detection_engine.py` | Multi-layered heuristic + threat scoring engine |
| `agent/prevention.py` | Alert persistence, process termination, CSV export, email |
| `file_monitor/file_monitor.py` | Watchdog-based FS event logging |
| `network/network_monitor.py` | Connection tracker using `psutil.net_connections()` |
| `dashboard/app.py` | Flask API and EDR dashboard UI |

### 3.2 Key Design Decisions

**Behaviour-only detection**: No signature database, no hash lookups, no network reputation checks. All decisions are made locally from runtime observable properties.

**Whitelist-based identity verification**: A configurable `whitelist.json` defines the set of trusted process names. The list is hot-reloaded on change via mtime caching.

**Additive threat scoring**: Multiple low-confidence signals are combined into a single score rather than any single indicator triggering an alert. This approach reduces both false positives and false negatives.

**Auto-prevention with safeguard**: The auto-termination feature is disabled by default (`AUTO_PREVENTION_ENABLED = False`) and requires explicit opt-in via CLI or config to prevent accidental disruption of legitimate processes.

**Thread isolation with shared file state**: Each monitor runs in its own daemon thread. The only shared mutable state is `logs/alerts.json`, protected by a `threading.Lock()`.

### 3.3 Dashboard

The web dashboard is a single-page application served by Flask. It polls `/api/alerts` every 5 seconds via JavaScript `fetch`, renders a colour-coded threat table with search and sort capabilities, and displays summary statistics (total alerts, high/medium/low counts, last detection timestamp).

---

## 4. Results

### 4.1 Detection Capability

| Scenario | Detected? | Threat Level |
|---|---|---|
| Execution from `/tmp/` | ✅ Yes | High (score ≥ 70) |
| Unknown binary outside trusted dirs | ✅ Yes | Medium–High |
| CPU spike on whitelisted process | ✅ Yes | High (CPU > 85%) |
| System daemon (`/usr/sbin/...`) | ✅ Not flagged | — (fast-path bypass) |
| Browser helper (GPU / Renderer) | ✅ Not flagged | — (pattern bypass) |
| Known-good process in normal operation | ✅ Not flagged | — |

### 4.2 Test Coverage

39 automated unit tests validate the detection engine, prevention module, and dashboard routes. All tests pass on the target platform (Python 3.12 on Linux).

### 4.3 Performance

- Process monitor loop overhead: < 50 ms per 2-second cycle on a standard workstation
- Memory footprint: ~30 MB RSS (Python interpreter + psutil + Flask)
- Dashboard latency: < 5 ms for `/api/alerts` with typical alert volumes (< 10 000 records)

---

## 5. Conclusion

### 5.1 Summary

The Zero-Day Prevention System demonstrates that effective endpoint threat detection can be implemented without signature databases or machine-learning models. By combining whitelist deviation analysis, execution-path heuristics, and resource-threshold monitoring into a multi-layered scoring engine, the system achieves high detection rates against the targeted attack scenarios with a low false-positive rate for standard system processes.

### 5.2 Contributions

- A lightweight, fully open-source EDR prototype suitable for academic study and homelab deployment
- A documented, configurable threat-scoring model that serves as a baseline for future ML-augmented approaches
- A complete project template (monitoring agent → detection engine → prevention → dashboard) that can be extended with additional monitor types

### 5.3 Limitations

- User-space monitoring is inherently bypassable by root-level adversaries
- The whitelist requires initial tuning for each deployment environment
- macOS network monitoring requires elevated privileges

### 5.4 Future Work

- eBPF-based kernel hooks for tamper-resistant monitoring
- Anomaly detection with an unsupervised ML model trained on baseline behaviour
- SIEM integration (Elastic SIEM, Splunk) via structured JSON log forwarding
- Multi-host deployment with a centralised alert aggregator

---

## References

1. Pontemon Institute. (2023). *The Cost of a Data Breach Report*. IBM Security.  
2. Symantec. (2022). *Internet Security Threat Report*. Broadcom.  
3. MITRE ATT&CK Framework — https://attack.mitre.org  
4. psutil documentation — https://psutil.readthedocs.io  
5. watchdog documentation — https://python-watchdog.readthedocs.io  
6. Flask documentation — https://flask.palletsprojects.com  
