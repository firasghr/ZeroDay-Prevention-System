"""
Flask Dashboard — Zero-Day Prevention System
Serves the EDR-style dashboard and exposes a /api/alerts JSON endpoint.
Also provides /api/stats for summary statistics used by the front-end.
"""

import json
import os

from flask import Flask, jsonify, render_template

import config
from engine import detection_engine

app = Flask(__name__, template_folder="templates", static_folder="static")

ALERTS_FILE: str = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "alerts.json"
)


def _load_alerts() -> list:
    """Read and return the alerts list from disk, or an empty list on error."""
    if os.path.isfile(ALERTS_FILE):
        try:
            with open(ALERTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return []


def _enrich_alert(alert: dict) -> dict:
    """
    Ensure every alert dict has threat_score and threat_level fields.

    Older alerts stored before the scoring feature was added will not have
    these fields.  This function back-fills them using the detection engine
    so the dashboard always displays consistent data.

    Args:
        alert: A raw alert dict loaded from alerts.json.

    Returns:
        The same dict with threat_score and threat_level guaranteed present.
    """
    if "threat_score" not in alert or "threat_level" not in alert:
        score = detection_engine.calculate_threat_score(alert)
        alert.setdefault("threat_score", score)
        alert.setdefault("threat_level", detection_engine.get_threat_level(score))
    return alert


@app.route("/")
def index():
    """Render the main dashboard page."""
    return render_template("index.html")


@app.route("/api/alerts")
def api_alerts():
    """Return all recorded alerts as a JSON array with threat scores enriched."""
    alerts = [_enrich_alert(a) for a in _load_alerts()]
    return jsonify(alerts)


@app.route("/api/stats")
def api_stats():
    """Return summary statistics for the dashboard header cards."""
    alerts = [_enrich_alert(a) for a in _load_alerts()]
    total = len(alerts)
    high = sum(1 for a in alerts if a.get("threat_level") == "high")
    medium = sum(1 for a in alerts if a.get("threat_level") == "medium")
    low = sum(1 for a in alerts if a.get("threat_level") == "low")
    last_ts = alerts[-1].get("timestamp") if alerts else None
    return jsonify(
        {
            "total": total,
            "high": high,
            "medium": medium,
            "low": low,
            "last_timestamp": last_ts,
            "auto_prevention": config.AUTO_PREVENTION_ENABLED,
        }
    )


if __name__ == "__main__":
    app.run(debug=False, host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT, use_reloader=False)
