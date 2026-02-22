"""
Flask Dashboard — Zero-Day Prevention System
Serves the EDR-style dashboard and exposes a /api/alerts JSON endpoint.
"""

import json
import os

from flask import Flask, jsonify, render_template

app = Flask(__name__, template_folder="templates", static_folder="static")

ALERTS_FILE = os.path.join(
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


@app.route("/")
def index():
    """Render the main dashboard page."""
    return render_template("index.html")


@app.route("/api/alerts")
def api_alerts():
    """Return all recorded alerts as a JSON array."""
    return jsonify(_load_alerts())


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5001, use_reloader=False)
