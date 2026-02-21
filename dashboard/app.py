"""
Flask Dashboard
Displays alerts from logs/alerts.json in a web page table.
"""

import json
import os

from flask import Flask, render_template_string

app = Flask(__name__)

ALERTS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "alerts.json"
)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zero-Day Prevention — Alerts Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; background: #1a1a2e; color: #eee; margin: 0; padding: 20px; }
        h1 { color: #e94560; text-align: center; margin-bottom: 30px; }
        table { width: 100%; border-collapse: collapse; background: #16213e; }
        th { background: #0f3460; color: #e94560; padding: 12px 15px; text-align: left; }
        td { padding: 10px 15px; border-bottom: 1px solid #0f3460; word-break: break-all; }
        tr:hover { background: #0f3460; }
        .no-alerts { text-align: center; padding: 40px; color: #aaa; }
        .badge { display: inline-block; background: #e94560; color: #fff;
                 border-radius: 12px; padding: 2px 10px; font-size: 0.8em; }
    </style>
</head>
<body>
    <h1>&#9888; Zero-Day Prevention — Alerts Dashboard</h1>
    {% if alerts %}
    <p style="text-align:center;">
        Total alerts: <span class="badge">{{ alerts|length }}</span>
    </p>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Process Name</th>
                <th>PID</th>
                <th>CPU (%)</th>
                <th>Memory (MB)</th>
                <th>Path</th>
            </tr>
        </thead>
        <tbody>
            {% for alert in alerts %}
            <tr>
                <td>{{ alert.get('timestamp', 'N/A') }}</td>
                <td>{{ alert.get('name', 'N/A') }}</td>
                <td>{{ alert.get('pid', 'N/A') }}</td>
                <td>{{ alert.get('cpu', 'N/A') }}</td>
                <td>{{ alert.get('memory', 'N/A') }}</td>
                <td>{{ alert.get('path', 'N/A') }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% else %}
    <div class="no-alerts">No alerts recorded yet.</div>
    {% endif %}
</body>
</html>
"""


@app.route("/")
def index():
    """Display all recorded alerts from logs/alerts.json."""
    alerts = []
    if os.path.isfile(ALERTS_FILE):
        try:
            with open(ALERTS_FILE, "r", encoding="utf-8") as f:
                alerts = json.load(f)
        except (json.JSONDecodeError, IOError):
            alerts = []
    return render_template_string(HTML_TEMPLATE, alerts=alerts)


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
