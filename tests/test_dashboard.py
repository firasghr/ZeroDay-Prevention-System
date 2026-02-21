"""
Unit tests for dashboard/app.py
"""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from dashboard.app import app, _load_alerts


class TestLoadAlerts(unittest.TestCase):
    """Tests for the _load_alerts helper."""

    def test_returns_empty_list_when_file_missing(self):
        with patch("dashboard.app.ALERTS_FILE", "/nonexistent/alerts.json"):
            result = _load_alerts()
        self.assertEqual(result, [])

    def test_returns_alerts_from_file(self):
        data = [{"pid": 1, "name": "proc1"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            tmp_path = f.name
        try:
            with patch("dashboard.app.ALERTS_FILE", tmp_path):
                result = _load_alerts()
            self.assertEqual(result, data)
        finally:
            os.unlink(tmp_path)

    def test_returns_empty_list_on_malformed_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not json{{")
            tmp_path = f.name
        try:
            with patch("dashboard.app.ALERTS_FILE", tmp_path):
                result = _load_alerts()
            self.assertEqual(result, [])
        finally:
            os.unlink(tmp_path)


class TestDashboardRoutes(unittest.TestCase):
    """HTTP-level tests for the Flask dashboard."""

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_index_returns_200(self):
        with patch("dashboard.app.ALERTS_FILE", "/nonexistent/alerts.json"):
            resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)

    def test_index_shows_no_alerts_message(self):
        with patch("dashboard.app.ALERTS_FILE", "/nonexistent/alerts.json"):
            resp = self.client.get("/")
        self.assertIn(b"No alerts recorded yet", resp.data)

    def test_index_shows_alert_data(self):
        data = [{"pid": 42, "name": "evil_proc", "cpu": 99, "memory": 512, "path": "/tmp/evil",
                 "timestamp": "2024-01-01T00:00:00+00:00"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            tmp_path = f.name
        try:
            with patch("dashboard.app.ALERTS_FILE", tmp_path):
                resp = self.client.get("/")
            self.assertIn(b"evil_proc", resp.data)
        finally:
            os.unlink(tmp_path)

    def test_api_alerts_returns_json(self):
        data = [{"pid": 1, "name": "proc1"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            tmp_path = f.name
        try:
            with patch("dashboard.app.ALERTS_FILE", tmp_path):
                resp = self.client.get("/api/alerts")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.get_json(), data)
        finally:
            os.unlink(tmp_path)

    def test_api_alerts_empty_when_no_file(self):
        with patch("dashboard.app.ALERTS_FILE", "/nonexistent/alerts.json"):
            resp = self.client.get("/api/alerts")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), [])

    def test_index_includes_auto_refresh_meta_tag(self):
        with patch("dashboard.app.ALERTS_FILE", "/nonexistent/alerts.json"):
            resp = self.client.get("/")
        self.assertIn(b'http-equiv="refresh"', resp.data)


if __name__ == "__main__":
    unittest.main()
