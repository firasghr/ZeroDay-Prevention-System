"""
Unit tests for agent/prevention.py
"""

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from agent import prevention


class TestLogAlert(unittest.TestCase):
    """Tests for prevention.log_alert."""

    def _make_info(self, pid=1234, name="test_proc", cpu=5.0, memory=50.0, path="/bin/test"):
        return {"pid": pid, "name": name, "cpu": cpu, "memory": memory, "path": path}

    def test_creates_alerts_file_and_appends_entry(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            alerts_path = os.path.join(tmp_dir, "alerts.json")
            with patch.object(prevention, "LOGS_DIR", tmp_dir), \
                 patch.object(prevention, "ALERTS_FILE", alerts_path):
                prevention.log_alert(self._make_info())

            with open(alerts_path, "r", encoding="utf-8") as f:
                data = json.load(f)

        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["name"], "test_proc")
        self.assertEqual(data[0]["pid"], 1234)
        self.assertIn("timestamp", data[0])

    def test_appends_to_existing_alerts(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            alerts_path = os.path.join(tmp_dir, "alerts.json")
            existing = [{"pid": 99, "name": "old_proc"}]
            with open(alerts_path, "w", encoding="utf-8") as f:
                json.dump(existing, f)

            with patch.object(prevention, "LOGS_DIR", tmp_dir), \
                 patch.object(prevention, "ALERTS_FILE", alerts_path):
                prevention.log_alert(self._make_info())

            with open(alerts_path, "r", encoding="utf-8") as f:
                data = json.load(f)

        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]["pid"], 99)
        self.assertEqual(data[1]["pid"], 1234)

    def test_recovers_from_corrupted_alerts_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            alerts_path = os.path.join(tmp_dir, "alerts.json")
            with open(alerts_path, "w", encoding="utf-8") as f:
                f.write("not json{{")

            with patch.object(prevention, "LOGS_DIR", tmp_dir), \
                 patch.object(prevention, "ALERTS_FILE", alerts_path):
                prevention.log_alert(self._make_info())

            with open(alerts_path, "r", encoding="utf-8") as f:
                data = json.load(f)

        self.assertEqual(len(data), 1)


class TestKillProcess(unittest.TestCase):
    """Tests for prevention.kill_process."""

    def test_calls_terminate_on_process(self):
        mock_proc = MagicMock()
        with patch("agent.prevention.psutil.Process", return_value=mock_proc):
            prevention.kill_process(1234)
        mock_proc.terminate.assert_called_once()

    def test_handles_no_such_process(self):
        import psutil
        with patch("agent.prevention.psutil.Process", side_effect=psutil.NoSuchProcess(1234)):
            # Should not raise
            prevention.kill_process(1234)

    def test_handles_access_denied(self):
        import psutil
        with patch("agent.prevention.psutil.Process", side_effect=psutil.AccessDenied(1234)):
            prevention.kill_process(1234)


if __name__ == "__main__":
    unittest.main()
