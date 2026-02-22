"""
Unit tests for engine/detection_engine.py
"""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from engine import detection_engine


class TestLoadWhitelist(unittest.TestCase):
    """Tests for detection_engine.load_whitelist."""

    def setUp(self):
        # Reset module-level cache before each test
        detection_engine._whitelist_cache = set()
        detection_engine._whitelist_mtime = 0.0

    def test_returns_whitelist_names(self):
        data = {"whitelist": ["bash", "python3"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            tmp_path = f.name
        try:
            with patch.object(detection_engine, "WHITELIST_PATH", tmp_path):
                result = detection_engine.load_whitelist()
            self.assertEqual(result, {"bash", "python3"})
        finally:
            os.unlink(tmp_path)

    def test_missing_file_returns_empty_set(self):
        with patch.object(detection_engine, "WHITELIST_PATH", "/nonexistent/path/whitelist.json"):
            result = detection_engine.load_whitelist()
        self.assertEqual(result, set())

    def test_malformed_json_returns_empty_set(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json{{")
            tmp_path = f.name
        try:
            with patch.object(detection_engine, "WHITELIST_PATH", tmp_path):
                result = detection_engine.load_whitelist()
            self.assertEqual(result, set())
        finally:
            os.unlink(tmp_path)

    def test_cache_is_used_when_mtime_unchanged(self):
        data = {"whitelist": ["bash"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            tmp_path = f.name
        try:
            with patch.object(detection_engine, "WHITELIST_PATH", tmp_path):
                first = detection_engine.load_whitelist()
                # Overwrite file without changing mtime in cache; cache should still be used
                cached_mtime = detection_engine._whitelist_mtime
                detection_engine._whitelist_cache = {"cached_value"}
                detection_engine._whitelist_mtime = cached_mtime  # keep same mtime
                second = detection_engine.load_whitelist()
            self.assertIn("cached_value", second)
        finally:
            os.unlink(tmp_path)


class TestIsProcessSuspicious(unittest.TestCase):
    """Tests for detection_engine.is_process_suspicious."""

    def _make_info(self, name="bash", cpu=10, memory=100, path="/bin/bash"):
        return {"name": name, "cpu": cpu, "memory": memory, "path": path}

    def test_whitelisted_safe_process_is_not_suspicious(self):
        with patch.object(detection_engine, "load_whitelist", return_value={"bash"}):
            result = detection_engine.is_process_suspicious(self._make_info())
        self.assertFalse(result)

    def test_not_in_whitelist_is_suspicious(self):
        with patch.object(detection_engine, "load_whitelist", return_value={"bash"}):
            result = detection_engine.is_process_suspicious(self._make_info(name="unknown_proc"))
        self.assertTrue(result)

    def test_high_cpu_is_suspicious(self):
        with patch.object(detection_engine, "load_whitelist", return_value={"bash"}):
            result = detection_engine.is_process_suspicious(
                self._make_info(cpu=detection_engine.CPU_THRESHOLD + 1)
            )
        self.assertTrue(result)

    def test_high_memory_is_suspicious(self):
        with patch.object(detection_engine, "load_whitelist", return_value={"bash"}):
            result = detection_engine.is_process_suspicious(
                self._make_info(memory=detection_engine.MEMORY_THRESHOLD + 1)
            )
        self.assertTrue(result)

    def test_missing_path_is_suspicious(self):
        with patch.object(detection_engine, "load_whitelist", return_value={"bash"}):
            result = detection_engine.is_process_suspicious(self._make_info(path=None))
        self.assertTrue(result)

    def test_empty_path_is_suspicious(self):
        with patch.object(detection_engine, "load_whitelist", return_value={"bash"}):
            result = detection_engine.is_process_suspicious(self._make_info(path=""))
        self.assertTrue(result)

    def test_cpu_at_threshold_is_not_suspicious(self):
        with patch.object(detection_engine, "load_whitelist", return_value={"bash"}):
            result = detection_engine.is_process_suspicious(
                self._make_info(cpu=detection_engine.CPU_THRESHOLD)
            )
        self.assertFalse(result)

    def test_memory_at_threshold_is_not_suspicious(self):
        with patch.object(detection_engine, "load_whitelist", return_value={"bash"}):
            result = detection_engine.is_process_suspicious(
                self._make_info(memory=detection_engine.MEMORY_THRESHOLD)
            )
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()


class TestCalculateThreatScore(unittest.TestCase):
    """Tests for detection_engine.calculate_threat_score."""

    def _make_info(self, name="bash", cpu=10, memory=100, path="/bin/bash"):
        return {"name": name, "cpu": cpu, "memory": memory, "path": path}

    def test_suspicious_path_raises_score(self):
        with patch.object(detection_engine, "load_whitelist", return_value={"bash"}):
            score = detection_engine.calculate_threat_score(
                self._make_info(path="/tmp/evil")
            )
        self.assertGreater(score, 0)

    def test_missing_path_raises_score(self):
        with patch.object(detection_engine, "load_whitelist", return_value={"bash"}):
            score_none = detection_engine.calculate_threat_score(self._make_info(path=None))
            score_empty = detection_engine.calculate_threat_score(self._make_info(path=""))
        self.assertGreater(score_none, 0)
        self.assertGreater(score_empty, 0)

    def test_high_cpu_raises_score(self):
        with patch.object(detection_engine, "load_whitelist", return_value={"bash"}):
            score = detection_engine.calculate_threat_score(
                self._make_info(cpu=detection_engine.CPU_THRESHOLD + 1)
            )
        self.assertGreater(score, 0)

    def test_score_capped_at_100(self):
        with patch.object(detection_engine, "load_whitelist", return_value=set()):
            score = detection_engine.calculate_threat_score(
                self._make_info(
                    name="evil",
                    cpu=detection_engine.CPU_THRESHOLD + 10,
                    memory=detection_engine.MEMORY_THRESHOLD + 100,
                    path="/tmp/evil",
                )
            )
        self.assertLessEqual(score, 100)

    def test_safe_process_scores_low(self):
        with patch.object(detection_engine, "load_whitelist", return_value={"bash"}):
            score = detection_engine.calculate_threat_score(self._make_info())
        self.assertLess(score, detection_engine.config.THREAT_HIGH_SCORE)


class TestGetThreatLevel(unittest.TestCase):
    """Tests for detection_engine.get_threat_level."""

    def test_high_score_returns_high(self):
        self.assertEqual(
            detection_engine.get_threat_level(detection_engine.config.THREAT_HIGH_SCORE),
            "high",
        )

    def test_medium_score_returns_medium(self):
        self.assertEqual(
            detection_engine.get_threat_level(detection_engine.config.THREAT_MEDIUM_SCORE),
            "medium",
        )

    def test_low_score_returns_low(self):
        self.assertEqual(detection_engine.get_threat_level(0), "low")
        self.assertEqual(
            detection_engine.get_threat_level(detection_engine.config.THREAT_MEDIUM_SCORE - 1),
            "low",
        )
