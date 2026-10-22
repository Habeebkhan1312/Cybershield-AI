"""
CyberShield AI — Detection Rules Tests
"""

import pytest
import pandas as pd
from datetime import datetime, timezone

from analyzers.log_parser import LogParser
from analyzers.detection_rules import DetectionEngine


def _make_events(records: list[dict]) -> pd.DataFrame:
    """Create a normalised DataFrame from a list of event dicts."""
    df = pd.DataFrame(records)
    return LogParser.normalize_events(df)


class TestBruteForce:
    def test_detects_brute_force(self):
        """6 failures from same IP within 5 minutes → alert."""
        events = [
            {"timestamp": f"2024-03-15T08:30:{10+i:02d}Z",
             "event_id": 4625, "username": "jsmith",
             "source_ip": "192.168.50.99", "action": "logon", "status": "failure"}
            for i in range(6)
        ]
        df = _make_events(events)
        alerts = DetectionEngine.detect_brute_force(df)
        assert len(alerts) >= 1
        assert alerts[0]["severity"] == "HIGH"
        assert "Brute Force" in alerts[0]["rule_name"]

    def test_no_alert_for_spread_out_failures(self):
        """5 failures spread over 30 minutes → no alert."""
        events = [
            {"timestamp": f"2024-03-15T08:{10+i*6:02d}:00Z",
             "event_id": 4625, "username": "jsmith",
             "source_ip": "192.168.50.99", "action": "logon", "status": "failure"}
            for i in range(5)
        ]
        df = _make_events(events)
        alerts = DetectionEngine.detect_brute_force(df, threshold=5, window_minutes=5)
        assert len(alerts) == 0

    def test_no_alert_below_threshold(self):
        """3 failures (below threshold of 5) → no alert."""
        events = [
            {"timestamp": f"2024-03-15T08:30:{10+i:02d}Z",
             "event_id": 4625, "username": "jsmith",
             "source_ip": "192.168.50.99", "action": "logon", "status": "failure"}
            for i in range(3)
        ]
        df = _make_events(events)
        alerts = DetectionEngine.detect_brute_force(df, threshold=5)
        assert len(alerts) == 0


class TestLoginAfterFailure:
    def test_detects_success_after_failures(self):
        events = [
            {"timestamp": "2024-03-15T08:30:10Z", "event_id": 4625,
             "username": "jsmith", "source_ip": "10.0.1.1",
             "action": "logon", "status": "failure"},
            {"timestamp": "2024-03-15T08:30:20Z", "event_id": 4625,
             "username": "jsmith", "source_ip": "10.0.1.1",
             "action": "logon", "status": "failure"},
            {"timestamp": "2024-03-15T08:30:30Z", "event_id": 4625,
             "username": "jsmith", "source_ip": "10.0.1.1",
             "action": "logon", "status": "failure"},
            {"timestamp": "2024-03-15T08:31:00Z", "event_id": 4624,
             "username": "jsmith", "source_ip": "10.0.1.1",
             "action": "logon", "status": "success"},
        ]
        df = _make_events(events)
        alerts = DetectionEngine.detect_login_after_failure(df)
        assert len(alerts) >= 1
        assert "Login After" in alerts[0]["rule_name"]

    def test_no_alert_without_success(self):
        events = [
            {"timestamp": "2024-03-15T08:30:10Z", "event_id": 4625,
             "username": "jsmith", "source_ip": "10.0.1.1",
             "action": "logon", "status": "failure"},
            {"timestamp": "2024-03-15T08:30:20Z", "event_id": 4625,
             "username": "jsmith", "source_ip": "10.0.1.1",
             "action": "logon", "status": "failure"},
            {"timestamp": "2024-03-15T08:30:30Z", "event_id": 4625,
             "username": "jsmith", "source_ip": "10.0.1.1",
             "action": "logon", "status": "failure"},
        ]
        df = _make_events(events)
        alerts = DetectionEngine.detect_login_after_failure(df)
        assert len(alerts) == 0


class TestUnusualHours:
    def test_detects_3am_login(self):
        events = [
            {"timestamp": "2024-03-16T03:00:00Z", "event_id": 4624,
             "username": "nightowl", "source_ip": "10.0.1.1",
             "action": "logon", "status": "success"},
        ]
        df = _make_events(events)
        alerts = DetectionEngine.detect_unusual_hours(df)
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "LOW"

    def test_no_alert_during_business_hours(self):
        events = [
            {"timestamp": "2024-03-15T10:00:00Z", "event_id": 4624,
             "username": "dayjob", "source_ip": "10.0.1.1",
             "action": "logon", "status": "success"},
        ]
        df = _make_events(events)
        alerts = DetectionEngine.detect_unusual_hours(df)
        assert len(alerts) == 0


class TestRunAllRules:
    def test_sorted_by_severity(self):
        """Alerts should be sorted HIGH → MEDIUM → LOW."""
        from pathlib import Path
        sample_csv = (
            Path(__file__).resolve().parent.parent
            / "sample_data" / "auth_logs.csv"
        )
        df = LogParser.parse_csv(sample_csv)
        df = LogParser.normalize_events(df)
        engine = DetectionEngine()
        alerts = engine.run_all_rules(df)

        if len(alerts) >= 2:
            severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
            severities = [severity_order.get(a["severity"], 99) for a in alerts]
            assert severities == sorted(severities)

    def test_returns_list(self):
        df = _make_events([
            {"timestamp": "2024-03-15T10:00:00Z", "event_id": 4624,
             "username": "normal", "source_ip": "10.0.1.1",
             "action": "logon", "status": "success"},
        ])
        engine = DetectionEngine()
        result = engine.run_all_rules(df)
        assert isinstance(result, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
