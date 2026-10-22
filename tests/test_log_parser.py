"""
CyberShield AI — Log Parser Tests
"""

import pytest
import pandas as pd
from pathlib import Path

from analyzers.log_parser import LogParser


SAMPLE_CSV = Path(__file__).resolve().parent.parent / "sample_data" / "auth_logs.csv"
SAMPLE_JSON = Path(__file__).resolve().parent.parent / "sample_data" / "siem_alerts.json"


class TestCSVParsing:
    def test_parse_csv_row_count(self):
        df = LogParser.parse_csv(SAMPLE_CSV)
        assert len(df) >= 40, f"Expected ≥40 rows, got {len(df)}"

    def test_parse_csv_columns(self):
        df = LogParser.parse_csv(SAMPLE_CSV)
        for col in ["timestamp", "event_id", "username", "source_ip", "action", "status"]:
            assert col in df.columns, f"Missing column: {col}"

    def test_validate_schema_ok(self):
        df = LogParser.parse_csv(SAMPLE_CSV)
        ok, issues = LogParser.validate_schema(df, "auth_log")
        assert ok is True
        assert issues == []

    def test_validate_schema_missing_columns(self):
        df = pd.DataFrame({"timestamp": ["2024-01-01"], "foo": ["bar"]})
        ok, issues = LogParser.validate_schema(df, "auth_log")
        assert ok is False
        assert any("Missing" in i for i in issues)

    def test_validate_empty_df(self):
        df = pd.DataFrame()
        ok, issues = LogParser.validate_schema(df, "auth_log")
        assert ok is False
        assert any("no data" in i.lower() for i in issues)


class TestJSONParsing:
    def test_parse_json_row_count(self):
        df = LogParser.parse_json(SAMPLE_JSON)
        assert len(df) >= 10

    def test_parse_json_columns(self):
        df = LogParser.parse_json(SAMPLE_JSON)
        for col in ["timestamp", "alert_name", "severity", "username"]:
            assert col in df.columns

    def test_validate_siem_schema(self):
        df = LogParser.parse_json(SAMPLE_JSON)
        ok, _ = LogParser.validate_schema(df, "siem_alert")
        assert ok is True


class TestNormalization:
    def test_timestamps_parsed(self):
        df = LogParser.parse_csv(SAMPLE_CSV)
        df = LogParser.normalize_events(df)
        assert pd.api.types.is_datetime64_any_dtype(df["timestamp"])

    def test_sorted_chronologically(self):
        df = LogParser.parse_csv(SAMPLE_CSV)
        df = LogParser.normalize_events(df)
        timestamps = df["timestamp"].tolist()
        assert timestamps == sorted(timestamps)

    def test_username_lowercase(self):
        df = LogParser.parse_csv(SAMPLE_CSV)
        df = LogParser.normalize_events(df)
        for u in df["username"]:
            assert u == u.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
