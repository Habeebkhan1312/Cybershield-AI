"""
CyberShield AI — Incident Analyzer Tests
"""

import pytest
import pandas as pd

from analyzers.log_parser import LogParser
from analyzers.incident_analyzer import IncidentAnalyzer


def _sample_events() -> pd.DataFrame:
    """A small DataFrame with one brute-force scenario."""
    events = [
        {"timestamp": f"2024-03-15T08:30:{10+i:02d}Z",
         "event_id": 4625, "username": "jsmith",
         "source_ip": "192.168.50.99", "action": "logon",
         "status": "failure"}
        for i in range(6)
    ]
    events.append(
        {"timestamp": "2024-03-15T08:31:00Z",
         "event_id": 4624, "username": "jsmith",
         "source_ip": "192.168.50.99", "action": "logon",
         "status": "success"}
    )
    return pd.DataFrame(events)


class TestIncidentAnalyzer:
    def test_analyze_without_rag(self):
        """Analyzer should work without a RAG engine."""
        analyzer = IncidentAnalyzer(rag_engine=None)
        df = _sample_events()
        report = analyzer.analyze(df, enrich_with_rag=False)

        assert "total_events" in report
        assert "alerts" in report
        assert "summary" in report
        assert report["total_events"] == 7
        assert len(report["alerts"]) >= 1

    def test_report_has_summary_counts(self):
        analyzer = IncidentAnalyzer(rag_engine=None)
        df = _sample_events()
        report = analyzer.analyze(df, enrich_with_rag=False)
        summary = report["summary"]

        assert "HIGH" in summary
        assert "MEDIUM" in summary
        assert "LOW" in summary
        assert summary["HIGH"] >= 1

    def test_alerts_have_required_fields(self):
        analyzer = IncidentAnalyzer(rag_engine=None)
        df = _sample_events()
        report = analyzer.analyze(df, enrich_with_rag=False)

        for alert in report["alerts"]:
            assert "alert_id" in alert
            assert "rule_name" in alert
            assert "severity" in alert
            assert "description" in alert
            assert "evidence_events" in alert

    def test_explain_without_rag(self):
        """explain_alert should return a warning when RAG is absent."""
        analyzer = IncidentAnalyzer(rag_engine=None)
        alert = {
            "rule_name": "Test Rule",
            "severity": "HIGH",
            "description": "Test alert",
            "mitre_technique_hint": "T1110",
            "evidence_events": [],
        }
        result = analyzer.explain_alert(alert)
        assert "⚠️" in result["answer"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
