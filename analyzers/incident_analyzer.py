"""
CyberShield AI — Incident Analyzer

Orchestrates detection rules and RAG retrieval to produce enriched
incident reports.  Deterministic detection identifies patterns;
RAG supplies relevant security knowledge; the LLM explains the evidence.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from analyzers.log_parser import LogParser
from analyzers.detection_rules import DetectionEngine


class IncidentAnalyzer:
    """Combine log parsing, detection, and RAG into one workflow."""

    def __init__(self, rag_engine: Any | None = None):
        """*rag_engine* is an optional ``CyberShieldRAG`` instance."""
        self.parser = LogParser()
        self.detector = DetectionEngine()
        self.rag = rag_engine

    # ── Full analysis ─────────────────────────────────────────────

    def analyze(
        self,
        df: pd.DataFrame,
        enrich_with_rag: bool = True,
    ) -> dict[str, Any]:
        """Run detection rules and optionally enrich with RAG context.

        Returns::

            {
                "total_events": int,
                "alerts": [...],
                "summary": {
                    "HIGH": int,
                    "MEDIUM": int,
                    "LOW": int,
                },
            }
        """
        # Normalize
        df = self.parser.normalize_events(df)

        # Detect
        alerts = self.detector.run_all_rules(df)

        # Enrich each alert with RAG context
        if enrich_with_rag and self.rag is not None:
            for alert in alerts:
                alert["rag_context"] = self._retrieve_context(alert)

        # Summary counts
        summary: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for alert in alerts:
            sev = alert.get("severity", "LOW")
            if sev in summary:
                summary[sev] += 1

        return {
            "total_events": len(df),
            "alerts": alerts,
            "summary": summary,
        }

    # ── RAG enrichment ────────────────────────────────────────────

    def _retrieve_context(self, alert: dict) -> dict[str, Any]:
        """Query RAG with the alert's MITRE technique hint."""
        hint = alert.get("mitre_technique_hint", "")
        query = (
            f"{hint}. {alert.get('description', '')} "
            "What defensive actions are recommended?"
        )
        try:
            hits = self.rag.retrieve(query, top_k=3)
            return {
                "hits": hits,
                "sources": [
                    {
                        "tag": f"S{i}",
                        "title": h.get("title", ""),
                        "source": h.get("source", ""),
                    }
                    for i, h in enumerate(hits, start=1)
                ],
            }
        except Exception as exc:
            return {"hits": [], "sources": [], "error": str(exc)}

    def explain_alert(self, alert: dict) -> dict[str, Any]:
        """Generate a natural-language explanation for an alert using RAG.

        Returns the full RAG ``generate()`` result dict.
        """
        if self.rag is None:
            return {
                "answer": (
                    "⚠️ RAG engine not available. Build the FAISS index "
                    "first with `python ingest.py && python build_index.py`."
                ),
                "sources": [],
                "hits": [],
            }

        hint = alert.get("mitre_technique_hint", "")
        description = alert.get("description", "")
        evidence_summary = ""
        for ev in alert.get("evidence_events", [])[:5]:
            ts = ev.get("timestamp", "")
            user = ev.get("username", "")
            ip = ev.get("source_ip", "")
            status = ev.get("status", "")
            evidence_summary += f"  - {ts} | {user} | {ip} | {status}\n"

        question = (
            f"Security alert: {alert.get('rule_name', 'Unknown')}\n"
            f"Severity: {alert.get('severity', 'UNKNOWN')}\n"
            f"MITRE reference: {hint}\n"
            f"Description: {description}\n\n"
            f"Evidence events:\n{evidence_summary}\n"
            "Explain what this alert means, why it is concerning, "
            "what MITRE ATT&CK techniques are relevant, and "
            "what defensive steps the analyst should take."
        )

        return self.rag.generate(question, top_k=5)
