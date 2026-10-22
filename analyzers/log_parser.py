"""
CyberShield AI — Log Parser

Parses CSV and JSON security logs, validates schemas, and normalizes
event fields for downstream detection rules.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any, BinaryIO

import pandas as pd


# ── Required columns per schema type ──────────────────────────────
SCHEMAS: dict[str, list[str]] = {
    "auth_log": [
        "timestamp",
        "event_id",
        "username",
        "source_ip",
        "action",
        "status",
    ],
    "siem_alert": [
        "timestamp",
        "alert_name",
        "severity",
        "source_ip",
        "username",
        "description",
    ],
}


class LogParser:
    """Parse, validate, and normalize security event logs."""

    # ── CSV parsing ───────────────────────────────────────────────

    @staticmethod
    def parse_csv(
        source: str | Path | BinaryIO,
    ) -> pd.DataFrame:
        """Read a CSV file or file-like object into a DataFrame.

        Columns are lower-cased and stripped of whitespace.
        """
        if isinstance(source, (str, Path)):
            df = pd.read_csv(source)
        else:
            # Streamlit UploadedFile or BytesIO
            content = source.read()
            if isinstance(content, bytes):
                content = content.decode("utf-8", errors="replace")
            df = pd.read_csv(io.StringIO(content))

        df.columns = [c.strip().lower() for c in df.columns]
        return df

    # ── JSON parsing ──────────────────────────────────────────────

    @staticmethod
    def parse_json(
        source: str | Path | BinaryIO,
    ) -> pd.DataFrame:
        """Read a JSON array or JSONL file into a DataFrame."""
        if isinstance(source, (str, Path)):
            text = Path(source).read_text(encoding="utf-8")
        else:
            raw = source.read()
            text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw

        text = text.strip()

        # JSON array
        if text.startswith("["):
            records: list[dict[str, Any]] = json.loads(text)
        else:
            # JSONL — one object per line
            records = [json.loads(line) for line in text.splitlines() if line.strip()]

        df = pd.DataFrame(records)
        df.columns = [c.strip().lower() for c in df.columns]
        return df

    # ── Schema validation ─────────────────────────────────────────

    @staticmethod
    def validate_schema(
        df: pd.DataFrame,
        schema_type: str = "auth_log",
    ) -> tuple[bool, list[str]]:
        """Check that *df* contains the required columns for *schema_type*.

        Returns ``(ok, issues)`` where *issues* is a list of problem
        descriptions (empty when *ok* is True).
        """
        required = SCHEMAS.get(schema_type)
        if required is None:
            return False, [f"Unknown schema type: {schema_type}"]

        issues: list[str] = []
        if df.empty:
            issues.append("The uploaded file contains no data rows.")
            return False, issues

        missing = [col for col in required if col not in df.columns]
        if missing:
            issues.append(f"Missing required columns: {', '.join(missing)}")

        return (len(issues) == 0), issues

    # ── Normalization ─────────────────────────────────────────────

    @staticmethod
    def normalize_events(df: pd.DataFrame) -> pd.DataFrame:
        """Standardize column names, parse timestamps, fill gaps."""
        df = df.copy()

        # Parse timestamp
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(
                df["timestamp"], utc=True, errors="coerce"
            )

        # Lowercase string fields
        for col in ("username", "action", "status", "source_ip"):
            if col in df.columns:
                df[col] = df[col].astype(str).str.strip().str.lower()

        # Fill missing workstation
        if "workstation" in df.columns:
            df["workstation"] = df["workstation"].fillna("unknown")
        else:
            df["workstation"] = "unknown"

        # Ensure event_id is integer where present
        if "event_id" in df.columns:
            df["event_id"] = pd.to_numeric(df["event_id"], errors="coerce").fillna(0).astype(int)

        # Sort chronologically
        if "timestamp" in df.columns:
            df = df.sort_values("timestamp").reset_index(drop=True)

        return df
