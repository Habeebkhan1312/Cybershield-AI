"""
CyberShield AI — Detection Rules Engine

Deterministic, rule-based detection of suspicious patterns in
security event logs.  Each rule returns a list of Alert dicts.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

import pandas as pd


def _alert_id() -> str:
    return f"ALERT-{uuid.uuid4().hex[:8].upper()}"


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class DetectionEngine:
    """Run detection rules against a normalised event DataFrame."""

    # ── Individual rules ──────────────────────────────────────────

    @staticmethod
    def detect_brute_force(
        df: pd.DataFrame,
        threshold: int = 5,
        window_minutes: int = 5,
    ) -> list[dict[str, Any]]:
        """Detect ≥ *threshold* failed logins from the same IP in *window*.

        MITRE ATT&CK: T1110 — Brute Force.
        """
        alerts: list[dict[str, Any]] = []
        failures = df[df["status"] == "failure"].copy()
        if failures.empty:
            return alerts

        for ip, group in failures.groupby("source_ip"):
            group = group.sort_values("timestamp")
            timestamps = group["timestamp"].tolist()

            for i, ts in enumerate(timestamps):
                window_end = ts + timedelta(minutes=window_minutes)
                window_events = [t for t in timestamps[i:] if t <= window_end]

                if len(window_events) >= threshold:
                    evidence = group[
                        (group["timestamp"] >= ts)
                        & (group["timestamp"] <= window_end)
                    ].to_dict(orient="records")

                    usernames = group[
                        (group["timestamp"] >= ts)
                        & (group["timestamp"] <= window_end)
                    ]["username"].unique().tolist()

                    alerts.append(
                        {
                            "alert_id": _alert_id(),
                            "rule_name": "Brute Force Attempt",
                            "severity": "HIGH",
                            "timestamp": str(ts),
                            "description": (
                                f"{len(window_events)} failed login attempts "
                                f"from {ip} targeting user(s) "
                                f"{', '.join(usernames)} within "
                                f"{window_minutes} minutes."
                            ),
                            "evidence_events": evidence,
                            "mitre_technique_hint": "T1110 Brute Force",
                            "source_ip": ip,
                        }
                    )
                    break  # One alert per IP per pass
        return alerts

    @staticmethod
    def detect_login_after_failure(
        df: pd.DataFrame,
        min_failures: int = 3,
        window_minutes: int = 10,
    ) -> list[dict[str, Any]]:
        """Detect successful login after ≥ *min_failures* failures.

        MITRE ATT&CK: T1078 — Valid Accounts.
        """
        alerts: list[dict[str, Any]] = []
        if "status" not in df.columns:
            return alerts

        for user, group in df.groupby("username"):
            group = group.sort_values("timestamp")
            successes = group[group["status"] == "success"]
            failures = group[group["status"] == "failure"]

            if failures.empty or successes.empty:
                continue

            for _, success_row in successes.iterrows():
                s_ts = success_row["timestamp"]
                window_start = s_ts - timedelta(minutes=window_minutes)
                prior_fails = failures[
                    (failures["timestamp"] >= window_start)
                    & (failures["timestamp"] < s_ts)
                ]

                if len(prior_fails) >= min_failures:
                    evidence = prior_fails.to_dict(orient="records")
                    evidence.append(success_row.to_dict())
                    alerts.append(
                        {
                            "alert_id": _alert_id(),
                            "rule_name": "Login After Multiple Failures",
                            "severity": "MEDIUM",
                            "timestamp": str(s_ts),
                            "description": (
                                f"User {user} successfully logged in after "
                                f"{len(prior_fails)} failed attempts within "
                                f"{window_minutes} minutes "
                                f"(source: {success_row.get('source_ip', 'unknown')})."
                            ),
                            "evidence_events": evidence,
                            "mitre_technique_hint": "T1078 Valid Accounts",
                            "source_ip": str(
                                success_row.get("source_ip", "unknown")
                            ),
                        }
                    )
                    break  # One alert per user
        return alerts

    @staticmethod
    def detect_privilege_escalation(
        df: pd.DataFrame,
    ) -> list[dict[str, Any]]:
        """Detect privilege assignment following login.

        MITRE ATT&CK: T1078.002 — Valid Accounts: Domain Accounts.
        """
        alerts: list[dict[str, Any]] = []
        priv_events = df[
            df["action"].isin(["privilege_assign", "special_privilege"])
            | (df["event_id"] == 4672)
        ]

        if priv_events.empty:
            return alerts

        for _, priv_row in priv_events.iterrows():
            user = priv_row["username"]
            p_ts = priv_row["timestamp"]

            # Look for a login within 10 minutes before the privilege event
            prior_logins = df[
                (df["username"] == user)
                & (df["action"].isin(["logon", "login"]))
                & (df["status"] == "success")
                & (df["timestamp"] >= p_ts - timedelta(minutes=10))
                & (df["timestamp"] <= p_ts)
            ]

            if prior_logins.empty:
                continue

            # Check if there were any failures before the login
            login_ts = prior_logins.iloc[0]["timestamp"]
            prior_failures = df[
                (df["username"] == user)
                & (df["status"] == "failure")
                & (df["timestamp"] >= login_ts - timedelta(minutes=15))
                & (df["timestamp"] < login_ts)
            ]

            if not prior_failures.empty:
                evidence = prior_failures.to_dict(orient="records")
                evidence.extend(prior_logins.to_dict(orient="records"))
                evidence.append(priv_row.to_dict())

                alerts.append(
                    {
                        "alert_id": _alert_id(),
                        "rule_name": "Privilege Escalation After Failures",
                        "severity": "HIGH",
                        "timestamp": str(p_ts),
                        "description": (
                            f"User {user} was assigned elevated privileges "
                            f"on {priv_row.get('workstation', 'unknown')} "
                            f"after {len(prior_failures)} prior login failures."
                        ),
                        "evidence_events": evidence,
                        "mitre_technique_hint": (
                            "T1078.002 Valid Accounts: Domain Accounts"
                        ),
                        "source_ip": str(
                            priv_row.get("source_ip", "unknown")
                        ),
                    }
                )
        return alerts

    @staticmethod
    def detect_unusual_hours(
        df: pd.DataFrame,
        start_hour: int = 6,
        end_hour: int = 22,
    ) -> list[dict[str, Any]]:
        """Detect successful logins outside normal business hours.

        MITRE ATT&CK: T1078 — Valid Accounts (off-hours access).
        """
        alerts: list[dict[str, Any]] = []
        successes = df[df["status"] == "success"].copy()
        if successes.empty:
            return alerts

        for _, row in successes.iterrows():
            ts = row["timestamp"]
            hour = ts.hour

            if hour < start_hour or hour >= end_hour:
                alerts.append(
                    {
                        "alert_id": _alert_id(),
                        "rule_name": "Off-Hours Login",
                        "severity": "LOW",
                        "timestamp": str(ts),
                        "description": (
                            f"User {row['username']} logged in at "
                            f"{ts.strftime('%H:%M UTC')} from "
                            f"{row.get('source_ip', 'unknown')} "
                            f"(outside {start_hour:02d}:00–{end_hour:02d}:00)."
                        ),
                        "evidence_events": [row.to_dict()],
                        "mitre_technique_hint": "T1078 Valid Accounts",
                        "source_ip": str(row.get("source_ip", "unknown")),
                    }
                )
        return alerts

    # ── Run all rules ─────────────────────────────────────────────

    def run_all_rules(self, df: pd.DataFrame) -> list[dict[str, Any]]:
        """Execute every detection rule and return deduplicated, sorted alerts."""
        all_alerts: list[dict[str, Any]] = []
        all_alerts.extend(self.detect_brute_force(df))
        all_alerts.extend(self.detect_login_after_failure(df))
        all_alerts.extend(self.detect_privilege_escalation(df))
        all_alerts.extend(self.detect_unusual_hours(df))

        # Sort: severity (HIGH first) → timestamp
        all_alerts.sort(
            key=lambda a: (
                SEVERITY_ORDER.get(a["severity"], 99),
                a["timestamp"],
            )
        )
        return all_alerts
