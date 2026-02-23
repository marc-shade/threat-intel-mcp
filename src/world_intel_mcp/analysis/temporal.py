"""Temporal baseline anomaly detection using Welford's online algorithm.

Maintains per-metric running statistics in SQLite and detects deviations
from historical baselines. The only analysis module with I/O (justified
for streaming stats persistence).
"""

from __future__ import annotations

import logging
import math
import os
import sqlite3
from datetime import datetime, timezone

logger = logging.getLogger("world-intel-mcp.analysis.temporal")

_DB_PATH = os.path.join(
    os.path.expanduser("~"), ".cache", "world-intel-mcp", "temporal.db"
)


class TemporalBaseline:
    """Streaming anomaly detector with Welford's algorithm + SQLite persistence."""

    def __init__(self, db_path: str = _DB_PATH):
        self._db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS baselines (
                key TEXT PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0,
                mean REAL NOT NULL DEFAULT 0.0,
                m2 REAL NOT NULL DEFAULT 0.0,
                updated_at TEXT NOT NULL
            )"""
        )
        self._conn.commit()

    def _key(self, event_type: str, region: str) -> str:
        """Build a composite key including weekday and month for seasonality."""
        now = datetime.now(timezone.utc)
        weekday = now.strftime("%A")
        month = now.strftime("%B")
        return f"{event_type}:{region}:{weekday}:{month}"

    def record(self, event_type: str, region: str, count: int) -> None:
        """Record an observation using Welford's online update."""
        key = self._key(event_type, region)
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        row = self._conn.execute(
            "SELECT count, mean, m2 FROM baselines WHERE key = ?", (key,)
        ).fetchone()

        if row is None:
            n, mean, m2 = 0, 0.0, 0.0
        else:
            n, mean, m2 = int(row[0]), float(row[1]), float(row[2])

        # Welford update
        n += 1
        delta = count - mean
        mean += delta / n
        delta2 = count - mean
        m2 += delta * delta2

        self._conn.execute(
            """INSERT INTO baselines (key, count, mean, m2, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET
                   count = excluded.count,
                   mean = excluded.mean,
                   m2 = excluded.m2,
                   updated_at = excluded.updated_at""",
            (key, n, mean, m2, now_iso),
        )
        self._conn.commit()

    def check(self, event_type: str, region: str, count: int) -> dict | None:
        """Check a value against the baseline.

        Returns None if: not enough data (n < 10), or value is within 1.5 std.
        Otherwise returns anomaly dict with z_score, severity, multiplier, message.
        """
        key = self._key(event_type, region)

        row = self._conn.execute(
            "SELECT count, mean, m2 FROM baselines WHERE key = ?", (key,)
        ).fetchone()

        if row is None:
            return None

        n, mean, m2 = int(row[0]), float(row[1]), float(row[2])

        if n < 10:
            return None

        variance = m2 / (n - 1)
        std = math.sqrt(variance) if variance > 0 else 0.0

        if std == 0:
            return None

        z_score = (count - mean) / std

        if z_score < 1.5:
            return None

        # Severity levels
        if z_score >= 3.0:
            severity = "critical"
        elif z_score >= 2.0:
            severity = "high"
        else:
            severity = "medium"

        multiplier = count / mean if mean > 0 else float("inf")

        now = datetime.now(timezone.utc)
        weekday = now.strftime("%A")
        month = now.strftime("%B")
        message = (
            f"{event_type.replace('_', ' ').title()} {multiplier:.1f}x normal "
            f"for {weekday} ({month})"
        )

        return {
            "event_type": event_type,
            "region": region,
            "z_score": round(z_score, 2),
            "severity": severity,
            "multiplier": round(multiplier, 1),
            "message": message,
            "observed": count,
            "expected": round(mean),
        }

    def record_and_check(
        self, event_type: str, region: str, count: int
    ) -> dict | None:
        """Record an observation and check for anomaly in one call."""
        self.record(event_type, region, count)
        return self.check(event_type, region, count)
