"""Keyword spike detection with CVE/APT extraction.

Compares recent keyword frequencies against stored baselines to detect
abnormal surges. Uses SQLite for baseline persistence (like temporal.py).
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
from datetime import datetime, timezone

logger = logging.getLogger("world-intel-mcp.analysis.spikes")

_DB_PATH = os.path.join(
    os.path.expanduser("~"), ".cache", "world-intel-mcp", "keyword_spikes.db"
)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_APT_RE = re.compile(
    r"\b(APT\d{1,3}|Lazarus|Fancy Bear|Cozy Bear|Sandworm|Turla|Kimsuky|"
    r"Volt Typhoon|Salt Typhoon|Midnight Blizzard|Scattered Spider|"
    r"LockBit|BlackCat|ALPHV|CL0P|Black Basta|Charming Kitten)\b",
    re.IGNORECASE,
)


class KeywordSpikeDetector:
    """Detects keyword frequency spikes against rolling baselines."""

    def __init__(self, db_path: str = _DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS kw_baselines (
                keyword TEXT PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0,
                mean REAL NOT NULL DEFAULT 0.0,
                m2 REAL NOT NULL DEFAULT 0.0,
                updated_at TEXT NOT NULL
            )"""
        )
        self._conn.commit()

    def _get_baseline(self, keyword: str) -> tuple[int, float, float]:
        """Get (count, mean, m2) for a keyword."""
        row = self._conn.execute(
            "SELECT count, mean, m2 FROM kw_baselines WHERE keyword = ?",
            (keyword,),
        ).fetchone()
        return row if row else (0, 0.0, 0.0)

    def _update_baseline(self, keyword: str, value: float) -> None:
        """Welford's online update for running mean/variance."""
        n, mean, m2 = self._get_baseline(keyword)
        n += 1
        delta = value - mean
        mean += delta / n
        delta2 = value - mean
        m2 += delta * delta2
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """INSERT INTO kw_baselines (keyword, count, mean, m2, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(keyword) DO UPDATE SET
                 count=?, mean=?, m2=?, updated_at=?""",
            (keyword, n, mean, m2, now, n, mean, m2, now),
        )
        self._conn.commit()

    def detect_spikes(
        self,
        keyword_counts: dict[str, int],
        z_threshold: float = 2.0,
    ) -> list[dict]:
        """Compare current keyword counts against baselines.

        Args:
            keyword_counts: {keyword: count} from current window.
            z_threshold: Z-score threshold for spike detection.

        Returns:
            List of spike dicts sorted by z-score descending.
        """
        spikes: list[dict] = []

        for kw, current_count in keyword_counts.items():
            n, mean, m2 = self._get_baseline(kw)

            if n < 3:
                # Not enough data for meaningful z-score
                self._update_baseline(kw, float(current_count))
                continue

            variance = m2 / n
            stddev = variance ** 0.5

            if stddev < 0.1:
                # Near-zero variance — use ratio instead
                ratio = current_count / max(mean, 0.1)
                if ratio > 3.0:
                    spikes.append({
                        "keyword": kw,
                        "current_count": current_count,
                        "baseline_mean": round(mean, 2),
                        "ratio": round(ratio, 2),
                        "z_score": None,
                        "detection": "ratio",
                    })
            else:
                z = (current_count - mean) / stddev
                if z >= z_threshold:
                    spikes.append({
                        "keyword": kw,
                        "current_count": current_count,
                        "baseline_mean": round(mean, 2),
                        "stddev": round(stddev, 2),
                        "z_score": round(z, 2),
                        "ratio": round(current_count / max(mean, 0.1), 2),
                        "detection": "z_score",
                    })

            # Update baseline
            self._update_baseline(kw, float(current_count))

        spikes.sort(key=lambda s: s.get("z_score") or s.get("ratio", 0), reverse=True)
        return spikes


# Module-level singleton
_detector: KeywordSpikeDetector | None = None


def _ensure_detector() -> KeywordSpikeDetector:
    global _detector
    if _detector is None:
        _detector = KeywordSpikeDetector()
    return _detector


async def fetch_keyword_spikes(
    fetcher,
    min_count: int = 3,
    z_threshold: float = 2.0,
) -> dict:
    """Fetch trending keywords and detect spikes against baselines.

    Also extracts CVE identifiers and APT group mentions from headlines.
    """
    from ..sources import news

    # Get current keyword frequencies
    kw_data = await news.fetch_trending_keywords(fetcher, min_count=min_count)
    keywords = kw_data.get("keywords", [])

    # Build count dict
    kw_counts: dict[str, int] = {}
    for item in keywords:
        kw_counts[item["keyword"]] = item["count"]

    # Detect spikes
    detector = _ensure_detector()
    spikes = detector.detect_spikes(kw_counts, z_threshold=z_threshold)

    # Extract CVEs and APTs from all recent headlines
    feed_data = await news.fetch_news_feed(fetcher, limit=100)
    all_text = " ".join(
        (it.get("title", "") + " " + it.get("summary", ""))
        for it in feed_data.get("items", [])
    )
    cve_mentions = list(set(_CVE_RE.findall(all_text)))
    apt_mentions = list(set(m.lower() for m in _APT_RE.findall(all_text)))

    return {
        "spikes": spikes,
        "spike_count": len(spikes),
        "keywords_analyzed": len(kw_counts),
        "z_threshold": z_threshold,
        "cve_mentions": sorted(cve_mentions),
        "apt_mentions": sorted(apt_mentions),
        "cve_count": len(cve_mentions),
        "apt_count": len(apt_mentions),
        "source": "keyword-spike-detector",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
