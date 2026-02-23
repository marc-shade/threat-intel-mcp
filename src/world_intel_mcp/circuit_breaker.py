"""Per-source circuit breaker for world-intel-mcp.

Tracks failures per data source. Trips after N consecutive failures,
blocks calls for a cooldown period, then allows a single probe.
"""

import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger("world-intel-mcp.circuit_breaker")


@dataclass
class _State:
    failures: int = 0
    last_failure: float = 0.0
    tripped_at: float = 0.0
    is_open: bool = False
    total_trips: int = 0
    total_successes: int = 0
    total_failures: int = 0


class CircuitBreaker:
    """Circuit breaker with configurable thresholds per source."""

    def __init__(
        self,
        failure_threshold: int = 3,
        cooldown_seconds: float = 300.0,
    ):
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self._states: dict[str, _State] = {}

    def _get(self, source: str) -> _State:
        if source not in self._states:
            self._states[source] = _State()
        return self._states[source]

    def is_available(self, source: str) -> bool:
        """Check if source is available (circuit closed or cooldown elapsed)."""
        state = self._get(source)
        if not state.is_open:
            return True
        if time.time() - state.tripped_at >= self.cooldown_seconds:
            return True  # allow probe
        return False

    def record_success(self, source: str) -> None:
        """Record successful call — resets failure count, closes circuit."""
        state = self._get(source)
        state.failures = 0
        state.is_open = False
        state.total_successes += 1

    def record_failure(self, source: str) -> None:
        """Record failed call — increments counter, may trip breaker."""
        state = self._get(source)
        state.failures += 1
        state.last_failure = time.time()
        state.total_failures += 1
        if state.failures >= self.failure_threshold and not state.is_open:
            state.is_open = True
            state.tripped_at = time.time()
            state.total_trips += 1
            logger.warning(
                "Circuit breaker TRIPPED for %s (failures=%d, cooldown=%.0fs)",
                source, state.failures, self.cooldown_seconds,
            )

    def status(self) -> dict[str, dict]:
        """Return status of all tracked sources."""
        now = time.time()
        result = {}
        for source, state in self._states.items():
            if state.is_open:
                remaining = max(0, self.cooldown_seconds - (now - state.tripped_at))
                status = "open" if remaining > 0 else "half-open"
            else:
                remaining = 0
                status = "closed"
            result[source] = {
                "status": status,
                "failures": state.failures,
                "cooldown_remaining_s": round(remaining, 1),
                "total_trips": state.total_trips,
                "total_successes": state.total_successes,
                "total_failures": state.total_failures,
            }
        return result
