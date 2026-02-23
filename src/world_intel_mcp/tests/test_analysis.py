"""Tests for circuit breaker and infrastructure."""

import time

import pytest

from world_intel_mcp.circuit_breaker import CircuitBreaker


def test_circuit_starts_closed() -> None:
    cb = CircuitBreaker(failure_threshold=3, cooldown_seconds=1.0)
    assert cb.is_available("test-source")


def test_circuit_trips_after_threshold() -> None:
    cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=10.0)
    cb.record_failure("src")
    assert cb.is_available("src")  # 1 failure, threshold is 2
    cb.record_failure("src")
    assert not cb.is_available("src")  # tripped


def test_circuit_recovers_after_cooldown() -> None:
    cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=0.5)
    cb.record_failure("src")
    assert not cb.is_available("src")
    time.sleep(0.6)
    assert cb.is_available("src")  # half-open, allows probe


def test_success_resets_failures() -> None:
    cb = CircuitBreaker(failure_threshold=3, cooldown_seconds=10.0)
    cb.record_failure("src")
    cb.record_failure("src")
    cb.record_success("src")
    assert cb.is_available("src")
    # Even after 2 more failures, need 3 consecutive
    cb.record_failure("src")
    cb.record_failure("src")
    assert cb.is_available("src")  # only 2 since reset


def test_status_output() -> None:
    cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=60.0)
    cb.record_success("healthy")
    cb.record_failure("unhealthy")
    cb.record_failure("unhealthy")

    status = cb.status()
    assert status["healthy"]["status"] == "closed"
    assert status["unhealthy"]["status"] == "open"
    assert status["unhealthy"]["total_trips"] == 1


def test_independent_sources() -> None:
    cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=60.0)
    cb.record_failure("source_a")
    assert not cb.is_available("source_a")
    assert cb.is_available("source_b")  # independent
