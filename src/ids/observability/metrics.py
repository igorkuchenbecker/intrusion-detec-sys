"""Runtime counters.

An IDS that cannot say how many packets it dropped is not trustworthy: silence
could mean a quiet network or a broken pipeline, and those must be
distinguishable. Every stage of the pipeline increments a counter here, and the
whole set is exposed on the API and the dashboard.
"""

from __future__ import annotations

import threading
from typing import Any

__all__ = ["Metrics", "COUNTER_NAMES"]

COUNTER_NAMES = (
    "packets_captured",
    "packets_parsed",
    "packets_unparsed",
    "packets_dropped",
    "events_processed",
    "host_events_processed",
    "detections_generated",
    "alerts_generated",
    "alerts_suppressed",
    "processing_errors",
    "rule_errors",
    "storage_errors",
)


class Metrics:
    """Thread-safe counters and gauges shared across every thread."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = dict.fromkeys(COUNTER_NAMES, 0)
        self._gauges: dict[str, float] = {"queue_size": 0.0, "queue_capacity": 0.0}

    def increment(self, name: str, amount: int = 1) -> None:
        """Add ``amount`` to counter ``name``."""
        if name not in self._counters:
            raise KeyError(f"unknown counter: {name!r}")
        with self._lock:
            self._counters[name] += amount

    def set_gauge(self, name: str, value: float) -> None:
        """Set gauge ``name`` to ``value``."""
        with self._lock:
            self._gauges[name] = value

    def get(self, name: str) -> int:
        """Return the current value of counter ``name``."""
        with self._lock:
            return self._counters[name]

    def snapshot(self) -> dict[str, Any]:
        """Return a consistent copy of every counter and gauge."""
        with self._lock:
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
            }
