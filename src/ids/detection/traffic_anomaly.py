"""Traffic volume anomaly detection.

Deliberately *not* called a DDoS detector. A volume spike is a statement about
traffic, not about intent: a backup job, a software rollout and a flood all
look the same from a packet counter. The alert says what was measured and
leaves the conclusion to an analyst.

Windows are closed on event time, and the baseline is the mean of the previous
closed windows. A minimum packet count stops an idle link -- where the baseline
is near zero and any traffic is "infinitely" above it -- from alerting.
"""

from __future__ import annotations

from collections import deque
from datetime import UTC, datetime

from ..core.enums import Confidence, DetectionType, EventType, Severity
from ..core.models import Detection, SecurityEvent, TrafficMetric
from .base import DetectionRule, register
from .state import CooldownGate

__all__ = ["TrafficAnomalyRule", "TrafficWindowAggregator"]

_COOLDOWN_KEY = "global"


class TrafficWindowAggregator:
    """Accumulates traffic into fixed windows and closes them on time.

    The rule needs windows to compare against a baseline and the dashboard
    needs the same windows as metrics. Computing them once, here, keeps the two
    from disagreeing about what a window is.
    """

    def __init__(self, window_seconds: float) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self._window = window_seconds
        self._start: float | None = None
        self._packets = 0
        self._bytes = 0
        self._events = 0
        self._sources: set[str] = set()
        self._last_event = 0.0

    def add(self, event: SecurityEvent) -> TrafficMetric | None:
        """Add ``event``; return the previous window if this one closed it."""
        now = event.timestamp.timestamp()
        self._last_event = max(self._last_event, now)
        if self._start is None:
            self._start = now

        closed: TrafficMetric | None = None
        if now - self._start >= self._window:
            closed = self._close(self._start + self._window)
            self._start = now

        self._packets += 1
        self._bytes += event.packet_size
        self._events += 1
        if event.source_ip:
            self._sources.add(event.source_ip)
        return closed

    def close_if_overdue(self, now: float) -> TrafficMetric | None:
        """Close the open window if its time has elapsed.

        Without this a window only ever closes when the *next* packet arrives,
        so a burst at the end of a capture -- or any quiet period after one --
        would never be evaluated. The effective clock is the later of wall time
        and the newest event seen, so replaying a capture faster than real time
        behaves the same as live traffic.
        """
        if self._start is None or self._events == 0:
            return None
        effective = max(now, self._last_event)
        if effective - self._start < self._window:
            return None
        closed = self._close(self._start + self._window)
        self._start = effective
        return closed

    def _close(self, end: float) -> TrafficMetric:
        assert self._start is not None
        metric = TrafficMetric(
            window_start=datetime.fromtimestamp(self._start, tz=UTC),
            window_end=datetime.fromtimestamp(end, tz=UTC),
            packets=self._packets,
            bytes_total=self._bytes,
            events=self._events,
            unique_sources=len(self._sources),
        )
        self._packets = 0
        self._bytes = 0
        self._events = 0
        self._sources = set()
        return metric


@register
class TrafficAnomalyRule(DetectionRule):
    """Flags a closed window whose packet count far exceeds the baseline."""

    name = "traffic_anomaly"
    detection_type = DetectionType.TRAFFIC_VOLUME_ANOMALY

    def __init__(self, config) -> None:
        super().__init__(config)
        self._aggregator = TrafficWindowAggregator(config.traffic_window)
        self._baseline: deque[int] = deque(maxlen=config.traffic_baseline_windows)
        self._cooldown = CooldownGate(config.traffic_cooldown, max_keys=8)
        self._pending: list[TrafficMetric] = []

    def evaluate(self, event: SecurityEvent) -> list[Detection]:
        """Feed the window; evaluate the baseline whenever a window closes."""
        if event.event_type is not EventType.NETWORK_FLOW:
            return []

        closed = self._aggregator.add(event)
        if closed is None:
            return []

        self._pending.append(closed)
        detections = self._assess(closed)
        self._baseline.append(closed.packets)
        return detections

    def tick(self, now: float) -> list[Detection]:
        """Close and assess an overdue window, if there is one."""
        closed = self._aggregator.close_if_overdue(now)
        if closed is None:
            return []
        self._pending.append(closed)
        detections = self._assess(closed)
        self._baseline.append(closed.packets)
        return detections

    def drain_metrics(self) -> list[TrafficMetric]:
        """Hand over closed windows for persistence, clearing the buffer."""
        metrics = self._pending
        self._pending = []
        return metrics

    def prune(self, now: float) -> None:
        """Expire the cooldown entry."""
        self._cooldown.prune(now)

    def state_size(self) -> int:
        """Return how many baseline windows are currently held."""
        return len(self._baseline)

    def _assess(self, window: TrafficMetric) -> list[Detection]:
        if len(self._baseline) < self._baseline.maxlen:
            # Not enough history yet: reporting against a half-formed baseline
            # would just mean alerting on startup every time.
            return []
        if window.packets < self._config.traffic_min_packets:
            return []

        baseline = sum(self._baseline) / len(self._baseline)
        threshold = baseline * self._config.traffic_threshold_multiplier
        if baseline <= 0 or window.packets <= threshold:
            return []
        if not self._cooldown.allow(_COOLDOWN_KEY, window.window_end.timestamp()):
            return []

        ratio = window.packets / baseline
        return [
            Detection(
                rule=self.name,
                detection_type=self.detection_type,
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                description=(
                    f"Traffic volume in the last {window.duration_seconds:g}s window was "
                    f"{window.packets} packets, {ratio:.1f}x the recent baseline of "
                    f"{baseline:.1f}. This is a volume observation, not evidence of an "
                    "attack: backups, deployments and batch jobs look identical."
                ),
                evidence={
                    "window_packets": window.packets,
                    "window_bytes": window.bytes_total,
                    "baseline_packets": round(baseline, 2),
                    "ratio": round(ratio, 2),
                    "multiplier": self._config.traffic_threshold_multiplier,
                    "unique_sources": window.unique_sources,
                    "packets_per_second": round(window.packets_per_second, 2),
                },
                mitigation=(
                    "Correlate the window with scheduled jobs and deployments before "
                    "treating it as hostile. If unexplained, identify the top talkers "
                    "and review capacity and upstream filtering."
                ),
                timestamp=window.window_end,
            )
        ]
