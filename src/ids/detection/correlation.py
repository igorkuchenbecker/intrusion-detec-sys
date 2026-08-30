"""Correlation of detections from the same source.

Grouping is the goal, not escalation. Seeing a scan and then failed logins from
one address is worth surfacing as a single storyline, but three weak signals do
not add up to a strong one, so the correlated finding inherits the highest
severity among its parts rather than exceeding it.

Correlation runs after the rules, on their output, so it stays independent of
how any individual rule reaches its conclusion.
"""

from __future__ import annotations

from ..core.enums import Confidence, DetectionType, Severity
from ..core.models import Detection
from .state import CooldownGate, SlidingWindow

__all__ = ["CorrelationEngine"]


class CorrelationEngine:
    """Emits a correlated finding when one source triggers several rule types."""

    name = "correlation"

    def __init__(self, config) -> None:
        self._config = config
        self._seen = SlidingWindow(config.correlation_window, config.max_tracked_sources)
        self._severities = SlidingWindow(config.correlation_window, config.max_tracked_sources)
        self._cooldown = CooldownGate(config.correlation_window, config.max_tracked_sources)

    def correlate(self, detections: list[Detection]) -> list[Detection]:
        """Return correlated findings produced by ``detections``."""
        correlated: list[Detection] = []
        for detection in detections:
            if detection.detection_type is DetectionType.CORRELATED_ACTIVITY:
                continue  # never correlate correlations
            source = detection.source_ip
            if source is None:
                continue

            now = detection.timestamp.timestamp()
            self._seen.add(source, detection.detection_type.code, now)
            self._severities.add(source, detection.severity.rank, now)

            types = self._seen.unique(source, now)
            if len(types) < self._config.correlation_min_types:
                continue
            if not self._cooldown.allow(source, now):
                continue

            correlated.append(self._build(detection, sorted(types), source, now))
        return correlated

    def prune(self, now: float) -> None:
        """Expire correlation state."""
        self._seen.prune(now)
        self._severities.prune(now)
        self._cooldown.prune(now)

    def state_size(self) -> int:
        """Return how many sources are currently tracked."""
        return len(self._seen)

    def _build(self, latest: Detection, types: list[str], source: str, now: float) -> Detection:
        ranks = self._severities.values(source, now)
        peak = max(ranks) if ranks else latest.severity.rank
        # Inherit, never exceed: correlation adds context, not impact.
        severity = next(member for member in Severity if member.rank == peak)

        return Detection(
            rule=self.name,
            detection_type=DetectionType.CORRELATED_ACTIVITY,
            severity=severity,
            confidence=Confidence.MEDIUM,
            description=(
                f"{source} triggered {len(types)} different detection types within "
                f"{self._config.correlation_window:g}s: {', '.join(types)}. Reported as "
                "one storyline; severity is inherited from the strongest component and "
                "is not escalated for the grouping itself."
            ),
            evidence={
                "detection_types": types,
                "window_seconds": self._config.correlation_window,
                "component_count": len(types),
                "peak_component_severity": severity.label,
            },
            mitigation=(
                "Review this source's full activity together rather than as separate "
                "alerts, and decide on containment from the combined picture."
            ),
            source_ip=source,
            timestamp=latest.timestamp,
        )
