"""Turns detections into persisted, deduplicated alerts.

Rules deliberately know nothing about storage or delivery. They emit findings;
this is the single place that decides whether a finding becomes an alert, what
it looks like, where it is written and who is told.

Deduplication here is a second layer on top of each rule's cooldown. The rule
suppresses repeats of its own signal; the manager collapses identical findings
arriving from any source and reports how many were folded together, so an
analyst sees "seen 47 times" instead of 47 rows.
"""

from __future__ import annotations

from ..config.settings import IDSConfig
from ..core.events import EventBus
from ..core.models import Alert, Detection
from ..detection.state import CooldownGate, SlidingWindow
from ..observability.log import get_logger
from ..observability.metrics import Metrics
from ..storage.repositories import AlertRepository

__all__ = ["AlertManager"]


class AlertManager:
    """Deduplicates, persists and publishes alerts."""

    def __init__(
        self,
        config: IDSConfig,
        repository: AlertRepository,
        metrics: Metrics,
        bus: EventBus | None = None,
    ) -> None:
        self._config = config
        self._repository = repository
        self._metrics = metrics
        self._bus = bus
        self._gate = CooldownGate(config.alert_dedup_window, config.max_tracked_sources)
        self._pending = SlidingWindow(config.alert_dedup_window, config.max_tracked_sources)
        self._log = get_logger("alerting")

    def handle(self, detections: list[Detection]) -> list[Alert]:
        """Process detections, returning the alerts actually raised."""
        raised: list[Alert] = []
        for detection in detections:
            alert = self._handle_one(detection)
            if alert is not None:
                raised.append(alert)
        return raised

    def _handle_one(self, detection: Detection) -> Alert | None:
        key = "|".join(detection.dedup_key())
        now = detection.timestamp.timestamp()

        if not self._gate.allow(key, now):
            # Fold into the running count instead of writing another row.
            self._pending.add(key, 1, now)
            self._metrics.increment("alerts_suppressed")
            return None

        occurrences = 1 + len(self._pending.values(key, now))
        alert = Alert.from_detection(detection, occurrences=occurrences)

        try:
            self._repository.add(alert)
        except Exception:
            # Losing the database must not stop detection; the alert still
            # reaches the live stream and the failure is counted.
            self._metrics.increment("storage_errors")
            self._log.exception("could not persist alert %s", alert.id)
        else:
            self._metrics.increment("alerts_generated")

        self._publish(alert)
        self._log.info(
            "%s | %s | source=%s | %s",
            alert.severity.label.upper(),
            alert.detection_type.title,
            alert.source_ip or "-",
            alert.description,
        )
        return alert

    def _publish(self, alert: Alert) -> None:
        if self._bus is None:
            return
        try:
            self._bus.publish({"type": "alert", "alert": alert.to_dict()})
        except Exception:
            self._log.exception("could not publish alert %s to the event bus", alert.id)

    def prune(self, now: float) -> None:
        """Expire deduplication state."""
        self._gate.prune(now)
        self._pending.prune(now)
