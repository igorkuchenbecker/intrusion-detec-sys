"""Runs the rule set over normalised events.

The engine's real job is isolation. A rule that raises must not stop capture,
the other rules, the API or the dashboard -- but it must also not fail
silently, because a rule that quietly stopped detecting is worse than one that
crashed loudly. Every failure is counted and logged.
"""

from __future__ import annotations

from ..config.settings import IDSConfig
from ..core.models import Detection, SecurityEvent, TrafficMetric
from ..observability.log import get_logger
from ..observability.metrics import Metrics
from .base import DetectionRule, build_rules
from .correlation import CorrelationEngine
from .traffic_anomaly import TrafficAnomalyRule

__all__ = ["DetectionEngine"]


class DetectionEngine:
    """Evaluates every rule against each event, then correlates the results."""

    def __init__(
        self,
        config: IDSConfig,
        metrics: Metrics,
        *,
        rules: list[DetectionRule] | None = None,
        correlation: CorrelationEngine | None = None,
    ) -> None:
        self._config = config
        self._metrics = metrics
        self._rules = rules if rules is not None else build_rules(config)
        self._correlation = correlation if correlation is not None else CorrelationEngine(config)
        self._log = get_logger("detection")
        self._last_prune = 0.0

    @property
    def rules(self) -> list[DetectionRule]:
        """The rules this engine runs."""
        return list(self._rules)

    def process(self, event: SecurityEvent) -> list[Detection]:
        """Return every detection produced by ``event``."""
        detections: list[Detection] = []
        for rule in self._rules:
            detections.extend(self._evaluate(rule, event))

        if detections:
            detections.extend(self._correlate(detections))

        self._metrics.increment("detections_generated", len(detections))
        self._maybe_prune(event.timestamp.timestamp())
        return detections

    def tick(self, now: float) -> list[Detection]:
        """Give time-driven rules a chance to fire while the pipeline is idle."""
        detections: list[Detection] = []
        for rule in self._rules:
            try:
                detections.extend(rule.tick(now))
            except Exception:
                self._metrics.increment("rule_errors")
                self._log.exception("tick failed for rule %s; continuing", rule.name)
        if detections:
            detections.extend(self._correlate(detections))
            self._metrics.increment("detections_generated", len(detections))
        return detections

    def drain_metrics(self) -> list[TrafficMetric]:
        """Collect traffic windows closed by the traffic rule."""
        metrics: list[TrafficMetric] = []
        for rule in self._rules:
            if isinstance(rule, TrafficAnomalyRule):
                metrics.extend(rule.drain_metrics())
        return metrics

    def state_sizes(self) -> dict[str, int]:
        """Per-rule tracked-key counts, exposed for observability."""
        sizes = {rule.name: rule.state_size() for rule in self._rules}
        sizes[self._correlation.name] = self._correlation.state_size()
        return sizes

    def _evaluate(self, rule: DetectionRule, event: SecurityEvent) -> list[Detection]:
        try:
            return rule.evaluate(event)
        except Exception:
            # Broad on purpose: a third-party rule must never take the pipeline
            # down. Never silent, though -- counted and logged with traceback.
            self._metrics.increment("rule_errors")
            self._log.exception("rule %s failed; continuing with the others", rule.name)
            return []

    def _correlate(self, detections: list[Detection]) -> list[Detection]:
        try:
            return self._correlation.correlate(detections)
        except Exception:
            self._metrics.increment("rule_errors")
            self._log.exception("correlation failed; emitting uncorrelated detections")
            return []

    def _maybe_prune(self, now: float) -> None:
        """Expire rule state at most once per second of event time."""
        if now - self._last_prune < 1.0:
            return
        self._last_prune = now
        for rule in self._rules:
            try:
                rule.prune(now)
            except Exception:
                self._metrics.increment("rule_errors")
                self._log.exception("pruning failed for rule %s", rule.name)
        self._correlation.prune(now)
