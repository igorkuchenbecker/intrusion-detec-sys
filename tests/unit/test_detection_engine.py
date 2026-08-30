"""Tests for rule error isolation and engine bookkeeping."""

from __future__ import annotations

from ids.core.enums import DetectionType
from ids.detection.base import DetectionRule
from ids.detection.engine import DetectionEngine
from ids.detection.port_scan import PortScanRule
from ids.observability.metrics import Metrics
from tests.conftest import syn


class ExplodingRule(DetectionRule):
    """A rule that always fails, to prove failures stay contained."""

    name = "exploding"
    detection_type = DetectionType.PORT_SCAN

    def evaluate(self, event):
        raise RuntimeError("rule is broken")

    def tick(self, now):
        raise RuntimeError("tick is broken too")

    def prune(self, now):
        raise RuntimeError("pruning is broken as well")


def test_a_broken_rule_does_not_stop_the_others(config) -> None:
    metrics = Metrics()
    engine = DetectionEngine(config, metrics, rules=[ExplodingRule(config), PortScanRule(config)])

    detections = []
    for index, port in enumerate([21, 22, 23, 25, 53, 80, 110]):
        detections.extend(engine.process(syn("10.0.0.5", port, offset=index * 0.1)))

    assert len(detections) == 1  # the working rule still fired
    assert metrics.get("rule_errors") >= 1  # and the failure was counted, not hidden


def test_broken_tick_and_prune_are_contained(config) -> None:
    metrics = Metrics()
    engine = DetectionEngine(config, metrics, rules=[ExplodingRule(config)])
    assert engine.tick(now=1.0) == []
    assert metrics.get("rule_errors") >= 1


def test_state_sizes_are_reported_per_rule(config) -> None:
    engine = DetectionEngine(config, Metrics(), rules=[PortScanRule(config)])
    engine.process(syn("10.0.0.5", 80))
    sizes = engine.state_sizes()
    assert sizes["port_scan"] == 1
    assert "correlation" in sizes


def test_detections_are_counted(config) -> None:
    metrics = Metrics()
    engine = DetectionEngine(config, metrics, rules=[PortScanRule(config)])
    for index, port in enumerate([21, 22, 23, 25, 53, 80]):
        engine.process(syn("10.0.0.5", port, offset=index * 0.1))
    assert metrics.get("detections_generated") >= 1
