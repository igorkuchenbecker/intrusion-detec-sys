"""Tests for traffic volume anomaly detection."""

from __future__ import annotations

from ids.core.enums import Confidence, DetectionType
from ids.detection.traffic_anomaly import TrafficAnomalyRule, TrafficWindowAggregator
from tests.conftest import at, established


def _steady(rule: TrafficAnomalyRule, windows: int, window: float, per_window: int) -> None:
    """Feed evenly spread traffic so the baseline fills."""
    for index in range(windows * per_window):
        offset = index * (window / per_window)
        rule.evaluate(established("192.168.1.10", 443, offset=offset))


def test_no_alert_before_the_baseline_is_full(config) -> None:
    rule = TrafficAnomalyRule(config)
    detections = []
    for index in range(40):
        detections.extend(established_eval(rule, index * 0.5))
    assert detections == []


def established_eval(rule, offset):
    return rule.evaluate(established("192.168.1.10", 443, offset=offset))


def test_spike_over_a_full_baseline_is_detected(config) -> None:
    rule = TrafficAnomalyRule(config)
    window = config.traffic_window
    per_window = 12
    baseline_windows = config.traffic_baseline_windows + 1
    _steady(rule, baseline_windows, window, per_window)

    detections = []
    start = baseline_windows * window
    burst = per_window * 20
    for index in range(burst):
        offset = start + index * (window * 2 / burst)
        detections.extend(rule.evaluate(established("10.0.0.9", 443, offset=offset)))

    assert len(detections) >= 1
    detection = detections[0]
    assert detection.detection_type is DetectionType.TRAFFIC_VOLUME_ANOMALY
    # Volume alone is weak evidence, and the rule says so.
    assert detection.confidence is Confidence.LOW
    assert detection.evidence["ratio"] > config.traffic_threshold_multiplier


def test_steady_traffic_never_alerts(config) -> None:
    rule = TrafficAnomalyRule(config)
    detections = []
    for index in range(300):
        offset = index * (config.traffic_window / 12)
        detections.extend(rule.evaluate(established("192.168.1.10", 443, offset=offset)))
    assert detections == []


def test_tiny_windows_are_below_the_minimum_packet_floor(config) -> None:
    """An idle link must not alert just because the baseline is near zero."""
    rule = TrafficAnomalyRule(config)
    detections = []
    for index in range(20):
        offset = index * config.traffic_window * 1.5  # about one packet per window
        detections.extend(rule.evaluate(established("192.168.1.10", 443, offset=offset)))
    assert detections == []


def test_aggregator_closes_a_window_and_reports_rates() -> None:
    aggregator = TrafficWindowAggregator(window_seconds=5.0)
    for index in range(10):
        assert aggregator.add(established("10.0.0.1", 80, offset=index * 0.4, size=100)) is None
    closed = aggregator.add(established("10.0.0.1", 80, offset=6.0))
    assert closed is not None
    assert closed.packets == 10
    assert closed.bytes_total == 1000
    assert closed.packets_per_second == 2.0


def test_aggregator_closes_overdue_window_without_new_traffic() -> None:
    """A burst at the end of a capture must still be evaluated."""
    aggregator = TrafficWindowAggregator(window_seconds=5.0)
    aggregator.add(established("10.0.0.1", 80, offset=0.0))
    assert aggregator.close_if_overdue(now=at(1.0).timestamp()) is None
    closed = aggregator.close_if_overdue(now=at(30.0).timestamp())
    assert closed is not None and closed.packets == 1


def test_metrics_are_drained_for_persistence(config) -> None:
    rule = TrafficAnomalyRule(config)
    _steady(rule, 3, config.traffic_window, 10)
    metrics = rule.drain_metrics()
    assert metrics
    assert rule.drain_metrics() == []  # drained once, not twice
