"""Tests for port-scan detection, including the cases that must NOT fire."""

from __future__ import annotations

from ids.core.enums import Confidence, DetectionType, Severity
from ids.detection.port_scan import PortScanRule
from tests.conftest import established, far_future, syn


def _feed(rule: PortScanRule, events) -> list:
    detections = []
    for event in events:
        detections.extend(rule.evaluate(event))
    return detections


def test_many_ports_from_one_source_is_detected(config) -> None:
    rule = PortScanRule(config)
    ports = [21, 22, 23, 25, 53, 80, 110]
    detections = _feed(rule, [syn("10.0.0.5", p, offset=i * 0.5) for i, p in enumerate(ports)])

    assert len(detections) == 1
    detection = detections[0]
    assert detection.detection_type is DetectionType.PORT_SCAN
    assert detection.source_ip == "10.0.0.5"
    assert detection.evidence["unique_ports"] >= config.port_scan_threshold
    assert detection.mitre_technique == "T1046"


def test_repeated_connections_to_one_port_is_not_a_scan(config) -> None:
    """The negative case: volume alone must not look like breadth."""
    rule = PortScanRule(config)
    detections = _feed(rule, [syn("10.0.0.5", 443, offset=i * 0.1) for i in range(50)])
    assert detections == []


def test_established_traffic_is_ignored(config) -> None:
    """A busy server talking on many ports is not attempting connections."""
    rule = PortScanRule(config)
    detections = _feed(
        rule, [established("10.0.0.5", p, offset=i) for i, p in enumerate(range(20))]
    )
    assert detections == []


def test_ports_spread_beyond_the_window_do_not_trigger(config) -> None:
    """Low-and-slow scanning is a documented false negative, asserted here."""
    rule = PortScanRule(config)
    spacing = config.port_scan_window  # one port per window
    detections = _feed(
        rule, [syn("10.0.0.5", p, offset=i * spacing) for i, p in enumerate(range(10))]
    )
    assert detections == []


def test_cooldown_prevents_alert_flooding(config) -> None:
    rule = PortScanRule(config)
    alerts = _feed(rule, [syn("10.0.0.5", p, offset=i * 0.1) for i, p in enumerate(range(1, 30))])
    # At most two: the threshold crossing and one escalation, never one per packet.
    assert len(alerts) <= 2


def test_distinct_sources_are_tracked_separately(config) -> None:
    """A distributed scan is the documented false negative: each source is under threshold."""
    rule = PortScanRule(config)
    events = []
    for index, port in enumerate([21, 22, 23, 25, 53, 80, 110]):
        events.append(syn(f"10.0.0.{index}", port, offset=index * 0.1))
    assert _feed(rule, events) == []


def test_large_scan_earns_one_escalated_alert(config) -> None:
    """The first alert is MEDIUM at the threshold; a far broader scan adds one HIGH."""
    rule = PortScanRule(config)
    ports = range(1, config.port_scan_threshold * 3 + 5)
    detections = _feed(rule, [syn("10.0.0.5", p, offset=i * 0.01) for i, p in enumerate(ports)])

    assert len(detections) == 2
    assert detections[0].severity is Severity.MEDIUM
    assert detections[1].severity is Severity.HIGH
    assert detections[1].confidence is Confidence.HIGH


def test_evidence_ports_are_truncated(config) -> None:
    """A thousand-port scan must not write a thousand-element array per alert."""
    wide = config.with_overrides(port_scan_threshold=40)
    rule = PortScanRule(wide)
    detections = _feed(
        rule, [syn("10.0.0.5", p, offset=i * 0.01) for i, p in enumerate(range(1, 200))]
    )
    assert len(detections[0].evidence["ports_sample"]) <= 25
    assert detections[0].evidence["ports_truncated"] is True


def test_state_is_bounded_and_prunable(config) -> None:
    rule = PortScanRule(config)
    for index in range(50):
        rule.evaluate(syn(f"10.1.0.{index}", 80, offset=index * 0.1))
    assert rule.state_size() > 0
    rule.prune(now=far_future())
    assert rule.state_size() == 0
