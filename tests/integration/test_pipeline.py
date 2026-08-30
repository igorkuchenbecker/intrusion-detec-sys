"""End-to-end pipeline tests: packets in, alerts in SQLite.

These run the real threaded engine against synthetic packets, so capture,
parsing, detection, alerting and persistence are all exercised together --
without a network interface or any privileges.
"""

from __future__ import annotations

import pytest

from ids.capture.simulator import TrafficSimulator
from ids.config.settings import IDSConfig
from ids.core.engine import IDSEngine
from ids.core.enums import DetectionType, Severity
from ids.storage.repositories import AlertFilters


@pytest.fixture()
def engine(tmp_path):
    config = IDSConfig(
        database_path=str(tmp_path / "ids.db"),
        traffic_baseline_windows=3,
        traffic_window=2.0,
        traffic_min_packets=10,
        port_scan_threshold=10,
        brute_force_threshold=5,
    )
    engine = IDSEngine(config)
    engine.start(capture=False)
    yield engine
    engine.stop()


def _alert_types(engine) -> set[str]:
    return {alert.detection_type.code for alert in engine.alerts.list(limit=100)}


def test_port_scan_travels_the_whole_pipeline(engine) -> None:
    simulator = TrafficSimulator()
    for packet in simulator.port_scan(source="10.0.0.66"):
        engine.submit_packet(packet)
    assert engine.wait_idle(timeout=15.0)

    alerts = engine.alerts.list(AlertFilters(detection_type=DetectionType.PORT_SCAN))
    assert alerts
    assert alerts[0].source_ip == "10.0.0.66"
    assert alerts[0].evidence["unique_ports"] >= 10
    assert alerts[0].mitre_technique == "T1046"


def test_benign_traffic_produces_no_alerts(engine) -> None:
    """The most important integration test: quiet networks must stay quiet."""
    for packet in TrafficSimulator().normal_traffic(count=200):
        engine.submit_packet(packet)
    assert engine.wait_idle(timeout=15.0)
    assert engine.alerts.count() == 0


def test_host_events_reach_detection(engine) -> None:
    for event in TrafficSimulator().brute_force_events(source="10.0.0.88", count=8):
        engine.submit_event(event)
    assert engine.wait_idle(timeout=15.0)
    assert DetectionType.BRUTE_FORCE.code in _alert_types(engine)


def test_correlated_scenario_groups_one_source(engine) -> None:
    TrafficSimulator().feed(engine, "correlated")
    assert engine.wait_idle(timeout=20.0)

    types = _alert_types(engine)
    assert DetectionType.CORRELATED_ACTIVITY.code in types
    correlated = engine.alerts.list(AlertFilters(detection_type=DetectionType.CORRELATED_ACTIVITY))[
        0
    ]
    assert correlated.source_ip == "10.0.0.99"
    # Grouping adds context, never impact.
    assert correlated.severity is not Severity.CRITICAL


def test_events_and_metrics_are_persisted(engine) -> None:
    TrafficSimulator().feed(engine, "traffic_burst")
    assert engine.wait_idle(timeout=20.0)
    engine._flush_events(force=True)

    assert engine.events.count() > 0
    assert engine.traffic.recent()


def test_pipeline_counters_add_up(engine) -> None:
    packets = TrafficSimulator().port_scan()
    for packet in packets:
        engine.submit_packet(packet)
    assert engine.wait_idle(timeout=15.0)

    counters = engine.metrics.snapshot()["counters"]
    assert counters["packets_captured"] == len(packets)
    assert counters["packets_parsed"] == len(packets)
    assert counters["packets_dropped"] == 0


def test_malformed_input_does_not_stop_the_pipeline(engine) -> None:
    """A packet the parser cannot handle must be counted, not fatal."""
    engine.submit_packet(object())
    for packet in TrafficSimulator().port_scan():
        engine.submit_packet(packet)
    assert engine.wait_idle(timeout=15.0)

    assert engine.metrics.get("processing_errors") >= 1
    assert engine.alerts.count() >= 1  # the good packets still produced an alert


def test_backpressure_drops_instead_of_growing(tmp_path) -> None:
    """A full queue must drop and count, never consume memory without bound."""
    config = IDSConfig(database_path=str(tmp_path / "ids.db"), queue_max_size=5)
    engine = IDSEngine(config)  # deliberately not started: nothing drains
    try:
        accepted = sum(engine.submit_packet(object()) for _ in range(50))
        assert accepted == 5
        assert engine.metrics.get("packets_dropped") == 45
    finally:
        engine.stop()


def test_shutdown_is_clean_and_repeatable(tmp_path) -> None:
    import threading

    config = IDSConfig(database_path=str(tmp_path / "ids.db"))
    engine = IDSEngine(config)
    engine.start(capture=False)
    TrafficSimulator().feed(engine, "port_scan")
    engine.stop()
    engine.stop()  # idempotent

    remaining = [t for t in threading.enumerate() if t.name.startswith("ids-")]
    assert remaining == []
