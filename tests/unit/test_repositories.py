"""Tests for the storage layer."""

from __future__ import annotations

import threading

from ids.core.enums import Confidence, DetectionType, EventType, Protocol, Severity
from ids.core.models import Alert, Detection, SecurityEvent, TrafficMetric, utc_now
from ids.storage.repositories import (
    AlertFilters,
    AlertRepository,
    EventRepository,
    MetricRepository,
)
from tests.conftest import at


def _alert(source: str = "10.0.0.5", severity: Severity = Severity.HIGH) -> Alert:
    detection = Detection(
        rule="port_scan",
        detection_type=DetectionType.PORT_SCAN,
        severity=severity,
        confidence=Confidence.MEDIUM,
        description="desc",
        evidence={"unique_ports": 20},
        mitigation="mitigate",
        source_ip=source,
        timestamp=utc_now(),
    )
    return Alert.from_detection(detection)


def test_alert_roundtrip(database) -> None:
    repo = AlertRepository(database)
    alert = _alert()
    repo.add(alert)

    stored = repo.get(alert.id)
    assert stored is not None
    assert stored.source_ip == "10.0.0.5"
    assert stored.evidence == {"unique_ports": 20}
    assert stored.severity is Severity.HIGH
    assert stored.detection_type is DetectionType.PORT_SCAN


def test_filters_are_applied(database) -> None:
    repo = AlertRepository(database)
    repo.add(_alert("10.0.0.5", Severity.HIGH))
    repo.add(_alert("10.0.0.9", Severity.LOW))

    assert repo.count(AlertFilters(severity=Severity.HIGH)) == 1
    assert repo.count(AlertFilters(source_ip="10.0.0.9")) == 1
    assert repo.count(AlertFilters(min_severity=Severity.MEDIUM)) == 1
    assert repo.count(AlertFilters(detection_type=DetectionType.BRUTE_FORCE)) == 0
    assert repo.count() == 2


def test_pagination(database) -> None:
    repo = AlertRepository(database)
    for _ in range(5):
        repo.add(_alert())
    assert len(repo.list(limit=2)) == 2
    assert len(repo.list(limit=2, offset=4)) == 1


def test_sql_injection_attempt_is_treated_as_data(database) -> None:
    """Filter values are bound parameters, never concatenated SQL."""
    repo = AlertRepository(database)
    repo.add(_alert())
    hostile = "10.0.0.5'; DROP TABLE alerts;--"
    assert repo.count(AlertFilters(source_ip=hostile)) == 0
    assert repo.count() == 1  # table intact


def test_severity_counts_and_top_sources(database) -> None:
    repo = AlertRepository(database)
    repo.add(_alert("10.0.0.5", Severity.HIGH))
    repo.add(_alert("10.0.0.5", Severity.LOW))
    counts = repo.severity_counts()
    assert counts["high"] == 1 and counts["low"] == 1 and counts["critical"] == 0
    assert repo.top_sources()[0] == {"source_ip": "10.0.0.5", "alerts": 2}


def test_retention_deletes_only_old_rows(database) -> None:
    repo = AlertRepository(database)
    repo.add(_alert())
    assert repo.delete_older_than(days=7) == 0  # the alert is new
    assert repo.delete_older_than(days=0) == 0  # 0 disables cleanup
    assert repo.count() == 1


def test_events_are_batched(database) -> None:
    repo = EventRepository(database)
    events = [
        SecurityEvent(
            timestamp=at(index),
            event_type=EventType.NETWORK_FLOW,
            source_ip="10.0.0.5",
            destination_ip="10.0.0.1",
            protocol=Protocol.TCP,
            packet_size=60,
        )
        for index in range(10)
    ]
    repo.add_many(events)
    repo.add_many([])  # empty batch is a no-op
    assert repo.count() == 10
    assert len(repo.recent(limit=3)) == 3


def test_traffic_metrics_are_returned_oldest_first(database) -> None:
    repo = MetricRepository(database)
    for index in range(3):
        repo.add(
            TrafficMetric(
                window_start=at(index * 5),
                window_end=at(index * 5 + 5),
                packets=index,
                bytes_total=index * 100,
                events=index,
                unique_sources=1,
            )
        )
    recent = repo.recent()
    assert [metric.packets for metric in recent] == [0, 1, 2]


def test_each_thread_gets_its_own_connection(database) -> None:
    """The concurrency contract: connections are never shared across threads."""
    seen: list[int] = []

    def worker() -> None:
        seen.append(id(database.connect()))
        database.close_current()

    main_connection = id(database.connect())
    threads = [threading.Thread(target=worker) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert all(connection_id != main_connection for connection_id in seen)


def test_writes_from_another_thread_are_visible(database) -> None:
    repo = AlertRepository(database)

    def worker() -> None:
        AlertRepository(database).add(_alert("10.0.0.77"))
        database.close_current()

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()
    assert repo.count(AlertFilters(source_ip="10.0.0.77")) == 1
