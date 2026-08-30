"""Tests for domain models, enums and the metrics registry."""

from __future__ import annotations

import threading

import pytest

from ids.core.enums import Confidence, DetectionType, EventType, Protocol, Severity
from ids.core.models import Alert, Detection, NetworkEvent, SecurityEvent, TrafficMetric, utc_now
from ids.observability.metrics import Metrics
from tests.conftest import at


def test_severity_is_ordered() -> None:
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.INFO.rank
    assert Severity.from_label("HIGH") is Severity.HIGH
    with pytest.raises(ValueError):
        Severity.from_label("apocalyptic")


def test_detection_type_titles_are_hedged() -> None:
    """Wording must reflect that a rule sees an indicator, not an attack."""
    titles = " ".join(member.title.lower() for member in DetectionType)
    assert "potential" in titles or "possible" in titles
    assert "attack detected" not in titles


def test_unknown_protocol_falls_back_to_other() -> None:
    assert Protocol.from_label("sctp") is Protocol.OTHER


def test_network_event_recognises_a_bare_syn() -> None:
    attempt = NetworkEvent(utc_now(), "10.0.0.5", "10.0.0.1", Protocol.TCP, 60, tcp_flags="S")
    reply = NetworkEvent(utc_now(), "10.0.0.5", "10.0.0.1", Protocol.TCP, 60, tcp_flags="SA")
    udp = NetworkEvent(utc_now(), "10.0.0.5", "10.0.0.1", Protocol.UDP, 60)
    assert attempt.is_tcp_syn and not reply.is_tcp_syn and not udp.is_tcp_syn


def test_normalisation_preserves_the_identifying_fields() -> None:
    network = NetworkEvent(at(0), "10.0.0.5", "10.0.0.1", Protocol.TCP, 60, 1234, 22, "S", "eth0")
    event = SecurityEvent.from_network_event(network)
    assert event.source_ip == "10.0.0.5"
    assert event.destination_port == 22
    assert event.attributes["interface"] == "eth0"
    assert event.actor == "10.0.0.5"


def test_host_identity_wins_over_address_as_actor() -> None:
    event = SecurityEvent(
        timestamp=at(0),
        event_type=EventType.AUTH_FAILURE,
        source_ip="10.0.0.5",
        identity="user:admin",
    )
    assert event.actor == "user:admin"


def test_alert_serialisation_is_explicit_and_complete() -> None:
    detection = Detection(
        rule="port_scan",
        detection_type=DetectionType.PORT_SCAN,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="d",
        evidence={"ports": [22]},
        mitigation="m",
        source_ip="10.0.0.5",
    )
    payload = Alert.from_detection(detection, occurrences=4).to_dict()
    assert payload["severity"] == "high"
    assert payload["title"] == DetectionType.PORT_SCAN.title
    assert payload["metadata"]["occurrences"] == 4


def test_dedup_key_ignores_timestamp() -> None:
    first = Detection(
        "r",
        DetectionType.PORT_SCAN,
        Severity.HIGH,
        Confidence.LOW,
        "d",
        {},
        "m",
        source_ip="10.0.0.5",
        timestamp=at(0),
    )
    second = Detection(
        "r",
        DetectionType.PORT_SCAN,
        Severity.HIGH,
        Confidence.LOW,
        "d",
        {},
        "m",
        source_ip="10.0.0.5",
        timestamp=at(500),
    )
    assert first.dedup_key() == second.dedup_key()


def test_traffic_metric_rates() -> None:
    metric = TrafficMetric(
        at(0), at(10), packets=100, bytes_total=5000, events=100, unique_sources=3
    )
    assert metric.packets_per_second == 10.0
    assert metric.bytes_per_second == 500.0
    assert metric.to_dict()["unique_sources"] == 3


def test_zero_length_window_does_not_divide_by_zero() -> None:
    metric = TrafficMetric(at(0), at(0), 5, 100, 5, 1)
    assert metric.packets_per_second == 0.0


def test_metrics_are_thread_safe() -> None:
    metrics = Metrics()

    def worker() -> None:
        for _ in range(1000):
            metrics.increment("packets_captured")

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert metrics.get("packets_captured") == 4000


def test_unknown_counter_is_rejected() -> None:
    with pytest.raises(KeyError):
        Metrics().increment("imaginary_counter")
