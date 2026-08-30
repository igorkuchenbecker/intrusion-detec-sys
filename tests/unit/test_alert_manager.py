"""Tests for alert deduplication, persistence and publication."""

from __future__ import annotations

from ids.alerting.manager import AlertManager
from ids.core.enums import Confidence, DetectionType, Severity
from ids.core.events import EventBus
from ids.core.models import Detection
from ids.observability.metrics import Metrics
from ids.storage.repositories import AlertRepository
from tests.conftest import at


def _detection(source: str = "10.0.0.5", offset: float = 0.0) -> Detection:
    return Detection(
        rule="port_scan",
        detection_type=DetectionType.PORT_SCAN,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description="desc",
        evidence={},
        mitigation="mitigate",
        source_ip=source,
        timestamp=at(offset),
    )


def _manager(config, database, bus=None):
    return AlertManager(config, AlertRepository(database), Metrics(), bus)


def test_detection_becomes_a_persisted_alert(config, database) -> None:
    manager = _manager(config, database)
    alerts = manager.handle([_detection()])
    assert len(alerts) == 1
    assert AlertRepository(database).count() == 1


def test_duplicates_are_folded_not_repeated(config, database) -> None:
    manager = _manager(config, database)
    manager.handle([_detection(offset=0)])
    suppressed = manager.handle([_detection(offset=index) for index in range(1, 5)])
    assert suppressed == []
    assert AlertRepository(database).count() == 1


def test_occurrences_are_counted_across_the_dedup_window(config, database) -> None:
    manager = _manager(config, database)
    manager.handle([_detection(offset=0)])
    manager.handle([_detection(offset=index) for index in range(1, 4)])
    # After the window, the next alert reports how many were folded in.
    alerts = manager.handle([_detection(offset=config.alert_dedup_window + 1)])
    assert alerts[0].metadata["occurrences"] > 1


def test_different_sources_are_not_deduplicated(config, database) -> None:
    manager = _manager(config, database)
    alerts = manager.handle([_detection("10.0.0.5"), _detection("10.0.0.9")])
    assert len(alerts) == 2


def test_alerts_are_published_to_subscribers(config, database) -> None:
    bus = EventBus()
    subscription = bus.subscribe()
    _manager(config, database, bus).handle([_detection()])

    message = bus.take(subscription.mailbox)
    assert message is not None
    assert message["type"] == "alert"
    assert message["alert"]["source_ip"] == "10.0.0.5"


def test_storage_failure_does_not_stop_alerting(config, database) -> None:
    """Losing the database must not blind the live stream."""
    from ids.core.exceptions import StorageError

    class BrokenRepository(AlertRepository):
        def add(self, alert):
            raise StorageError("disk on fire")

    metrics = Metrics()
    bus = EventBus()
    subscription = bus.subscribe()
    manager = AlertManager(config, BrokenRepository(database), metrics, bus)

    alerts = manager.handle([_detection()])
    assert len(alerts) == 1  # still raised
    assert metrics.get("storage_errors") == 1
    assert bus.take(subscription.mailbox) is not None
