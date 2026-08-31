"""Tests for the console session's alert buffer and lifecycle.

The console is a second consumer of the same bus the dashboard uses, so the
properties worth asserting are the ones that would let it misreport or
misbehave as a subscriber: that it records what is published, that its buffer
is bounded and says so, and that stopping it leaves no thread running.
"""

from __future__ import annotations

import pytest

from ids.config.settings import IDSConfig
from ids.core.engine import IDSEngine
from ids.core.enums import Severity
from ids.tui.session import ConsoleSession, ConsoleState


def _alert(severity: str = "medium", **overrides) -> dict:
    payload = {
        "id": "abc",
        "severity": severity,
        "confidence": "medium",
        "detection_type": "port_scan",
        "title": "Potential Port Scan",
        "description": "connection attempts to many ports",
        "source_ip": "10.0.0.1",
        "evidence": {"unique_ports": 15},
        "mitigation": "review the source",
    }
    payload.update(overrides)
    return payload


@pytest.fixture()
def session(tmp_path, config: IDSConfig):
    """A console over a real engine with a temporary database, capture off."""
    engine = IDSEngine(config.with_overrides(database_path=str(tmp_path / "console.db")))
    console = ConsoleSession(config, engine=engine, alert_limit=5)
    yield console
    console.stop()


def test_starts_stopped_and_empty(session: ConsoleSession) -> None:
    assert session.state is ConsoleState.STOPPED
    assert session.rows == []
    assert session.threat_level() is None
    assert session.uptime_seconds == 0.0


def test_published_alerts_reach_the_console(session: ConsoleSession) -> None:
    assert session.start(capture=False) is True
    assert session.state is ConsoleState.MONITORING

    session.engine.bus.publish({"type": "alert", "alert": _alert()})
    _wait_for(session, 1)

    rows = session.rows
    assert len(rows) == 1
    assert rows[0].severity is Severity.MEDIUM
    assert rows[0].title == "Potential Port Scan"
    assert rows[0].source_ip == "10.0.0.1"


def test_non_alert_messages_are_ignored(session: ConsoleSession) -> None:
    session.start(capture=False)

    session.engine.bus.publish({"type": "heartbeat"})
    session.engine.bus.publish({"type": "alert", "alert": _alert()})
    _wait_for(session, 1)

    assert len(session.rows) == 1


def test_drain_hands_over_each_alert_once(session: ConsoleSession) -> None:
    session.start(capture=False)
    session.engine.bus.publish({"type": "alert", "alert": _alert()})
    _wait_for(session, 1)

    assert len(session.drain().rows) == 1
    assert not session.drain()


def test_the_buffer_stops_recording_at_its_limit_and_counts_the_rest(
    session: ConsoleSession,
) -> None:
    """The database keeps every alert; the console must not imply otherwise."""
    session.start(capture=False)
    for _ in range(8):
        session.engine.bus.publish({"type": "alert", "alert": _alert()})
    _wait_for(session, 5)

    assert len(session.rows) == 5
    assert session.not_recorded >= 1
    assert [row.seq for row in session.rows] == [1, 2, 3, 4, 5]


def test_threat_level_is_the_highest_severity_present(session: ConsoleSession) -> None:
    session.start(capture=False)
    for severity in ("low", "high", "info"):
        session.engine.bus.publish({"type": "alert", "alert": _alert(severity)})
    _wait_for(session, 3)

    assert session.threat_level() is Severity.HIGH
    counts = session.severity_counts()
    assert counts[Severity.HIGH] == 1
    assert counts[Severity.LOW] == 1
    assert counts[Severity.CRITICAL] == 0


def test_threat_level_is_nominal_with_no_alerts(session: ConsoleSession) -> None:
    """Nominal means nothing fired, which is not the same as nothing happened."""
    session.start(capture=False)
    assert session.threat_level() is None


def test_stopping_ends_the_reader_thread(session: ConsoleSession) -> None:
    session.start(capture=False)
    reader = session._reader
    assert reader is not None and reader.is_alive()

    session.stop()

    reader.join(timeout=5.0)
    assert not reader.is_alive()
    assert session.state is ConsoleState.STOPPED


def test_row_lookup_misses_return_none(session: ConsoleSession) -> None:
    assert session.row(99) is None


def test_metrics_and_health_come_from_the_engine(session: ConsoleSession) -> None:
    session.start(capture=False)

    snapshot = session.metrics()
    assert "counters" in snapshot and "gauges" in snapshot
    assert snapshot["gauges"]["queue_capacity"] > 0

    health = session.health()
    assert health["capture"] == "disabled"
    # A superset, not an equality: correlation is a separate stage that also
    # holds state, so it appears in the sizes without being a rule.
    sizes = set(health["detectors"]["state_sizes"])
    assert {rule.name for rule in session.engine.detection.rules} <= sizes
    assert session.engine.detection.correlation.name in sizes


def _wait_for(session: ConsoleSession, count: int, timeout: float = 5.0) -> None:
    """Block until the reader thread has recorded ``count`` alerts."""
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if len(session.rows) >= count:
            return
        time.sleep(0.01)
    raise AssertionError(f"only {len(session.rows)} of {count} alerts arrived")
