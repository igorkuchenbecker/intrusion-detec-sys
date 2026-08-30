"""Shared fixtures and event factories.

Rules are driven by event timestamps rather than the wall clock, so tests can
build an exact timeline and assert on it without sleeping.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ids.config.settings import IDSConfig
from ids.core.enums import EventType, Protocol
from ids.core.models import SecurityEvent
from ids.storage.database import Database

BASE_TIME = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def far_future() -> float:
    """An epoch far past the fixture timeline, for asserting that state expires.

    A bare large constant would not do: the fixture base time is in 2026, so a
    number like 1e9 is in the *past* and would expire nothing.
    """
    return at(10**6).timestamp()


def at(seconds: float) -> datetime:
    """Return a timestamp ``seconds`` after the fixed base time."""
    return BASE_TIME + timedelta(seconds=seconds)


def syn(
    source: str, port: int, *, offset: float = 0.0, target: str = "192.168.1.1"
) -> SecurityEvent:
    """Build a bare-SYN network event: a connection attempt."""
    return SecurityEvent(
        timestamp=at(offset),
        event_type=EventType.NETWORK_FLOW,
        source_ip=source,
        destination_ip=target,
        source_port=40000 + port,
        destination_port=port,
        protocol=Protocol.TCP,
        packet_size=60,
        tcp_flags="S",
    )


def established(source: str, port: int, *, offset: float = 0.0, size: int = 500) -> SecurityEvent:
    """Build an established-traffic event (SYN+ACK set), not an attempt."""
    return SecurityEvent(
        timestamp=at(offset),
        event_type=EventType.NETWORK_FLOW,
        source_ip=source,
        destination_ip="192.168.1.1",
        source_port=40000 + port,
        destination_port=port,
        protocol=Protocol.TCP,
        packet_size=size,
        tcp_flags="PA",
    )


def auth_failure(source: str, *, offset: float = 0.0, account: str = "root") -> SecurityEvent:
    """Build an authentication-failure host event."""
    return SecurityEvent(
        timestamp=at(offset),
        event_type=EventType.AUTH_FAILURE,
        source_ip=source,
        destination_port=22,
        identity=source,
        message=f"Failed password for {account} from {source} port 22 ssh2",
        attributes={"account": account, "service": "ssh"},
    )


@pytest.fixture()
def config() -> IDSConfig:
    """A configuration with small thresholds, so tests stay short."""
    return IDSConfig(
        port_scan_window=10.0,
        port_scan_threshold=5,
        port_scan_cooldown=60.0,
        traffic_window=5.0,
        traffic_baseline_windows=3,
        traffic_threshold_multiplier=3.0,
        traffic_min_packets=10,
        brute_force_window=60.0,
        brute_force_threshold=3,
        brute_force_cooldown=120.0,
        correlation_min_types=2,
        alert_dedup_window=30.0,
    )


@pytest.fixture()
def database(tmp_path) -> Database:
    """A file-backed database; files rather than :memory: so WAL is exercised."""
    db = Database(tmp_path / "test.db")
    db.initialize()
    yield db
    db.close_all()
