"""Synthetic traffic generation.

The whole system can be demonstrated and tested without a network interface,
without privileges and without any external host. Packets are crafted in
memory with Scapy and pushed through the same queue the real sniffer feeds, so
what runs here is the actual pipeline -- parser included -- not a mock of it.

Nothing is transmitted. These packets never reach a socket.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from typing import Any

from ..core.enums import EventType
from ..core.models import SecurityEvent

__all__ = ["TrafficSimulator", "SCENARIOS"]

SCENARIOS = ("normal", "port_scan", "traffic_burst", "brute_force", "correlated", "all")

_COMMON_PORTS = (80, 443, 53, 22, 123, 8080)
_SCAN_PORTS = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1723,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
    9200,
    27017,
)


class TrafficSimulator:
    """Builds benign and suspicious traffic for demos and tests."""

    def __init__(self, seed: int | None = 1337) -> None:
        # Seeded by default: a demo that produces different alerts on every run
        # is not a demo, it is a coin toss.
        self._random = random.Random(seed)

    # -- packet builders -----------------------------------------------------

    def normal_traffic(self, count: int = 40, *, start: datetime | None = None) -> list[Any]:
        """Ordinary established conversations between a few hosts."""
        from scapy.layers.inet import IP, TCP

        base = start or _now()
        packets = []
        for index in range(count):
            source = f"192.168.1.{self._random.randint(10, 40)}"
            packet = IP(src=source, dst="192.168.1.1") / TCP(
                sport=self._random.randint(20000, 60000),
                dport=self._random.choice(_COMMON_PORTS),
                flags="PA",  # established traffic, not connection attempts
            )
            packet.time = (base + timedelta(milliseconds=index * 50)).timestamp()
            packets.append(packet)
        return packets

    def port_scan(
        self,
        source: str = "10.0.0.66",
        target: str = "192.168.1.1",
        *,
        ports: tuple[int, ...] = _SCAN_PORTS,
        start: datetime | None = None,
    ) -> list[Any]:
        """One source sending bare SYNs across many ports."""
        from scapy.layers.inet import IP, TCP

        base = start or _now()
        packets = []
        for index, port in enumerate(ports):
            packet = IP(src=source, dst=target) / TCP(
                sport=self._random.randint(20000, 60000), dport=port, flags="S"
            )
            packet.time = (base + timedelta(milliseconds=index * 20)).timestamp()
            packets.append(packet)
        return packets

    def traffic_burst(
        self,
        source: str = "10.0.0.77",
        target: str = "192.168.1.1",
        *,
        count: int = 900,
        duration_seconds: float = 10.0,
        start: datetime | None = None,
    ) -> list[Any]:
        """Build a volume spike spread over more than one detection window.

        The spread matters: a burst shorter than one window would leave that
        window open until unrelated traffic arrived, so the spike would be
        evaluated late or not at all.
        """
        from scapy.layers.inet import IP, TCP

        base = start or _now()
        packets = []
        step = duration_seconds / max(count, 1)
        for index in range(count):
            packet = IP(src=source, dst=target) / TCP(
                sport=self._random.randint(20000, 60000), dport=443, flags="PA"
            )
            packet.time = (base + timedelta(seconds=index * step)).timestamp()
            packets.append(packet)
        return packets

    def baseline_traffic(
        self,
        *,
        windows: int,
        window_seconds: float,
        packets_per_window: int = 20,
        start: datetime | None = None,
    ) -> list[Any]:
        """Steady traffic spread evenly across whole windows.

        The traffic rule needs a full baseline before it will judge anything;
        this builds one.
        """
        from scapy.layers.inet import IP, TCP

        base = start or _now()
        packets = []
        for window in range(windows):
            for index in range(packets_per_window):
                offset = window * window_seconds + (
                    index * window_seconds / max(packets_per_window, 1)
                )
                packet = IP(src="192.168.1.20", dst="192.168.1.1") / TCP(
                    sport=30000 + index, dport=443, flags="PA"
                )
                packet.time = (base + timedelta(seconds=offset)).timestamp()
                packets.append(packet)
        return packets

    # -- host events ---------------------------------------------------------

    def brute_force_events(
        self,
        source: str = "10.0.0.88",
        *,
        count: int = 8,
        account: str = "admin",
        start: datetime | None = None,
    ) -> list[SecurityEvent]:
        """Repeated authentication failures from one address."""
        base = start or _now()
        return [
            SecurityEvent(
                timestamp=base + timedelta(seconds=index * 2),
                event_type=EventType.AUTH_FAILURE,
                source_ip=source,
                destination_port=22,
                identity=source,
                message=f"Failed password for {account} from {source} port 22 ssh2",
                attributes={"account": account, "service": "ssh"},
            )
            for index in range(count)
        ]

    # -- scenarios -----------------------------------------------------------

    def feed(self, engine: Any, scenario: str) -> dict[str, int]:
        """Push a scenario through ``engine``; return what was submitted."""
        if scenario not in SCENARIOS:
            raise ValueError(f"unknown scenario: {scenario!r}; choose from {SCENARIOS}")

        packets: list[Any] = []
        events: list[SecurityEvent] = []
        window = engine.config.traffic_window
        baseline_windows = engine.config.traffic_baseline_windows

        # Everything is anchored in the *past*, ending about now. Real captures
        # carry past timestamps, and generating future ones would leave the
        # final window waiting for a wall clock that has not got there yet.
        burst_seconds = window * 2
        baseline_seconds = (baseline_windows + 1) * window
        origin = _now() - timedelta(seconds=baseline_seconds + burst_seconds)

        if scenario in ("normal", "all"):
            packets += self.normal_traffic(start=origin)
        if scenario in ("port_scan", "all"):
            packets += self.port_scan(start=origin)
        if scenario in ("traffic_burst", "all"):
            packets += self.baseline_traffic(
                windows=baseline_windows + 1, window_seconds=window, start=origin
            )
            packets += self.traffic_burst(
                duration_seconds=burst_seconds,
                start=origin + timedelta(seconds=baseline_seconds),
            )
        if scenario in ("brute_force", "all"):
            events += self.brute_force_events(start=origin)
        if scenario in ("correlated", "all"):
            # One source doing two different things: this is what the
            # correlation layer exists to join into a single storyline.
            noisy = "10.0.0.99"
            packets += self.port_scan(source=noisy, start=origin)
            events += self.brute_force_events(source=noisy, start=origin)

        for packet in packets:
            engine.submit_packet(packet)
        for event in events:
            engine.submit_event(event)
        return {"packets": len(packets), "host_events": len(events)}


def _now() -> datetime:
    return datetime.now(UTC)
