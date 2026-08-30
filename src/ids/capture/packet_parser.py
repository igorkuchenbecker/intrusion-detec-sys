"""Scapy packet -> :class:`NetworkEvent`.

This is the only module in the project that understands Scapy. Everything
downstream sees plain dataclasses, which is what allows the detection rules and
their tests to run with no capture, no privileges and no network.

Only ``scapy.layers`` is imported, never ``scapy.all``: the latter pulls in the
whole library (including sending primitives this project has no business
touching) and costs seconds of import time.
"""

from __future__ import annotations

from datetime import UTC, datetime

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from ..core.enums import Protocol
from ..core.models import NetworkEvent

__all__ = ["PacketParser"]

_MAX_FLAG_LENGTH = 16


class PacketParser:
    """Extracts the metadata the pipeline needs from a captured packet."""

    def __init__(self, interface: str = "") -> None:
        self._interface = interface

    def parse(self, packet: Packet) -> NetworkEvent | None:
        """Return a :class:`NetworkEvent`, or ``None`` if not IP traffic.

        Non-IP frames (ARP, raw link-layer chatter) are dropped here rather
        than propagated as half-populated events: every rule in this system
        reasons about addresses, so an event without them is noise.
        """
        source_ip, destination_ip = self._addresses(packet)
        if source_ip is None or destination_ip is None:
            return None

        protocol, source_port, destination_port, flags = self._transport(packet)

        return NetworkEvent(
            timestamp=self._timestamp(packet),
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            packet_size=len(packet),
            source_port=source_port,
            destination_port=destination_port,
            tcp_flags=flags,
            interface=self._interface,
        )

    @staticmethod
    def _addresses(packet: Packet) -> tuple[str | None, str | None]:
        if packet.haslayer(IP):
            layer = packet[IP]
            return str(layer.src), str(layer.dst)
        if packet.haslayer(IPv6):
            layer = packet[IPv6]
            return str(layer.src), str(layer.dst)
        return None, None

    @staticmethod
    def _transport(packet: Packet) -> tuple[Protocol, int | None, int | None, str]:
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            # str(flags) yields the conventional letter form ("S", "SA", ...).
            # It is truncated defensively: it comes from the wire.
            flags = str(tcp.flags)[:_MAX_FLAG_LENGTH]
            return Protocol.TCP, int(tcp.sport), int(tcp.dport), flags
        if packet.haslayer(UDP):
            udp = packet[UDP]
            return Protocol.UDP, int(udp.sport), int(udp.dport), ""
        if packet.haslayer(ICMP):
            return Protocol.ICMP, None, None, ""
        return Protocol.OTHER, None, None, ""

    @staticmethod
    def _timestamp(packet: Packet) -> datetime:
        """Prefer the capture timestamp; fall back to now if absent."""
        raw = getattr(packet, "time", None)
        if raw is None:
            return datetime.now(UTC)
        try:
            return datetime.fromtimestamp(float(raw), tz=UTC)
        except (OverflowError, OSError, ValueError):
            return datetime.now(UTC)
