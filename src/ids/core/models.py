"""Typed domain models.

Plain frozen ``dataclasses`` are used instead of a validation framework: every
value is produced internally (by the parser, the rules or the database layer)
and validated at the boundary where it enters, so a runtime validator would add
a dependency without removing a real risk.

The models form a deliberate chain, and each step throws information away:

``NetworkEvent`` (what the wire showed) -> ``SecurityEvent`` (what the rules
read) -> ``Detection`` (what a rule concluded) -> ``Alert`` (what a human sees).
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .enums import Confidence, DetectionType, EventType, Protocol, Severity

__all__ = [
    "NetworkEvent",
    "SecurityEvent",
    "Detection",
    "Alert",
    "TrafficMetric",
    "utc_now",
]


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class NetworkEvent:
    """One packet, reduced to the metadata the system actually uses.

    Payload bytes are intentionally absent: this system reasons about who
    talked to whom, how often and with which flags. Keeping payloads would
    expand both the privacy surface and the memory footprint for no gain to any
    current rule.
    """

    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: Protocol
    packet_size: int
    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags: str = ""
    interface: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def is_tcp_syn(self) -> bool:
        """Whether this is a bare SYN: a connection attempt, not a reply.

        The SYN-without-ACK shape is what makes a connection attempt visible to
        a passive observer, and it is the primitive the port-scan rule counts.
        """
        return self.protocol is Protocol.TCP and "S" in self.tcp_flags and "A" not in self.tcp_flags


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """A normalised event, whatever its origin.

    Network packets and host log lines both arrive here. Rules are written
    against this type only, which is what keeps the brute-force rule from
    knowing that Scapy exists.
    """

    timestamp: datetime
    event_type: EventType
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: Protocol | None = None
    packet_size: int = 0
    tcp_flags: str = ""
    identity: str | None = None
    message: str = ""
    attributes: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_network_event(cls, event: NetworkEvent) -> SecurityEvent:
        """Normalise a :class:`NetworkEvent` into a :class:`SecurityEvent`."""
        return cls(
            timestamp=event.timestamp,
            event_type=EventType.NETWORK_FLOW,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            source_port=event.source_port,
            destination_port=event.destination_port,
            protocol=event.protocol,
            packet_size=event.packet_size,
            tcp_flags=event.tcp_flags,
            attributes={"interface": event.interface, **dict(event.metadata)},
        )

    @property
    def actor(self) -> str | None:
        """The best available identifier of who caused the event.

        Host events may name a user; network events only have an address.
        """
        return self.identity or self.source_ip


@dataclass(frozen=True, slots=True)
class Detection:
    """What a single rule concluded from a window of events.

    A detection is not yet an alert: the :class:`~ids.alerting.manager.AlertManager`
    still applies deduplication and cooldown before anything is persisted.
    """

    rule: str
    detection_type: DetectionType
    severity: Severity
    confidence: Confidence
    description: str
    evidence: Mapping[str, Any]
    mitigation: str
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    timestamp: datetime = field(default_factory=utc_now)
    mitre_technique: str | None = None

    def dedup_key(self) -> tuple[str, str, str]:
        """Identity used to collapse repeats of the same finding."""
        return (self.detection_type.code, self.source_ip or "-", self.destination_ip or "-")


@dataclass(frozen=True, slots=True)
class Alert:
    """A persisted, human-facing security alert."""

    id: str
    timestamp: datetime
    detection_type: DetectionType
    severity: Severity
    confidence: Confidence
    description: str
    evidence: Mapping[str, Any]
    mitigation: str
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    rule: str = ""
    mitre_technique: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_detection(cls, detection: Detection, *, occurrences: int = 1) -> Alert:
        """Promote a :class:`Detection` into an :class:`Alert`."""
        return cls(
            id=uuid.uuid4().hex,
            timestamp=detection.timestamp,
            detection_type=detection.detection_type,
            severity=detection.severity,
            confidence=detection.confidence,
            description=detection.description,
            evidence=dict(detection.evidence),
            mitigation=detection.mitigation,
            source_ip=detection.source_ip,
            destination_ip=detection.destination_ip,
            source_port=detection.source_port,
            destination_port=detection.destination_port,
            rule=detection.rule,
            mitre_technique=detection.mitre_technique,
            metadata={"occurrences": occurrences},
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the API. Explicit, so no field leaks by accident."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "detection_type": self.detection_type.code,
            "title": self.detection_type.title,
            "severity": self.severity.label,
            "confidence": self.confidence.label,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "description": self.description,
            "evidence": dict(self.evidence),
            "mitigation": self.mitigation,
            "rule": self.rule,
            "mitre_technique": self.mitre_technique,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class TrafficMetric:
    """Aggregated traffic figures for one closed time window."""

    window_start: datetime
    window_end: datetime
    packets: int
    bytes_total: int
    events: int
    unique_sources: int

    @property
    def duration_seconds(self) -> float:
        """Length of the window in seconds."""
        return (self.window_end - self.window_start).total_seconds()

    @property
    def packets_per_second(self) -> float:
        """Average packet rate over the window."""
        duration = self.duration_seconds
        return self.packets / duration if duration > 0 else 0.0

    @property
    def bytes_per_second(self) -> float:
        """Average byte rate over the window."""
        duration = self.duration_seconds
        return self.bytes_total / duration if duration > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the API."""
        return {
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "packets": self.packets,
            "bytes": self.bytes_total,
            "events": self.events,
            "unique_sources": self.unique_sources,
            "packets_per_second": round(self.packets_per_second, 3),
            "bytes_per_second": round(self.bytes_per_second, 3),
        }
