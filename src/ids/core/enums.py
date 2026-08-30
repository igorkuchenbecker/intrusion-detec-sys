"""Controlled vocabularies of the domain.

Every value that the system branches on lives in an enum rather than in a
string literal: a typo in ``"HIGH"`` should be an ``AttributeError`` at import
time, not a detection that silently never fires.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["Severity", "Confidence", "Protocol", "DetectionType", "EventType"]


class Severity(Enum):
    """How much impact the observed behaviour would have if it is real.

    ``rank`` exists so alerts can be sorted, filtered and summarised without
    mapping labels back to an order at every call site.
    """

    INFO = ("info", 0)
    LOW = ("low", 1)
    MEDIUM = ("medium", 2)
    HIGH = ("high", 3)
    CRITICAL = ("critical", 4)

    def __init__(self, label: str, rank: int) -> None:
        self.label = label
        self.rank = rank

    def __str__(self) -> str:
        return self.label

    @classmethod
    def from_label(cls, label: str) -> Severity:
        """Return the severity matching ``label``, case-insensitively."""
        wanted = label.strip().lower()
        for member in cls:
            if member.label == wanted:
                return member
        raise ValueError(f"unknown severity: {label!r}")


class Confidence(Enum):
    """How strongly the evidence supports the detection.

    Deliberately separate from :class:`Severity`. "How bad would this be" and
    "how sure am I that it happened" are different questions, and collapsing
    them is how heuristic tools end up crying wolf.
    """

    LOW = ("low", 0)
    MEDIUM = ("medium", 1)
    HIGH = ("high", 2)

    def __init__(self, label: str, rank: int) -> None:
        self.label = label
        self.rank = rank

    def __str__(self) -> str:
        return self.label

    @classmethod
    def from_label(cls, label: str) -> Confidence:
        """Return the confidence matching ``label``, case-insensitively."""
        wanted = label.strip().lower()
        for member in cls:
            if member.label == wanted:
                return member
        raise ValueError(f"unknown confidence: {label!r}")


class Protocol(Enum):
    """Transport protocols the parser recognises."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"

    def __str__(self) -> str:
        return self.value

    @classmethod
    def from_label(cls, label: str) -> Protocol:
        """Return the protocol matching ``label``, falling back to OTHER."""
        wanted = label.strip().lower()
        for member in cls:
            if member.value == wanted:
                return member
        return cls.OTHER


class DetectionType(Enum):
    """The kinds of behaviour this system knows how to flag.

    Names are deliberately hedged ("potential", "possible"): a rule observes an
    indicator, it does not witness an attack.
    """

    PORT_SCAN = ("port_scan", "Potential Port Scan")
    TRAFFIC_VOLUME_ANOMALY = ("traffic_volume_anomaly", "Traffic Volume Anomaly")
    BRUTE_FORCE = ("brute_force", "Possible Brute-Force Activity")
    CORRELATED_ACTIVITY = ("correlated_activity", "Correlated Suspicious Activity")

    def __init__(self, code: str, title: str) -> None:
        self.code = code
        self.title = title

    def __str__(self) -> str:
        return self.code

    @classmethod
    def from_code(cls, code: str) -> DetectionType:
        """Return the detection type matching ``code``."""
        wanted = code.strip().lower()
        for member in cls:
            if member.code == wanted:
                return member
        raise ValueError(f"unknown detection type: {code!r}")


class EventType(Enum):
    """The normalised event shapes that detection rules consume.

    Network packets and host log lines both end up here, which is what lets a
    rule be written once against a single vocabulary.
    """

    NETWORK_FLOW = "network_flow"
    AUTH_FAILURE = "authentication_failure"
    AUTH_SUCCESS = "authentication_success"
    HOST_LOG = "host_log"

    def __str__(self) -> str:
        return self.value
