"""Passive port-scan detection.

The signal is one source address reaching for many distinct destination ports
in a short window, using bare SYNs -- the shape of a connection *attempt*
rather than an established conversation.

Nothing is sent. The rule only counts what the capture already saw, which is
why it is safe to run on a production span port.
"""

from __future__ import annotations

from ..core.enums import Confidence, DetectionType, EventType, Severity
from ..core.models import Detection, SecurityEvent
from .base import DetectionRule, register
from .state import CooldownGate, SlidingWindow

__all__ = ["PortScanRule"]

#: MITRE ATT&CK T1046, Network Service Discovery. Verified against the
#: enterprise matrix; rules without a technique I am sure of stay unmapped.
_MITRE_TECHNIQUE = "T1046"

#: Ports listed as evidence. A 1000-port scan should not write a 1000-element
#: array into the database on every alert.
_MAX_EVIDENCE_PORTS = 25

#: Multiple of the threshold above which the finding is rated HIGH and allowed
#: one extra alert. Without a separate cooldown key this branch would be
#: unreachable: the rule fires the moment breadth crosses the threshold, and
#: the cooldown would then suppress every later, larger observation.
_ESCALATION_FACTOR = 3


@register
class PortScanRule(DetectionRule):
    """Flags a source touching many distinct ports within the window."""

    name = "port_scan"
    detection_type = DetectionType.PORT_SCAN

    def __init__(self, config) -> None:
        super().__init__(config)
        self._ports = SlidingWindow(config.port_scan_window, config.max_tracked_sources)
        self._targets = SlidingWindow(config.port_scan_window, config.max_tracked_sources)
        self._cooldown = CooldownGate(config.port_scan_cooldown, config.max_tracked_sources)

    def evaluate(self, event: SecurityEvent) -> list[Detection]:
        """Count SYNs per source and report once the port count crosses."""
        if event.event_type is not EventType.NETWORK_FLOW:
            return []
        if not self._is_connection_attempt(event):
            return []
        source = event.source_ip
        if source is None or event.destination_port is None:
            return []

        now = event.timestamp.timestamp()
        self._ports.add(source, event.destination_port, now)
        if event.destination_ip:
            self._targets.add(source, event.destination_ip, now)

        ports = self._ports.unique(source, now)
        if len(ports) < self._config.port_scan_threshold:
            return []

        # A scan that turns out to be far broader than the threshold earns one
        # further alert, under its own cooldown key. At most two per source per
        # cooldown: enough to show the escalation, not enough to flood.
        escalated = len(ports) >= self._config.port_scan_threshold * _ESCALATION_FACTOR
        if not self._cooldown.allow(f"{source}:large" if escalated else source, now):
            return []

        return [self._build(event, sorted(ports), self._targets.unique(source, now), escalated)]

    def prune(self, now: float) -> None:
        """Expire tracked ports, targets and cooldowns."""
        self._ports.prune(now)
        self._targets.prune(now)
        self._cooldown.prune(now)

    def state_size(self) -> int:
        """Return how many source addresses are currently tracked."""
        return len(self._ports)

    @staticmethod
    def _is_connection_attempt(event: SecurityEvent) -> bool:
        """Return whether this is a SYN without ACK: a connection attempt.

        Filtering on this is what keeps a busy web server, which legitimately
        talks on many ephemeral ports, from looking like a scanner.
        """
        return "S" in event.tcp_flags and "A" not in event.tcp_flags

    def _build(
        self, event: SecurityEvent, ports: list[int], targets: set, escalated: bool
    ) -> Detection:
        threshold = self._config.port_scan_threshold
        window = self._config.port_scan_window

        return Detection(
            rule=self.name,
            detection_type=self.detection_type,
            severity=Severity.HIGH if escalated else Severity.MEDIUM,
            confidence=Confidence.HIGH if escalated else Confidence.MEDIUM,
            description=(
                f"{event.source_ip} sent connection attempts to {len(ports)} distinct "
                f"ports within {window:g}s (threshold {threshold}). This is consistent "
                "with port scanning, but a vulnerability scanner or monitoring probe "
                "produces the same pattern."
            ),
            evidence={
                "unique_ports": len(ports),
                "ports_sample": ports[:_MAX_EVIDENCE_PORTS],
                "ports_truncated": len(ports) > _MAX_EVIDENCE_PORTS,
                "targets": sorted(str(target) for target in targets)[:10],
                "window_seconds": window,
                "threshold": threshold,
            },
            mitigation=(
                "Confirm whether the source is an authorised scanner or monitoring "
                "system. If not, restrict its network access and review what the "
                "probed services expose."
            ),
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            destination_port=event.destination_port,
            timestamp=event.timestamp,
            mitre_technique=_MITRE_TECHNIQUE,
        )
