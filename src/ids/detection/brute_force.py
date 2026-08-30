"""Repeated authentication failure detection.

This rule detects, it does not attempt. It reads authentication *failures that
already happened*, normalised from host or application logs, and reports when
one identity or address accumulates too many within a window.

Keying on identity when available, and on address otherwise, is what lets it
see an attacker spraying one password across many accounts from one host.
"""

from __future__ import annotations

from ..core.enums import Confidence, DetectionType, EventType, Severity
from ..core.models import Detection, SecurityEvent
from .base import DetectionRule, register
from .state import CooldownGate, SlidingWindow

__all__ = ["BruteForceRule"]

#: MITRE ATT&CK T1110, Brute Force. Verified against the enterprise matrix.
_MITRE_TECHNIQUE = "T1110"

_MAX_EVIDENCE_ACCOUNTS = 10


@register
class BruteForceRule(DetectionRule):
    """Flags repeated authentication failures from one actor."""

    name = "brute_force"
    detection_type = DetectionType.BRUTE_FORCE

    def __init__(self, config) -> None:
        super().__init__(config)
        self._failures = SlidingWindow(config.brute_force_window, config.max_tracked_sources)
        self._cooldown = CooldownGate(config.brute_force_cooldown, config.max_tracked_sources)

    def evaluate(self, event: SecurityEvent) -> list[Detection]:
        """Count failures per actor and report once the threshold is crossed."""
        if event.event_type is not EventType.AUTH_FAILURE:
            return []
        actor = event.actor
        if actor is None:
            return []

        now = event.timestamp.timestamp()
        target = str(event.attributes.get("account") or event.identity or "unknown")
        self._failures.add(actor, target, now)

        attempts = self._failures.values(actor, now)
        if len(attempts) < self._config.brute_force_threshold:
            return []
        if not self._cooldown.allow(actor, now):
            return []

        return [self._build(event, actor, attempts)]

    def prune(self, now: float) -> None:
        """Expire tracked failures and cooldowns."""
        self._failures.prune(now)
        self._cooldown.prune(now)

    def state_size(self) -> int:
        """Return how many actors are currently tracked."""
        return len(self._failures)

    def _build(self, event: SecurityEvent, actor: str, attempts: list) -> Detection:
        accounts = sorted({str(account) for account in attempts})
        window = self._config.brute_force_window
        # Many failures against many accounts is spraying; against one account
        # it is guessing. Both matter, and the evidence should say which.
        spraying = len(accounts) > 1

        return Detection(
            rule=self.name,
            detection_type=self.detection_type,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM if spraying else Confidence.HIGH,
            description=(
                f"{actor} produced {len(attempts)} authentication failures within "
                f"{window:g}s across {len(accounts)} account(s). Consistent with "
                "credential guessing, though a misconfigured client or an expired "
                "saved password produces the same pattern."
            ),
            evidence={
                "failure_count": len(attempts),
                "window_seconds": window,
                "threshold": self._config.brute_force_threshold,
                "accounts": accounts[:_MAX_EVIDENCE_ACCOUNTS],
                "distinct_accounts": len(accounts),
                "pattern": "password_spraying" if spraying else "single_account",
            },
            mitigation=(
                "Confirm whether the source is a legitimate client with stale "
                "credentials. If not, apply rate limiting or lockout on the "
                "authentication endpoint and review whether any attempt succeeded."
            ),
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            destination_port=event.destination_port,
            timestamp=event.timestamp,
            mitre_technique=_MITRE_TECHNIQUE,
        )
