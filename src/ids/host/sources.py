"""Host event sources.

Host telemetry enters through this interface and leaves as
:class:`SecurityEvent`, exactly like network traffic does. That is what lets
the brute-force rule work identically whether failures come from an SSH log, a
Windows event log or an application -- and it is why host monitoring is not
tangled into the Scapy code path.

Log text is treated as untrusted input: it is written by whatever produced the
log, and an attacker who can influence a log line should not be able to forge
fields, inject control characters into our own logs, or hand us an unbounded
string.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path

from ..core.enums import EventType
from ..core.models import SecurityEvent
from ..observability.log import get_logger

__all__ = ["HostEventSource", "InMemoryHostEventSource", "AuthLogSource", "sanitize_log_text"]

#: Matches the OpenSSH failure lines emitted on Debian/Ubuntu and RHEL.
_SSH_FAILURE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<account>[^\s]+) "
    r"from (?P<ip>[0-9a-fA-F.:]+) port (?P<port>\d+)"
)
_SSH_SUCCESS = re.compile(
    r"Accepted (?:password|publickey) for (?P<account>[^\s]+) "
    r"from (?P<ip>[0-9a-fA-F.:]+) port (?P<port>\d+)"
)

_MAX_MESSAGE_LENGTH = 512
_MAX_LINES_PER_POLL = 2_000
# Every C0 control plus DEL. Newlines are included on purpose: they are the
# forged-record vector, so leaving them in would defeat the whole function.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def sanitize_log_text(text: str) -> str:
    """Strip control characters and cap length before a log line is stored.

    Without this, a crafted log line containing newlines and ANSI escapes could
    forge extra records in our own log output or in the dashboard.
    """
    return _CONTROL_CHARS.sub("", text).strip()[:_MAX_MESSAGE_LENGTH]


class HostEventSource(ABC):
    """A source of already-normalised host events."""

    name: str = ""

    @abstractmethod
    def poll(self) -> list[SecurityEvent]:
        """Return events observed since the last call. Must not block."""

    def close(self) -> None:  # noqa: B027 - optional hook, not every source holds resources
        """Release any resources held by the source."""


class InMemoryHostEventSource(HostEventSource):
    """A source fed programmatically; used by the simulator and the tests."""

    name = "memory"

    def __init__(self, events: list[SecurityEvent] | None = None) -> None:
        self._events = list(events or [])

    def push(self, event: SecurityEvent) -> None:
        """Queue an event for the next poll."""
        self._events.append(event)

    def poll(self) -> list[SecurityEvent]:
        """Return and clear the queued events."""
        events, self._events = self._events, []
        return events


class AuthLogSource(HostEventSource):
    """Tails an OpenSSH-style auth log and emits authentication events.

    Reads incrementally from a stored offset. If the file shrinks -- rotation,
    truncation -- the offset resets to the start rather than seeking past the
    end of the new file and going permanently blind.
    """

    name = "auth_log"

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._offset = 0
        self._log = get_logger("host.auth_log")

    def poll(self) -> list[SecurityEvent]:
        """Return events for lines appended since the previous poll."""
        try:
            size = self._path.stat().st_size
        except OSError:
            return []

        if size < self._offset:
            self._log.info("%s shrank; assuming rotation and rereading", self._path)
            self._offset = 0
        if size == self._offset:
            return []

        try:
            with self._path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(self._offset)
                lines = handle.readlines(_MAX_LINES_PER_POLL * _MAX_MESSAGE_LENGTH)
                self._offset = handle.tell()
        except OSError as exc:
            self._log.warning("cannot read %s: %s", self._path, exc)
            return []

        events = [self.parse_line(line) for line in lines[:_MAX_LINES_PER_POLL]]
        return [event for event in events if event is not None]

    @staticmethod
    def parse_line(line: str, *, now: datetime | None = None) -> SecurityEvent | None:
        """Parse one log line into an event, or ``None`` if it is not one.

        The line's own timestamp is not trusted for windowing: it lacks a year
        in the syslog format and is attacker-influenceable. Observation time is
        used instead, which is what the rules need anyway.
        """
        clean = sanitize_log_text(line)
        if not clean:
            return None

        observed = now or datetime.now(UTC)

        failure = _SSH_FAILURE.search(clean)
        if failure:
            return SecurityEvent(
                timestamp=observed,
                event_type=EventType.AUTH_FAILURE,
                source_ip=failure.group("ip"),
                destination_port=int(failure.group("port")),
                identity=failure.group("ip"),
                message=clean,
                attributes={"account": failure.group("account"), "service": "ssh"},
            )

        success = _SSH_SUCCESS.search(clean)
        if success:
            return SecurityEvent(
                timestamp=observed,
                event_type=EventType.AUTH_SUCCESS,
                source_ip=success.group("ip"),
                destination_port=int(success.group("port")),
                identity=success.group("ip"),
                message=clean,
                attributes={"account": success.group("account"), "service": "ssh"},
            )
        return None
