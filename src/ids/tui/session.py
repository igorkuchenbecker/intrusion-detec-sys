"""Engine lifecycle and the alert stream, for one console run.

The console is a **second consumer of the same event bus the web dashboard
uses**, not a reimplementation of it. That matters for one specific reason:
the bus fans out to bounded per-subscriber mailboxes, so a console that falls
behind drops its own messages and counts them. It cannot starve the dashboard,
and it cannot grow a queue until the process dies.

Everything the console shows comes from the running engine — the bus for live
alerts, the metrics for pipeline health, the repositories for history. Nothing
here re-derives a verdict; if the console and the dashboard ever disagree, it
is a rendering bug, not two opinions.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from ..capture.simulator import TrafficSimulator
from ..config.settings import IDSConfig
from ..core.engine import IDSEngine
from ..core.enums import Severity
from ..core.events import Subscription
from ..core.exceptions import CaptureError, IDSError
from ..core.models import TrafficMetric
from ..host.sources import AuthLogSource
from ..observability.log import get_logger

__all__ = [
    "ConsoleState",
    "AlertRow",
    "DrainedAlerts",
    "ConsoleSession",
    "DEFAULT_ALERT_LIMIT",
]

#: How many alerts the console keeps on screen. The database keeps every one;
#: this is the working set a person can actually scroll.
DEFAULT_ALERT_LIMIT = 1_000

#: How long the bus reader waits before checking whether it should stop.
#: Short enough that quitting is immediate, long enough that an idle console
#: is not a spin loop.
_LISTEN_TIMEOUT = 1.0

_log = get_logger("tui")


class ConsoleState(Enum):
    """What the console's engine is doing."""

    STOPPED = "stopped"
    MONITORING = "monitoring"
    FAILED = "failed"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class AlertRow:
    """One alert as the console holds it.

    The payload is the same dictionary the API and the dashboard receive, so
    there is exactly one serialisation of an alert in this system and the two
    front ends cannot describe the same finding differently.
    """

    seq: int
    received_at: datetime
    payload: dict[str, Any]

    @property
    def severity(self) -> Severity:
        """The alert's severity, parsed back from its label."""
        return Severity.from_label(str(self.payload.get("severity", "info")))

    @property
    def title(self) -> str:
        """The human-facing name of what fired."""
        return str(self.payload.get("title", self.payload.get("detection_type", "unknown")))

    @property
    def source_ip(self) -> str:
        """The alert's source address, or a dash."""
        return str(self.payload.get("source_ip") or "-")


@dataclass(slots=True)
class DrainedAlerts:
    """What the UI picked up on one drain."""

    rows: list[AlertRow] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.rows)


class ConsoleSession:
    """Owns the engine, the bus subscription and the alert buffer."""

    def __init__(
        self,
        config: IDSConfig,
        *,
        engine: IDSEngine | None = None,
        alert_limit: int = DEFAULT_ALERT_LIMIT,
        simulator: TrafficSimulator | None = None,
    ) -> None:
        self.config = config
        self._alert_limit = alert_limit
        self._simulator = simulator or TrafficSimulator()
        # Injectable so tests can drive a console without constructing a
        # database on disk; the default is the engine the CLI builds.
        self._engine = engine or IDSEngine(config)

        self._lock = threading.Lock()
        self._state = ConsoleState.STOPPED
        self._failure: str | None = None
        self._started_at: datetime | None = None
        self._capture_requested = False

        self._rows: list[AlertRow] = []
        self._by_seq: dict[int, AlertRow] = {}
        self._pending: list[AlertRow] = []
        self._seq = 0
        self._not_recorded = 0

        self._subscription: Subscription | None = None
        self._reader: threading.Thread | None = None
        self._stop = threading.Event()

    # ------------------------------------------------------------------
    # Reading state
    # ------------------------------------------------------------------

    @property
    def engine(self) -> IDSEngine:
        """The running engine."""
        return self._engine

    @property
    def state(self) -> ConsoleState:
        """Whether the engine is monitoring."""
        with self._lock:
            return self._state

    @property
    def failure(self) -> str | None:
        """Why the engine could not start, if it could not."""
        with self._lock:
            return self._failure

    @property
    def capturing(self) -> bool:
        """Whether packet capture was requested and started."""
        with self._lock:
            return self._capture_requested and self._state is ConsoleState.MONITORING

    @property
    def rows(self) -> list[AlertRow]:
        """Every recorded alert, oldest first."""
        with self._lock:
            return list(self._rows)

    @property
    def not_recorded(self) -> int:
        """Alerts that arrived after the console's buffer was full.

        They are still in the database. Only the console's view of them was
        dropped, and saying so is the difference between a short list and a
        quiet network.
        """
        with self._lock:
            return self._not_recorded

    @property
    def bus_dropped(self) -> int:
        """Alerts the bus discarded because this console fell behind."""
        subscription = self._subscription
        return subscription.dropped if subscription is not None else 0

    @property
    def uptime_seconds(self) -> float:
        """How long the engine has been monitoring."""
        with self._lock:
            if self._started_at is None:
                return 0.0
            return (datetime.now(UTC) - self._started_at).total_seconds()

    def row(self, seq: int) -> AlertRow | None:
        """Return the recorded alert numbered ``seq``."""
        with self._lock:
            return self._by_seq.get(seq)

    def severity_counts(self) -> dict[Severity, int]:
        """Tally the console's alerts by severity, highest first."""
        counts = dict.fromkeys(Severity, 0)
        for row in self.rows:
            counts[row.severity] += 1
        return dict(sorted(counts.items(), key=lambda item: item[0].rank, reverse=True))

    def threat_level(self) -> Severity | None:
        """Return the highest severity currently present, or ``None`` for nominal.

        The same derivation the web dashboard uses: a level, not a score. An
        invented composite number would imply a precision that four heuristic
        rules cannot support.
        """
        present = [severity for severity, count in self.severity_counts().items() if count]
        return max(present, key=lambda severity: severity.rank) if present else None

    def metrics(self) -> dict[str, Any]:
        """Return the pipeline's counters and gauges."""
        return self._engine.metrics.snapshot()

    def health(self) -> dict[str, Any]:
        """Return the engine's own health summary."""
        return self._engine.health()

    def traffic(self, limit: int = 60) -> list[TrafficMetric]:
        """Recent closed traffic windows, oldest first."""
        try:
            windows = self._engine.traffic.recent(limit)
        except IDSError:
            _log.exception("could not read traffic windows")
            return []
        return sorted(windows, key=lambda window: window.window_start)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self, *, capture: bool, auth_log: str | None = None) -> bool:
        """Start the engine and begin reading the bus. Returns success.

        Never raises for a capture failure: an operator without privileges
        should see the reason on screen and still get the pipeline, not a
        traceback and no interface.
        """
        if auth_log:
            self._engine.add_host_source(AuthLogSource(auth_log))

        with self._lock:
            self._capture_requested = capture

        try:
            self._engine.start(capture=capture)
        except CaptureError as exc:
            self._fail(str(exc))
            return False
        except IDSError as exc:
            self._fail(str(exc))
            return False

        self._subscription = self._engine.bus.subscribe()
        self._stop.clear()
        self._reader = threading.Thread(target=self._read_bus, name="ids-tui-bus", daemon=True)
        self._reader.start()

        with self._lock:
            self._state = ConsoleState.MONITORING
            self._failure = None
            self._started_at = datetime.now(UTC)
        return True

    def stop(self) -> None:
        """Stop the engine and the bus reader.

        Order matters. The subscription is closed first so the reader wakes
        and exits; stopping the engine closes the bus, which would also wake
        it, but only after the engine has spent its shutdown flushing.
        """
        self._stop.set()
        if self._subscription is not None:
            self._subscription.close()
        if self._reader is not None:
            self._reader.join(timeout=5.0)
            self._reader = None
        self._engine.stop()
        self._subscription = None
        with self._lock:
            if self._state is not ConsoleState.FAILED:
                self._state = ConsoleState.STOPPED

    def _fail(self, message: str) -> None:
        with self._lock:
            self._state = ConsoleState.FAILED
            self._failure = message

    # ------------------------------------------------------------------
    # Feeding a scenario
    # ------------------------------------------------------------------

    def feed(
        self,
        scenario: str,
        *,
        on_done: Callable[[dict[str, int]], None] | None = None,
    ) -> None:
        """Push a synthetic scenario through the real pipeline. Blocking.

        Call this on a worker thread. It exercises the same queue, parser,
        rules and alert manager that live capture does — it is a traffic
        source, not a mock of the detection path.
        """
        submitted = self._simulator.feed(self._engine, scenario)
        self._engine.wait_idle(timeout=30.0)
        if on_done is not None:
            on_done(submitted)

    # ------------------------------------------------------------------
    # The bus reader thread
    # ------------------------------------------------------------------

    def _read_bus(self) -> None:
        """Consume published alerts until the console stops."""
        subscription = self._subscription
        if subscription is None:
            return
        for message in subscription.listen(timeout=_LISTEN_TIMEOUT):
            if self._stop.is_set():
                return
            if message is None or message.get("type") != "alert":
                continue
            payload = message.get("alert")
            if isinstance(payload, dict):
                self._record(payload)

    def _record(self, payload: dict[str, Any]) -> None:
        with self._lock:
            self._seq += 1
            row = AlertRow(seq=self._seq, received_at=datetime.now(UTC), payload=payload)
            if len(self._rows) >= self._alert_limit:
                # Stop recording rather than evict. An operator reading a row
                # should not have it slide out from under them, and "buffer
                # full, N more in the database" is a clearer statement than a
                # window that silently moved.
                self._not_recorded += 1
                return
            self._rows.append(row)
            self._by_seq[row.seq] = row
            self._pending.append(row)

    # ------------------------------------------------------------------
    # Draining (UI thread)
    # ------------------------------------------------------------------

    def drain(self) -> DrainedAlerts:
        """Take every alert buffered since the last call."""
        with self._lock:
            drained = DrainedAlerts(rows=self._pending)
            self._pending = []
        return drained
