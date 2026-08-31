"""The threat indicator, the queue gauge and the status line.

Two of these exist to stop the console making a claim the pipeline cannot
support:

* :class:`ThreatLevel` reports the highest severity currently present as a
  *level*, exactly as the web dashboard does. It is not a composite score,
  because averaging four heuristic rules into one number would imply a
  precision none of them has.
* :class:`QueueGauge` shows the queue against its capacity and, next to it,
  the dropped-packet count. A dropped packet is a packet nobody analysed, so
  an empty alert list means nothing while that number is climbing. The gauge
  says so in writing rather than leaving the operator to infer it.

Nothing here is signalled by colour alone.
"""

from __future__ import annotations

from rich.text import Text
from textual.widgets import Static

from ..core.enums import Severity
from .session import ConsoleSession, ConsoleState
from .theme import ACCENT, INK, MUTED, NOMINAL, SEVERITY_COLOURS

__all__ = ["ThreatLevel", "QueueGauge", "StatusLine", "severity_text"]

_FILLED = "█"
_TRACK = "░"


def severity_text(severity: Severity) -> Text:
    """Return the severity's written label in its colour."""
    return Text(severity.label.upper(), style=f"bold {SEVERITY_COLOURS[severity]}")


class ThreatLevel(Static):
    """The highest severity currently present, as a level with a bar."""

    DEFAULT_CSS = """
    ThreatLevel { height: auto; }
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._level: Severity | None = None
        self._counts: dict[Severity, int] = dict.fromkeys(Severity, 0)

    def update_level(self, level: Severity | None, counts: dict[Severity, int]) -> None:
        """Set the current level and the per-severity tally."""
        self._level = level
        self._counts = {severity: counts.get(severity, 0) for severity in Severity}
        self.refresh()

    @staticmethod
    def fill_cells(level: Severity, width: int) -> int:
        """Return how much of a ``width``-cell track ``level`` fills.

        ``(rank + 1) / 5`` of the track: the same fraction the web dashboard
        fills, so a level looks like the same amount of bar in the terminal
        and in the browser. Always at least one cell — a level that named
        itself while drawing nothing would read as nominal.
        """
        return max(1, min(width, round(width * (level.rank + 1) / len(Severity))))

    def on_resize(self) -> None:
        """Redraw: the bar is proportional to the widget's width."""
        self.refresh()

    def render(self) -> Text:
        """Draw the level, its bar and the per-severity counts."""
        width = max(self.size.width, 20)
        out = Text()

        out.append("threat level  ", style=MUTED)
        if self._level is None:
            out.append("NOMINAL", style=f"bold {NOMINAL}")
            out.append("   nothing has fired; not a statement that nothing happened", style=MUTED)
            out.append("\n")
            out.append(_TRACK * width, style=MUTED)
            return out

        colour = SEVERITY_COLOURS[self._level]
        out.append(self._level.label.upper(), style=f"bold {colour}")
        out.append(f"   highest severity among {sum(self._counts.values())} alert(s)", style=MUTED)
        out.append("\n")

        filled = self.fill_cells(self._level, width)
        out.append(_FILLED * filled, style=colour)
        out.append(_TRACK * (width - filled), style=MUTED)
        out.append("\n")

        for severity, count in sorted(
            self._counts.items(), key=lambda item: item[0].rank, reverse=True
        ):
            out.append(f"{severity.label.upper()} ", style=SEVERITY_COLOURS[severity])
            out.append(f"{count}  ", style=f"bold {INK}" if count else MUTED)
        return out


class QueueGauge(Static):
    """Pipeline saturation and loss, side by side.

    These two belong together. A queue at 90% is a warning; a queue at 90%
    with a rising drop count is an admission that the alert list is
    incomplete, and only the pair says which one you are looking at.
    """

    DEFAULT_CSS = """
    QueueGauge { height: auto; }
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        # Named _queue_size, not _size: Widget already owns _size and
        # overwriting it with an int breaks the framework's own layout code
        # with an error that points nowhere near this class.
        self._queue_size = 0
        self._queue_capacity = 1
        self._dropped = 0

    def update_queue(self, size: int, capacity: int, dropped: int) -> None:
        """Set the queue occupancy and the cumulative drop count."""
        self._queue_size = size
        self._queue_capacity = max(capacity, 1)
        self._dropped = dropped
        self.refresh()

    def on_resize(self) -> None:
        """Redraw: the bar is proportional to the widget's width."""
        self.refresh()

    def render(self) -> Text:
        """Draw the fill bar and the loss statement."""
        width = max(self.size.width, 20)
        fill = self._queue_size / self._queue_capacity
        colour = ACCENT if fill < 0.9 else SEVERITY_COLOURS[Severity.HIGH]

        out = Text()
        out.append("capture queue  ", style=MUTED)
        out.append(f"{self._queue_size}/{self._queue_capacity}", style=f"bold {colour}")
        out.append(f"  ({fill:.0%} full)\n", style=MUTED)

        filled = min(width, round(width * fill))
        out.append(_FILLED * filled, style=colour)
        out.append(_TRACK * (width - filled), style=MUTED)
        out.append("\n")

        out.append("packets dropped  ", style=MUTED)
        if self._dropped:
            out.append(str(self._dropped), style=f"bold {SEVERITY_COLOURS[Severity.HIGH]}")
            out.append(
                "\nA dropped packet was never analysed. While this number is above zero, "
                "an empty alert list is not evidence of a quiet network.",
                style=MUTED,
            )
        else:
            out.append("0", style=INK)
            out.append(
                "\nNothing was lost, so the alert list covers every packet seen.", style=MUTED
            )
        return out


class StatusLine(Static):
    """The bottom bar: engine state, alert tally and what has been lost."""

    DEFAULT_CSS = """
    StatusLine { height: 1; }
    """

    _STATE_COLOURS = {
        ConsoleState.STOPPED: MUTED,
        ConsoleState.MONITORING: ACCENT,
        ConsoleState.FAILED: SEVERITY_COLOURS[Severity.CRITICAL],
    }

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._session: ConsoleSession | None = None
        self._detail = ""

    def bind_session(self, session: ConsoleSession) -> None:
        """Point the status line at ``session``."""
        self._session = session
        self.refresh()

    def set_detail(self, detail: str) -> None:
        """Show ``detail`` as the current activity."""
        self._detail = detail
        self.refresh()

    def render(self) -> Text:
        """Draw the status fields."""
        line = Text()
        session = self._session
        if session is None:
            line.append(" STOPPED ", style=f"bold {MUTED}")
            return line

        state = session.state
        line.append(f" {state.value.upper()} ", style=f"bold {self._STATE_COLOURS[state]}")
        line.append("capture " if session.capturing else "no capture ", style=MUTED)
        if self._detail:
            line.append(f"{self._detail} ", style=INK)

        counters = session.metrics()["counters"]
        self._field(line, "alerts", str(counters["alerts_generated"]))
        self._field(line, "events", str(counters["events_processed"]))
        self._field(line, "dropped", str(counters["packets_dropped"]))
        self._field(line, "uptime", f"{session.uptime_seconds:.0f}s")
        if session.not_recorded or session.bus_dropped:
            self._field(line, "console lost", str(session.not_recorded + session.bus_dropped))
        return line

    @staticmethod
    def _field(line: Text, label: str, value: str) -> None:
        line.append(" │ ", style=MUTED)
        line.append(f"{label} ", style=MUTED)
        line.append(value, style=INK)
