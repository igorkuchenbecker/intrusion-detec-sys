"""The operator console.

This is not a terminal port of the web dashboard. It is the view an operator
wants when they are already on the box: alerts arriving live, the pipeline's
own health beside them, and the state each rule is holding — over SSH, with no
browser and no port to expose. The dashboard binds to ``127.0.0.1`` for a
reason, and reaching it from another machine means standing up a proxy with
authentication and TLS. A console does not.

Both front ends read the *same* running engine: the same event bus for live
alerts, the same metrics, the same repositories. Neither re-derives a verdict,
so if they ever disagree it is a rendering bug and not two opinions.

Nothing here makes the system less passive. It observes and reports; no packet
is sent, no host is probed, nothing is blocked.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections import deque
from collections.abc import Sequence
from datetime import datetime
from importlib import resources
from typing import Any

from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.timer import Timer
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Label,
    RichLog,
    Select,
    Sparkline,
    Static,
    TabbedContent,
    TabPane,
)

from ..capture.simulator import SCENARIOS
from ..config.settings import IDSConfig
from ..core.enums import Severity
from ..observability.log import get_logger
from ..utils.privileges import check_capture_privileges
from .session import AlertRow, ConsoleSession, ConsoleState, DrainedAlerts
from .theme import ACCENT, INK, MUTED, SEVERITY_COLOURS, css_variables
from .widgets import QueueGauge, StatusLine, ThreatLevel, severity_text

__all__ = ["ConsoleTUI", "load_stylesheet", "main"]

_AUTHORISED_USE = (
    "Defensive monitoring only. Run this against networks and hosts you are authorised to "
    "monitor. Capturing someone else's traffic is usually illegal."
)

#: How often the console picks up new alerts. Fast enough to feel live.
_DRAIN_INTERVAL = 0.2

#: How often the slower panes are refreshed. Counters and queue depth do not
#: need redrawing five times a second, and a console left open for a week
#: should not spend its life repainting.
_REFRESH_INTERVAL = 1.0

_LOG_LINES = 2_000

#: Traffic windows kept in the sparkline.
_TRAFFIC_WINDOWS = 60


def load_stylesheet() -> str:
    """Return the stylesheet with the shared palette prepended.

    Read through :mod:`importlib.resources` rather than from a path relative
    to this file, so it resolves from an installed wheel and not only from a
    source checkout.
    """
    sheet = resources.files("ids.tui").joinpath("app.tcss").read_text(encoding="utf-8")
    return f"{css_variables()}\n{sheet}"


class _UiLogHandler(logging.Handler):
    """Buffers log records for the UI thread to render."""

    def __init__(self, buffer: deque[logging.LogRecord]) -> None:
        super().__init__()
        self._buffer = buffer

    def emit(self, record: logging.LogRecord) -> None:
        """Queue ``record`` for the next drain."""
        self._buffer.append(record)


class ConsoleTUI(App[int]):
    """Terminal operator console for a running IDS."""

    CSS = load_stylesheet()
    TITLE = "ids-console"

    BINDINGS = [
        Binding("ctrl+f", "feed", "Feed scenario", priority=True),
        Binding("ctrl+l", "clear_alerts", "Clear view", priority=True),
        Binding("ctrl+q", "quit", "Quit", priority=True),
    ]

    _LEVEL_COLOURS = {
        logging.DEBUG: MUTED,
        logging.INFO: INK,
        logging.WARNING: SEVERITY_COLOURS[Severity.MEDIUM],
        logging.ERROR: SEVERITY_COLOURS[Severity.CRITICAL],
        logging.CRITICAL: SEVERITY_COLOURS[Severity.CRITICAL],
    }

    def __init__(
        self,
        session: ConsoleSession,
        *,
        capture: bool = False,
        auth_log: str | None = None,
        scenario: str = "all",
        verbose: bool = False,
    ) -> None:
        super().__init__()
        self._session = session
        self._capture = capture
        self._auth_log = auth_log
        self._scenario = scenario
        self._verbose = verbose

        self._log_buffer: deque[logging.LogRecord] = deque(maxlen=_LOG_LINES)
        self._log_handler: _UiLogHandler | None = None
        self._selected: AlertRow | None = None
        self._auto_selected = False
        self._feeding = False
        self._drain_timer: Timer | None = None
        self._refresh_timer: Timer | None = None
        self._closing = False

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        """Build the widget tree."""
        yield Static(self._banner(), id="banner")

        with Vertical(id="controls"):
            with Horizontal(classes="control-row"):
                yield Label("scenario", classes="field-label")
                yield Select(
                    [(name, name) for name in SCENARIOS],
                    value=self._scenario if self._scenario in SCENARIOS else Select.BLANK,
                    allow_blank=False,
                    id="scenario",
                )
                yield Button("FEED", id="feed", variant="success")
                yield Button("CLEAR VIEW", id="clear")

        yield ThreatLevel(id="threat")
        yield DataTable(id="alerts", cursor_type="row", zebra_stripes=False)

        with TabbedContent(id="tabs"):
            with TabPane("Alert", id="tab-alert"):
                with VerticalScroll(classes="pane"):
                    yield Static(self._placeholder(), id="alert-detail")
            with TabPane("Pipeline", id="tab-pipeline"):
                with VerticalScroll(classes="pane"):
                    yield QueueGauge(id="queue")
                    yield Label("COUNTERS", classes="section")
                    yield Static(self._placeholder(), id="counters")
                    yield Label("HEALTH", classes="section")
                    yield Static(self._placeholder(), id="health")
            with TabPane("Rules", id="tab-rules"):
                with VerticalScroll(classes="pane"):
                    yield Static(self._placeholder(), id="rules")
            with TabPane("Traffic", id="tab-traffic"):
                with VerticalScroll(classes="pane"):
                    yield Label("PACKETS PER SECOND, BY CLOSED WINDOW", classes="section")
                    yield Sparkline([], id="pps", summary_function=max)
                    yield Static(self._placeholder(), id="traffic")
            with TabPane("Log", id="tab-log"):
                yield RichLog(id="log", markup=False, wrap=True, max_lines=_LOG_LINES)

        yield StatusLine(id="status")
        yield Footer()

    @staticmethod
    def _placeholder() -> Text:
        return Text("Nothing yet.", style=MUTED)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        """Start the engine, wire logging and begin the refresh timers."""
        table = self.query_one("#alerts", DataTable)
        table.add_column("#", width=5)
        table.add_column("time", width=9)
        table.add_column("severity", width=9)
        table.add_column("conf", width=6)
        table.add_column("detection", width=30)
        table.add_column("source", width=16)
        table.add_column("description")

        self.query_one("#status", StatusLine).bind_session(self._session)
        self._attach_log_capture()
        self._refresh_rules()

        started = self._session.start(capture=self._capture, auth_log=self._auth_log)
        if not started:
            self.notify(
                self._session.failure or "the engine could not start",
                title="Not monitoring",
                severity="error",
            )

        self._drain_timer = self.set_interval(_DRAIN_INTERVAL, self._drain)
        self._refresh_timer = self.set_interval(_REFRESH_INTERVAL, self._refresh_slow)
        self._refresh_slow()

    def on_unmount(self) -> None:
        """Stop the timers and the engine.

        Stopping the engine matters more here than in the other tools: it owns
        capture threads, a database and a bus. Leaving the console must leave
        no thread still reading a socket.
        """
        self._closing = True
        for timer in (self._drain_timer, self._refresh_timer):
            if timer is not None:
                timer.stop()
        self._drain_timer = self._refresh_timer = None
        self._session.stop()
        self._detach_log_capture()

    def _attach_log_capture(self) -> None:
        logger = get_logger()
        logger.setLevel(logging.DEBUG if self._verbose else logging.INFO)
        logger.propagate = False
        # The package logger writes to stderr by default, which would paint
        # over the interface. The console owns it while it runs.
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
        self._log_handler = _UiLogHandler(self._log_buffer)
        logger.addHandler(self._log_handler)

    def _detach_log_capture(self) -> None:
        if self._log_handler is not None:
            get_logger().removeHandler(self._log_handler)
            self._log_handler = None

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_feed(self) -> None:
        """Push the selected synthetic scenario through the real pipeline."""
        if self._feeding:
            self.notify("A scenario is already running.", severity="warning")
            return
        if self._session.state is not ConsoleState.MONITORING:
            self.notify(
                self._session.failure or "the engine is not running",
                title="Cannot feed a scenario",
                severity="error",
            )
            return

        scenario = str(self.query_one("#scenario", Select).value)
        self._feeding = True
        self.query_one("#feed", Button).disabled = True
        self.query_one("#status", StatusLine).set_detail(f"feeding {scenario}")
        self.run_worker(
            lambda: self._session.feed(scenario, on_done=self._feed_done),
            thread=True,
            name="feed",
            group="feed",
        )

    def _feed_done(self, submitted: dict[str, int]) -> None:
        """Record that the scenario finished. Runs on the worker thread."""
        self._feeding = False
        self.call_from_thread(self._after_feed, submitted)

    def _after_feed(self, submitted: dict[str, int]) -> None:
        if self._closing:
            return
        self.query_one("#feed", Button).disabled = False
        self.query_one("#status", StatusLine).set_detail("")
        self.notify(
            f"{submitted['packets']} packet(s), {submitted['host_events']} host event(s) "
            "through the pipeline.",
            title="Scenario finished",
        )

    def action_clear_alerts(self) -> None:
        """Empty the alert table without deleting anything from the database."""
        self.query_one("#alerts", DataTable).clear()
        self._selected = None
        self._auto_selected = False
        self.query_one("#alert-detail", Static).update(
            Text(
                "View cleared. Alerts are still in the database; only this table was emptied.",
                style=MUTED,
            )
        )

    @on(Button.Pressed, "#feed")
    def _on_feed_pressed(self) -> None:
        self.action_feed()

    @on(Button.Pressed, "#clear")
    def _on_clear_pressed(self) -> None:
        self.action_clear_alerts()

    # ------------------------------------------------------------------
    # Refreshing
    # ------------------------------------------------------------------

    def _drain(self) -> None:
        """Move newly published alerts into the table.

        The look-before-you-leap check is deliberate: Textual unmounts children
        before parents, so this app's ``on_unmount`` runs after the widgets are
        gone and a tick scheduled just before it lands on an empty screen.
        Draining is destructive, so a batch taken and half applied is an alert
        no later tick can recover.
        """
        if self._closing or not self.query("#status"):
            return
        self._drain_logs()
        self._apply(self._session.drain())

    def _apply(self, drained: DrainedAlerts) -> None:
        if not drained:
            return
        table = self.query_one("#alerts", DataTable)
        for row in drained.rows:
            self._append_row(table, row)
            # Select the first alert automatically. The guard is this flag and
            # not ``self._selected``, which a message handler writes later: a
            # batch arriving in one tick would otherwise land on the last row.
            if not self._auto_selected:
                self._auto_selected = True
                table.move_cursor(row=table.row_count - 1)
        self._refresh_threat()

    def _refresh_slow(self) -> None:
        """Repaint the panes that change on their own, not per alert."""
        if self._closing or not self.query("#status"):
            return
        self._refresh_threat()
        self._refresh_pipeline()
        self._refresh_rules()
        self._refresh_traffic()
        self.query_one("#status", StatusLine).refresh()

    def _drain_logs(self) -> None:
        if not self._log_buffer:
            return
        pane = self.query_one("#log", RichLog)
        while self._log_buffer:
            record = self._log_buffer.popleft()
            pane.write(self._format_record(record))

    def _format_record(self, record: logging.LogRecord) -> Text:
        stamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        colour = self._LEVEL_COLOURS.get(record.levelno, INK)
        line = Text()
        line.append(f"{stamp} ", style=MUTED)
        line.append(f"{record.levelname:<8}", style=colour)
        line.append(f"{record.name.removeprefix('ids.'):<12} ", style=MUTED)
        line.append(record.getMessage(), style=INK)
        return line

    # ------------------------------------------------------------------
    # Panes
    # ------------------------------------------------------------------

    def _refresh_threat(self) -> None:
        self.query_one("#threat", ThreatLevel).update_level(
            self._session.threat_level(), self._session.severity_counts()
        )

    def _refresh_pipeline(self) -> None:
        snapshot = self._session.metrics()
        gauges = snapshot["gauges"]
        counters = snapshot["counters"]
        self.query_one("#queue", QueueGauge).update_queue(
            int(gauges.get("queue_size", 0)),
            int(gauges.get("queue_capacity", 1)),
            counters.get("packets_dropped", 0),
        )

        body = Text()
        for name, value in counters.items():
            body.append(f"{name:<26}", style=MUTED)
            body.append(f"{value}\n", style=INK)
        self.query_one("#counters", Static).update(body)

        health = self._session.health()
        detail = Text()
        status = str(health.get("status", "unknown"))
        detail.append(f"{'status':<20}", style=MUTED)
        detail.append(
            f"{status}\n",
            style=f"bold {ACCENT if status == 'healthy' else SEVERITY_COLOURS[Severity.HIGH]}",
        )
        for key in ("database", "capture"):
            detail.append(f"{key:<20}", style=MUTED)
            detail.append(f"{health.get(key, 'unknown')}\n", style=INK)
        queue = health.get("queue", {})
        detail.append(f"{'queue':<20}", style=MUTED)
        detail.append(
            f"{queue.get('size', 0)}/{queue.get('capacity', 0)} ({queue.get('state', '?')})\n",
            style=INK,
        )
        if self._session.bus_dropped or self._session.not_recorded:
            detail.append("\n")
            detail.append(
                "This console fell behind. ",
                style=f"bold {SEVERITY_COLOURS[Severity.MEDIUM]}",
            )
            detail.append(
                f"{self._session.bus_dropped} alert(s) were dropped from its mailbox and "
                f"{self._session.not_recorded} were not recorded because its buffer is full. "
                "All of them are in the database; the web dashboard was unaffected, because "
                "each subscriber has its own bounded mailbox.",
                style=MUTED,
            )
        self.query_one("#health", Static).update(detail)

    def _refresh_rules(self) -> None:
        """List every stage holding state, what it reports and how much it holds.

        Correlation is listed with the rules but marked as what it is: a
        separate stage that runs on their output. It has its own bounded
        state, and a pane that showed three rules while the metrics reported
        four state sizes would leave the fourth unexplained.
        """
        detection = self._session.engine.detection
        sizes = detection.state_sizes()

        body = Text()
        body.append(
            "Every temporal rule expires state by time and caps how many keys it tracks. "
            "State that grows without bound is how an IDS dies after a week in production.\n\n",
            style=MUTED,
        )
        for rule in detection.rules:
            self._append_stage(
                body,
                name=rule.name,
                reports=rule.detection_type.title,
                mitre=self._mitre_for(rule.name),
                tracked=sizes.get(rule.name, 0),
                doc=rule.__doc__,
            )

        correlation = detection.correlation
        self._append_stage(
            body,
            name=correlation.name,
            reports="Correlated Suspicious Activity",
            mitre=self._mitre_for(correlation.name),
            tracked=sizes.get(correlation.name, 0),
            doc=correlation.__doc__,
            note="runs after the rules, on their output; inherits severity rather than raising it",
        )
        self.query_one("#rules", Static).update(body)

    @staticmethod
    def _append_stage(
        body: Text,
        *,
        name: str,
        reports: str,
        mitre: str,
        tracked: int,
        doc: str | None,
        note: str = "",
    ) -> None:
        body.append(f"{name}\n", style=f"bold {ACCENT}")
        body.append(f"  reports        {reports}\n", style=INK)
        body.append(f"  MITRE          {mitre}\n", style=MUTED)
        body.append(f"  tracked keys   {tracked}\n", style=INK)
        summary = (doc or "").strip().splitlines()
        if summary:
            body.append(f"  {summary[0]}\n", style=MUTED)
        if note:
            body.append(f"  {note}\n", style=MUTED)
        body.append("\n")

    @staticmethod
    def _mitre_for(rule_name: str) -> str:
        """Return the technique a rule maps to, or an honest blank.

        A volume spike is not necessarily denial of service, so that rule has
        no technique rather than an invented one.
        """
        return {"port_scan": "T1046", "brute_force": "T1110"}.get(rule_name, "— none claimed")

    def _refresh_traffic(self) -> None:
        windows = self._session.traffic(_TRAFFIC_WINDOWS)
        sparkline = self.query_one("#pps", Sparkline)
        sparkline.data = [window.packets_per_second for window in windows]

        body = Text()
        if not windows:
            body.append(
                "No traffic window has closed yet. Windows close on a timer, so an idle "
                "pipeline produces none.",
                style=MUTED,
            )
            self.query_one("#traffic", Static).update(body)
            return

        latest = windows[-1]
        body.append("latest window   ", style=MUTED)
        body.append(f"{latest.packets_per_second:.1f} packets/s", style=f"bold {ACCENT}")
        body.append(f"   {latest.bytes_per_second:.0f} bytes/s\n\n", style=MUTED)

        body.append(
            f"{'window start':<22}{'pkts':>8}{'pkt/s':>10}{'bytes':>12}{'srcs':>7}\n", style=MUTED
        )
        for window in reversed(windows[-20:]):
            body.append(f"{window.window_start.strftime('%Y-%m-%d %H:%M:%S'):<22}", style=MUTED)
            body.append(f"{window.packets:>8}", style=INK)
            body.append(f"{window.packets_per_second:>10.1f}", style=INK)
            body.append(f"{window.bytes_total:>12}", style=MUTED)
            body.append(f"{window.unique_sources:>7}\n", style=MUTED)
        self.query_one("#traffic", Static).update(body)

    # ------------------------------------------------------------------
    # The alert table
    # ------------------------------------------------------------------

    def _append_row(self, table: DataTable, row: AlertRow) -> None:
        payload = row.payload
        table.add_row(
            Text(str(row.seq), style=MUTED),
            Text(row.received_at.strftime("%H:%M:%S"), style=MUTED),
            severity_text(row.severity),
            Text(str(payload.get("confidence", "-")), style=MUTED),
            Text(row.title, style=INK),
            Text(row.source_ip, style=INK),
            Text(str(payload.get("description", "")), style=INK),
            key=str(row.seq),
        )

    @on(DataTable.RowHighlighted, "#alerts")
    def _on_row(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key.value is None:
            return
        row = self._session.row(int(event.row_key.value))
        if row is None:
            return
        self._selected = row
        self.query_one("#alert-detail", Static).update(self._render_alert(row))

    def _render_alert(self, row: AlertRow) -> Text:
        payload = row.payload
        out = Text()
        out.append_text(severity_text(row.severity))
        out.append(f"  {row.title}\n", style=f"bold {INK}")
        out.append(f"{payload.get('description', '')}\n\n", style=INK)

        facts = (
            ("rule", payload.get("rule") or "-"),
            ("detection type", payload.get("detection_type") or "-"),
            ("confidence", payload.get("confidence") or "-"),
            ("source", self._endpoint(payload, "source")),
            ("destination", self._endpoint(payload, "destination")),
            ("MITRE", payload.get("mitre_technique") or "— none claimed"),
            ("occurrences", str(dict(payload.get("metadata") or {}).get("occurrences", 1))),
            ("alert id", payload.get("id") or "-"),
        )
        for label, value in facts:
            out.append(f"{label:<16}", style=MUTED)
            out.append(f"{value}\n", style=INK)

        evidence = dict(payload.get("evidence") or {})
        out.append("\nEVIDENCE\n", style=f"bold {ACCENT}")
        if evidence:
            for key, value in evidence.items():
                out.append(f"  {key:<24}", style=MUTED)
                out.append(f"{value}\n", style=INK)
        else:
            out.append("  none recorded\n", style=MUTED)

        out.append("\nWHAT TO DO\n", style=f"bold {ACCENT}")
        out.append(f"{payload.get('mitigation', '')}\n", style=INK)

        out.append(
            "\nThis is an indicator, not a confirmed attack. The rule observed a pattern; "
            "confirming it needs context this system does not have.",
            style=MUTED,
        )
        return out

    @staticmethod
    def _endpoint(payload: dict[str, Any], side: str) -> str:
        address = payload.get(f"{side}_ip")
        port = payload.get(f"{side}_port")
        if not address:
            return "-"
        return f"{address}:{port}" if port else str(address)

    # ------------------------------------------------------------------

    @staticmethod
    def _banner() -> Text:
        line = Text()
        line.append("// IDS CONSOLE", style=f"bold {ACCENT}")
        line.append(
            "   monitoring only · no packet sent · no host probed or blocked",
            style=MUTED,
        )
        return line


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``ids-console``."""
    parser = argparse.ArgumentParser(
        prog="ids-console",
        description="Terminal operator console for the intrusion detection system.",
        epilog=_AUTHORISED_USE,
    )
    parser.add_argument("--config", help="Path to a TOML configuration file.")
    parser.add_argument("--database", help="Path to the SQLite database.")
    parser.add_argument("--interface", help="Interface to capture on.")
    parser.add_argument("--bpf-filter", help="BPF capture filter, e.g. 'tcp or udp'.")
    parser.add_argument("--auth-log", help="Path to an OpenSSH-style auth log to monitor.")
    parser.add_argument(
        "--capture",
        action="store_true",
        help="Capture live traffic. Needs privileges; run 'ids check' to see what is missing.",
    )
    parser.add_argument(
        "--scenario",
        choices=SCENARIOS,
        default="all",
        help="Which synthetic scenario the FEED button runs.",
    )
    parser.add_argument("--verbose", action="store_true", help="Show debug records in the log.")
    args = parser.parse_args(argv)

    config = IDSConfig.from_toml(args.config) if args.config else IDSConfig()
    config = IDSConfig.from_env(config).with_overrides(
        database_path=args.database,
        interface=args.interface,
        bpf_filter=args.bpf_filter,
    )

    if args.capture:
        report = check_capture_privileges()
        if not report.can_capture:
            print("Cannot capture with the current privileges.\n", file=sys.stderr)
            print(report.guidance, file=sys.stderr)
            return 1

    # Built before the interface takes over the terminal: a database that
    # cannot be opened should say so on a normal console, not behind a
    # half-drawn screen.
    session = ConsoleSession(config)
    ConsoleTUI(
        session,
        capture=args.capture,
        auth_log=args.auth_log,
        scenario=args.scenario,
        verbose=args.verbose,
    ).run()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
