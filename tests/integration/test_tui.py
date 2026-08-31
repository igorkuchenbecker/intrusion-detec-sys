"""The operator console driven end to end against a real running engine.

The scenario is pushed through the actual pipeline — queue, parser, rules,
correlation, alert manager, SQLite, bus — not a fake of it. What is being
tested is that the console reports what that pipeline produced, and that it
leaves nothing running when it closes.

``asyncio.run`` is used directly rather than adding an async test plugin.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar

import pytest
from textual.widgets import Button, DataTable, Select, Sparkline, Static

from ids.config.settings import IDSConfig
from ids.core.engine import IDSEngine
from ids.tui.app import ConsoleTUI
from ids.tui.session import ConsoleSession, ConsoleState
from ids.tui.widgets import QueueGauge, ThreatLevel

_T = TypeVar("_T")

#: A synthetic scenario drains in well under a second; this is the margin for
#: a loaded CI box, small enough that a stall fails rather than hangs.
_TIMEOUT_SECONDS = 30.0
_POLL = 0.02

#: How long the alert count must hold still before a test believes it. Longer
#: than the console's 0.2s drain interval, so "settled" means a drain ran and
#: found nothing new rather than one simply not having fired yet.
_SETTLE_SECONDS = 0.4


@pytest.fixture()
def console(tmp_path, config: IDSConfig):
    """A console over a real engine with a temporary database."""
    engine = IDSEngine(config.with_overrides(database_path=str(tmp_path / "console.db")))
    session = ConsoleSession(config, engine=engine)
    yield session
    session.stop()


def _run(coro_factory: Callable[[], Awaitable[_T]]) -> _T:
    return asyncio.run(coro_factory())


async def _await_alerts(app: ConsoleTUI, pilot, minimum: int = 1) -> None:
    """Pump the UI until the alert flow has *settled*, not merely started.

    There are three distinct moments here and only the last one is safe to
    assert against: the feed worker returns, the bus reader records what was
    published, and the drain timer renders it. Waiting on the first — or even
    on the first row appearing — leaves every assertion racing a drain that
    has not run yet.

    So this waits for the table to match the session's own count *and* stay
    unchanged for longer than one drain interval.
    """
    quiet_polls = int(_SETTLE_SECONDS / _POLL)
    waited = 0.0
    stable = 0
    previous = -1
    table = app.query_one("#alerts", DataTable)

    while waited < _TIMEOUT_SECONDS:
        await pilot.pause()
        count = table.row_count
        caught_up = count >= minimum and count == len(app._session.rows) and not app._feeding
        stable = stable + 1 if caught_up and count == previous else 0
        previous = count
        if stable >= quiet_polls:
            return
        await asyncio.sleep(_POLL)
        waited += _POLL

    raise AssertionError(
        f"alerts did not settle: table has {table.row_count} row(s), "
        f"the session has {len(app._session.rows)}"
    )


def _text(widget: Static) -> str:
    content = getattr(widget, "_content", None)
    return str(content) if content is not None else str(widget.render())


@pytest.mark.parametrize("size", [(80, 24), (100, 30), (160, 46), (220, 60)])
def test_every_control_is_actually_on_screen(console: ConsoleSession, size) -> None:
    """A widget laid out past the edge is in the DOM and invisible.

    A query finds it and a test that only queries passes while the operator
    cannot see the button. Checking geometry is what catches that.
    """

    async def scenario() -> None:
        app = ConsoleTUI(console, capture=False)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            width, height = app.size.width, app.size.height
            offscreen = [
                (widget.__class__.__name__, widget.id, str(widget.region))
                for widget in (*app.query(Select), *app.query(Button))
                if widget.region.x < 0
                or widget.region.right > width
                or widget.region.y < 0
                or widget.region.bottom > height
            ]
            assert offscreen == []

    _run(scenario)


def test_the_engine_starts_monitoring_without_capture(console: ConsoleSession) -> None:
    async def scenario() -> None:
        app = ConsoleTUI(console, capture=False)
        async with app.run_test(size=(160, 46)) as pilot:
            await pilot.pause()
            assert console.state is ConsoleState.MONITORING
            assert console.capturing is False
            assert console.health()["capture"] == "disabled"

    _run(scenario)


def test_a_scenario_produces_alerts_and_fills_the_panes(console: ConsoleSession) -> None:
    async def scenario() -> None:
        app = ConsoleTUI(console, capture=False, scenario="all")
        async with app.run_test(size=(160, 46)) as pilot:
            await pilot.pause()
            app.action_feed()
            await _await_alerts(app, pilot)

            table = app.query_one("#alerts", DataTable)
            assert table.row_count == len(console.rows)
            assert table.row_count > 0

            # Every alert came from the real pipeline, so the counters agree.
            counters = console.metrics()["counters"]
            assert counters["packets_captured"] > 0
            assert counters["events_processed"] > 0
            assert counters["alerts_generated"] == len(console.rows)

            threat = str(app.query_one("#threat", ThreatLevel).render())
            assert console.threat_level() is not None
            assert console.threat_level().label.upper() in threat

            detail = _text(app.query_one("#alert-detail", Static))
            assert "EVIDENCE" in detail
            assert "WHAT TO DO" in detail
            assert "indicator, not a confirmed attack" in detail

    _run(scenario)


def test_the_first_alert_is_selected_not_the_last(console: ConsoleSession) -> None:
    """A batch drained in one tick must not land the cursor on the newest row."""

    async def scenario() -> None:
        app = ConsoleTUI(console, capture=False, scenario="all")
        async with app.run_test(size=(160, 46)) as pilot:
            await pilot.pause()
            app.action_feed()
            await _await_alerts(app, pilot, minimum=2)

            assert app._selected is not None
            assert app._selected.seq == 1

    _run(scenario)


def test_the_pipeline_pane_reports_a_clean_run(console: ConsoleSession) -> None:
    async def scenario() -> None:
        app = ConsoleTUI(console, capture=False, scenario="all")
        async with app.run_test(size=(160, 46)) as pilot:
            await pilot.pause()
            app.action_feed()
            await _await_alerts(app, pilot)
            app._refresh_slow()
            await pilot.pause()

            gauge = str(app.query_one("#queue", QueueGauge).render())
            counters = console.metrics()["counters"]
            if counters["packets_dropped"]:
                assert "not evidence of a quiet network" in gauge
            else:
                assert "covers every packet seen" in gauge

            pane = _text(app.query_one("#counters", Static))
            assert "packets_captured" in pane
            assert "packets_dropped" in pane

    _run(scenario)


def test_the_rules_pane_lists_every_stage_that_holds_state(
    console: ConsoleSession,
) -> None:
    """Correlation is a stage too, and the metrics already count its state."""

    async def scenario() -> None:
        app = ConsoleTUI(console, capture=False)
        async with app.run_test(size=(160, 46)) as pilot:
            await pilot.pause()
            pane = _text(app.query_one("#rules", Static))

            for name in console.engine.detection.state_sizes():
                assert name in pane, f"{name} holds state but is not listed"
            assert "T1046" in pane
            assert "none claimed" in pane  # traffic_anomaly claims no technique

    _run(scenario)


def test_the_traffic_pane_shows_closed_windows(console: ConsoleSession) -> None:
    async def scenario() -> None:
        app = ConsoleTUI(console, capture=False, scenario="all")
        async with app.run_test(size=(160, 46)) as pilot:
            await pilot.pause()
            app.action_feed()
            await _await_alerts(app, pilot)
            app._refresh_slow()
            await pilot.pause()

            windows = console.traffic()
            assert windows, "the scenario should close at least one traffic window"
            assert app.query_one("#pps", Sparkline).data == [
                window.packets_per_second for window in windows
            ]
            assert "packets/s" in _text(app.query_one("#traffic", Static))

    _run(scenario)


def test_clearing_the_view_keeps_the_alerts_in_the_database(
    console: ConsoleSession,
) -> None:
    async def scenario() -> None:
        app = ConsoleTUI(console, capture=False, scenario="all")
        async with app.run_test(size=(160, 46)) as pilot:
            await pilot.pause()
            app.action_feed()
            await _await_alerts(app, pilot)
            stored = console.engine.alerts.count()
            assert stored > 0

            app.action_clear_alerts()
            await pilot.pause()

            assert app.query_one("#alerts", DataTable).row_count == 0
            assert app._selected is None
            assert console.engine.alerts.count() == stored
            assert "still in the database" in _text(app.query_one("#alert-detail", Static))

    _run(scenario)


def test_quitting_stops_the_engine_and_its_threads(tmp_path, config: IDSConfig) -> None:
    """The console owns capture threads, a database and a bus.

    Leaving it must leave none of them running, and the drain timer must not
    fire after the widgets it writes to are gone.
    """
    engine = IDSEngine(config.with_overrides(database_path=str(tmp_path / "quit.db")))
    session = ConsoleSession(config, engine=engine)

    async def scenario() -> None:
        app = ConsoleTUI(session, capture=False, scenario="all")
        async with app.run_test(size=(160, 46)) as pilot:
            await pilot.pause()
            app.action_feed()
            await _await_alerts(app, pilot)
        # Leaving the context unmounts the app; Textual re-raises anything the
        # app raised, so reaching this line is the assertion about the timer.

    _run(scenario)

    assert session.state is ConsoleState.STOPPED
    assert engine.running is False
    reader = session._reader
    assert reader is None or not reader.is_alive()
