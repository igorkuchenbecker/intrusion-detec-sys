"""Tests for the threat indicator and the queue gauge.

Both of these can mislead in a specific way, and that is what is asserted:
the threat bar can fill to a fraction that does not match the level it names,
and the queue gauge can show a healthy-looking pipeline while packets are
being dropped.
"""

from __future__ import annotations

import pytest

from ids.core.enums import Severity
from ids.tui.app import load_stylesheet
from ids.tui.widgets import QueueGauge, ThreatLevel

_WIDTHS = [20, 40, 80, 158, 220]


def _threat(level: Severity | None, **counts: int) -> ThreatLevel:
    widget = ThreatLevel()
    widget._level = level
    widget._counts = {severity: counts.get(severity.label, 0) for severity in Severity}
    return widget


def test_nominal_says_what_it_does_not_mean() -> None:
    """ "Nothing fired" and "nothing happened" are different claims."""
    rendered = str(_threat(None).render())
    assert "NOMINAL" in rendered
    assert "not a statement that nothing happened" in rendered


@pytest.mark.parametrize("severity", list(Severity))
def test_every_level_names_itself_in_writing(severity: Severity) -> None:
    rendered = str(_threat(severity, **{severity.label: 1}).render())
    assert severity.label.upper() in rendered


@pytest.mark.parametrize("severity", list(Severity))
@pytest.mark.parametrize("width", _WIDTHS)
def test_the_bar_fills_the_fraction_the_dashboard_fills(severity: Severity, width: int) -> None:
    """The console and the browser must agree on what a level looks like."""
    assert ThreatLevel.fill_cells(severity, width) == max(
        1, min(width, round(width * (severity.rank + 1) / len(Severity)))
    )


@pytest.mark.parametrize("severity", list(Severity))
@pytest.mark.parametrize("width", _WIDTHS)
def test_the_bar_never_overflows_and_never_vanishes(severity: Severity, width: int) -> None:
    """A level that drew nothing would read as nominal, which is the opposite."""
    cells = ThreatLevel.fill_cells(severity, width)
    assert 1 <= cells <= width


def test_the_levels_are_ordered_by_how_much_they_fill() -> None:
    """A worse level must never draw a shorter bar than a milder one."""
    ordered = sorted(Severity, key=lambda severity: severity.rank)
    filled = [ThreatLevel.fill_cells(severity, 100) for severity in ordered]
    assert filled == sorted(filled)
    assert len(set(filled)) == len(ordered)


def test_a_clean_queue_says_the_alert_list_is_complete() -> None:
    gauge = QueueGauge()
    gauge.update_queue(0, 10_000, 0)
    rendered = str(gauge.render())
    assert "0/10000" in rendered
    assert "covers every packet seen" in rendered


def test_dropped_packets_invalidate_an_empty_alert_list_in_writing() -> None:
    """The single most important sentence this console prints."""
    gauge = QueueGauge()
    gauge.update_queue(9_500, 10_000, 42)
    rendered = str(gauge.render())

    assert "42" in rendered
    assert "never analysed" in rendered
    assert "not evidence of a quiet network" in rendered


def test_a_zero_capacity_does_not_divide_by_zero() -> None:
    gauge = QueueGauge()
    gauge.update_queue(0, 0, 0)
    assert "0/1" in str(gauge.render())


def test_the_queue_gauge_does_not_shadow_the_widget_size() -> None:
    """``Widget`` owns ``_size``; overwriting it breaks Textual's own layout.

    This one is worth pinning: the failure surfaced as an AttributeError deep
    inside the framework, pointing nowhere near the widget that caused it.
    """
    gauge = QueueGauge()
    gauge.update_queue(5, 10, 0)
    assert not isinstance(gauge._size, int)


def test_stylesheet_ships_with_the_package() -> None:
    """The sheet must resolve from package data, not from the source tree."""
    sheet = load_stylesheet()
    assert "$accent:" in sheet
    assert "$sev-critical:" in sheet
    assert "Screen {" in sheet
