"""Tests for the bounded state structures every temporal rule depends on."""

from __future__ import annotations

import pytest

from ids.detection.state import CooldownGate, SlidingWindow


def test_values_expire_outside_the_window() -> None:
    window = SlidingWindow(window_seconds=10.0, max_keys=100)
    window.add("a", 1, now=0.0)
    window.add("a", 2, now=5.0)
    assert window.count("a", now=5.0) == 2
    # At t=12 the entry from t=0 has aged out; the one from t=5 has not.
    assert window.count("a", now=12.0) == 1


def test_unique_collapses_repeats() -> None:
    window = SlidingWindow(window_seconds=10.0, max_keys=100)
    for _ in range(5):
        window.add("a", 443, now=1.0)
    assert window.unique("a", now=1.0) == {443}


def test_key_count_is_capped_and_evicts_oldest() -> None:
    window = SlidingWindow(window_seconds=100.0, max_keys=3)
    for index in range(5):
        window.add(f"key{index}", index, now=float(index))
    assert len(window) == 3
    assert window.evictions == 2
    assert window.count("key0", now=5.0) == 0  # evicted
    assert window.count("key4", now=5.0) == 1


def test_prune_forgets_emptied_keys() -> None:
    window = SlidingWindow(window_seconds=5.0, max_keys=10)
    window.add("a", 1, now=0.0)
    assert len(window) == 1
    window.prune(now=100.0)
    assert len(window) == 0


def test_cooldown_blocks_repeats_then_allows() -> None:
    gate = CooldownGate(cooldown_seconds=30.0, max_keys=10)
    assert gate.allow("src", now=0.0) is True
    assert gate.allow("src", now=10.0) is False
    assert gate.allow("src", now=29.9) is False
    assert gate.allow("src", now=30.0) is True
    assert gate.suppressed == 2


def test_cooldown_is_per_key() -> None:
    gate = CooldownGate(cooldown_seconds=30.0, max_keys=10)
    assert gate.allow("a", now=0.0) is True
    assert gate.allow("b", now=0.0) is True


def test_cooldown_key_count_is_capped() -> None:
    gate = CooldownGate(cooldown_seconds=30.0, max_keys=2)
    for index in range(5):
        gate.allow(f"key{index}", now=0.0)
    assert len(gate) <= 2


@pytest.mark.parametrize(
    ("cls", "kwargs"),
    [
        (SlidingWindow, {"window_seconds": 0, "max_keys": 1}),
        (SlidingWindow, {"window_seconds": 1, "max_keys": 0}),
        (CooldownGate, {"cooldown_seconds": -1, "max_keys": 1}),
        (CooldownGate, {"cooldown_seconds": 1, "max_keys": 0}),
    ],
)
def test_invalid_bounds_rejected(cls, kwargs) -> None:
    with pytest.raises(ValueError):
        cls(**kwargs)
