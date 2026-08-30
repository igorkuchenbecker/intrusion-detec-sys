"""Bounded, self-expiring state for temporal rules.

Every rule that reasons over a time window needs to remember recent events, and
that memory is exactly where a long-running IDS leaks. Both structures here are
bounded twice over: entries expire by time, and the number of tracked keys is
capped, evicting the least recently updated key when full.

Time is passed in explicitly as a float of seconds, taken from the *event*
rather than the wall clock. That is what makes rule behaviour reproducible in
tests and identical when replaying a capture faster than real time.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from collections.abc import Iterator
from typing import Any

__all__ = ["SlidingWindow", "CooldownGate"]


class SlidingWindow:
    """Per-key time-ordered values, pruned by age and by key count."""

    def __init__(self, window_seconds: float, max_keys: int) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        if max_keys <= 0:
            raise ValueError("max_keys must be > 0")
        self._window = window_seconds
        self._max_keys = max_keys
        self._data: OrderedDict[str, deque[tuple[float, Any]]] = OrderedDict()
        self.evictions = 0

    @property
    def window_seconds(self) -> float:
        """Length of the retention window."""
        return self._window

    def add(self, key: str, value: Any, now: float) -> None:
        """Record ``value`` under ``key`` at time ``now``."""
        entries = self._data.get(key)
        if entries is None:
            self._make_room()
            entries = deque()
            self._data[key] = entries
        entries.append((now, value))
        self._data.move_to_end(key)
        self._expire(entries, now)

    def values(self, key: str, now: float) -> list[Any]:
        """Return the unexpired values recorded under ``key``."""
        entries = self._data.get(key)
        if entries is None:
            return []
        self._expire(entries, now)
        return [value for _, value in entries]

    def count(self, key: str, now: float) -> int:
        """Return how many unexpired values are recorded under ``key``."""
        entries = self._data.get(key)
        if entries is None:
            return 0
        self._expire(entries, now)
        return len(entries)

    def unique(self, key: str, now: float) -> set[Any]:
        """Return the distinct unexpired values recorded under ``key``."""
        return set(self.values(key, now))

    def prune(self, now: float) -> None:
        """Drop expired entries everywhere and forget emptied keys.

        Called periodically by the engine so that a source seen once and never
        again does not occupy a slot forever.
        """
        for key in list(self._data):
            entries = self._data[key]
            self._expire(entries, now)
            if not entries:
                del self._data[key]

    def keys(self) -> Iterator[str]:
        """Iterate over the currently tracked keys."""
        return iter(list(self._data))

    def __len__(self) -> int:
        return len(self._data)

    def _expire(self, entries: deque[tuple[float, Any]], now: float) -> None:
        cutoff = now - self._window
        while entries and entries[0][0] < cutoff:
            entries.popleft()

    def _make_room(self) -> None:
        while len(self._data) >= self._max_keys:
            self._data.popitem(last=False)
            self.evictions += 1


class CooldownGate:
    """Suppresses repeats of the same finding for a cooldown period.

    Without this, a single scan of 1000 ports produces an alert per packet once
    the threshold is crossed. Alert flooding is not thoroughness: it buries the
    finding it is trying to report.
    """

    def __init__(self, cooldown_seconds: float, max_keys: int) -> None:
        if cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must be >= 0")
        if max_keys <= 0:
            raise ValueError("max_keys must be > 0")
        self._cooldown = cooldown_seconds
        self._max_keys = max_keys
        self._last_fired: OrderedDict[str, float] = OrderedDict()
        self.suppressed = 0

    def allow(self, key: str, now: float) -> bool:
        """Return whether ``key`` may fire now, recording the time if so."""
        previous = self._last_fired.get(key)
        if previous is not None and now - previous < self._cooldown:
            self.suppressed += 1
            return False
        while len(self._last_fired) >= self._max_keys:
            self._last_fired.popitem(last=False)
        self._last_fired[key] = now
        self._last_fired.move_to_end(key)
        return True

    def prune(self, now: float) -> None:
        """Forget keys whose cooldown has fully elapsed."""
        cutoff = now - self._cooldown
        for key in list(self._last_fired):
            if self._last_fired[key] < cutoff:
                del self._last_fired[key]

    def __len__(self) -> int:
        return len(self._last_fired)
