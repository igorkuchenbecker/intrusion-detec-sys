"""Detection rule interface and registry.

Rules are strategies behind one interface, registered by name. The engine
depends on the interface and the registry only, so a new rule is a new class
plus a ``@register`` line -- no change to the pipeline, the storage layer or
the API.

A filesystem plugin loader was considered and rejected: it would let arbitrary
code in a directory execute inside a process that may hold capture privileges.
For a known, small rule set that is a bad trade.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from ..config.settings import IDSConfig
from ..core.enums import DetectionType
from ..core.models import Detection, SecurityEvent

__all__ = ["DetectionRule", "register", "build_rules", "available_rules"]


class DetectionRule(ABC):
    """Base class for every detection rule."""

    #: Stable identifier used in configuration, logs and alerts.
    name: str = ""
    #: What this rule reports when it fires.
    detection_type: DetectionType

    def __init__(self, config: IDSConfig) -> None:
        if not self.name:
            raise ValueError(f"{type(self).__name__} must define a name")
        self._config = config

    @abstractmethod
    def evaluate(self, event: SecurityEvent) -> list[Detection]:
        """Return detections triggered by ``event``.

        Rules are called once per event and must return quickly: this runs on
        the processing thread, between the capture queue and the alert manager.
        """

    def tick(self, now: float) -> list[Detection]:  # noqa: B027 - optional hook
        """Return detections that depend on elapsed time, not on a new event.

        Called when the pipeline is idle. The default does nothing; rules that
        close time windows override it.
        """
        return []

    def prune(self, now: float) -> None:  # noqa: B027 - optional hook
        """Drop expired internal state.

        Called periodically by the engine. The default does nothing; stateful
        rules override it, and every stateful rule in this package does.
        """

    def state_size(self) -> int:
        """Return how many keys this rule currently tracks, for metrics."""
        return 0


_REGISTRY: dict[str, type[DetectionRule]] = {}


def register(cls: type[DetectionRule]) -> type[DetectionRule]:
    """Class decorator registering ``cls`` under its ``name``."""
    if not cls.name:
        raise ValueError(f"{cls.__name__} must define a name before registration")
    if cls.name in _REGISTRY:
        raise ValueError(f"duplicate rule name: {cls.name!r}")
    _REGISTRY[cls.name] = cls
    return cls


def available_rules() -> tuple[str, ...]:
    """Return the names of every registered rule, sorted."""
    return tuple(sorted(_REGISTRY))


def build_rules(config: IDSConfig, names: Iterable[str] | None = None) -> list[DetectionRule]:
    """Instantiate the requested rules, or all of them when ``names`` is empty."""
    selected = tuple(names) if names else available_rules()
    unknown = [name for name in selected if name not in _REGISTRY]
    if unknown:
        raise KeyError(f"unknown rule(s): {unknown}")
    return [_REGISTRY[name](config) for name in selected]
