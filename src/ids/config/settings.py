"""Central configuration.

Every threshold, window and limit in the system is defined here. A reviewer
auditing detection behaviour or resource usage reads one file, and no module
has to invent a magic number.

Precedence, highest first: CLI flags, environment variables, TOML file,
built-in defaults. Defaults are chosen to be quiet rather than sensitive: a
noisy IDS gets ignored, which is worse than one that misses a slow scan.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, fields, replace
from pathlib import Path
from typing import Any

from ..core.exceptions import ConfigurationError

__all__ = ["IDSConfig"]

_ENV_PREFIX = "IDS_"
_VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


@dataclass(frozen=True, slots=True)
class IDSConfig:
    """Immutable configuration for one IDS run."""

    # Capture
    interface: str | None = None
    bpf_filter: str | None = None
    queue_max_size: int = 10_000

    # Storage
    database_path: str = "ids.db"
    retention_days: int = 7

    # Port scan rule
    port_scan_window: float = 10.0
    port_scan_threshold: int = 15
    port_scan_cooldown: float = 60.0

    # Traffic volume rule
    traffic_window: float = 5.0
    traffic_baseline_windows: int = 12
    traffic_threshold_multiplier: float = 4.0
    traffic_min_packets: int = 50
    traffic_cooldown: float = 60.0

    # Brute-force rule
    brute_force_window: float = 60.0
    brute_force_threshold: int = 5
    brute_force_cooldown: float = 120.0

    # Alerting
    alert_dedup_window: float = 30.0

    # Correlation
    correlation_window: float = 300.0
    correlation_min_types: int = 2

    # Resource bounds
    max_tracked_sources: int = 4_096

    # API / dashboard
    api_host: str = "127.0.0.1"
    api_port: int = 8080  # 0 selects a free ephemeral port
    dashboard_enabled: bool = True
    max_page_size: int = 500

    # Logging
    log_level: str = "INFO"

    def __post_init__(self) -> None:
        self._positive("queue_max_size", self.queue_max_size)
        self._positive("port_scan_window", self.port_scan_window)
        self._positive("port_scan_threshold", self.port_scan_threshold)
        self._positive("traffic_window", self.traffic_window)
        self._positive("traffic_baseline_windows", self.traffic_baseline_windows)
        self._positive("traffic_threshold_multiplier", self.traffic_threshold_multiplier)
        self._positive("brute_force_window", self.brute_force_window)
        self._positive("brute_force_threshold", self.brute_force_threshold)
        self._positive("alert_dedup_window", self.alert_dedup_window)
        self._positive("correlation_window", self.correlation_window)
        self._positive("correlation_min_types", self.correlation_min_types)
        self._positive("max_tracked_sources", self.max_tracked_sources)
        self._positive("max_page_size", self.max_page_size)

        for name in ("port_scan_cooldown", "traffic_cooldown", "brute_force_cooldown"):
            if getattr(self, name) < 0:
                raise ConfigurationError(f"{name} must be >= 0")
        if self.retention_days < 0:
            raise ConfigurationError("retention_days must be >= 0 (0 disables cleanup)")
        if self.traffic_min_packets < 0:
            raise ConfigurationError("traffic_min_packets must be >= 0")
        # 0 is meaningful: it asks the OS for a free ephemeral port, which is
        # how the tests bind without racing for a fixed one.
        if not 0 <= self.api_port <= 65535:
            raise ConfigurationError("api_port must be between 0 and 65535")
        if self.log_level.upper() not in _VALID_LOG_LEVELS:
            raise ConfigurationError(
                f"log_level must be one of {sorted(_VALID_LOG_LEVELS)}, got {self.log_level!r}"
            )

    @staticmethod
    def _positive(name: str, value: float) -> None:
        if value <= 0:
            raise ConfigurationError(f"{name} must be > 0")

    @classmethod
    def from_toml(cls, path: str | Path) -> IDSConfig:
        """Build a config from a TOML file.

        ``tomllib`` is in the standard library from Python 3.11, so file-based
        configuration costs no dependency.
        """
        file_path = Path(path)
        if not file_path.is_file():
            raise ConfigurationError(f"config file not found: {file_path}")
        try:
            with file_path.open("rb") as handle:
                raw = tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigurationError(f"invalid TOML in {file_path}: {exc}") from exc
        return cls.from_mapping(_flatten_sections(raw))

    @classmethod
    def from_mapping(cls, values: dict[str, Any]) -> IDSConfig:
        """Build a config from a flat mapping, rejecting unknown keys.

        Unknown keys are an error rather than a shrug: a typo in a threshold
        name would otherwise silently leave the default in place.
        """
        known = {f.name for f in fields(cls)}
        unknown = set(values) - known
        if unknown:
            raise ConfigurationError(f"unknown configuration keys: {sorted(unknown)}")
        return cls(**values)

    @classmethod
    def from_env(cls, base: IDSConfig | None = None) -> IDSConfig:
        """Overlay ``IDS_*`` environment variables onto ``base``."""
        config = base or cls()
        overrides: dict[str, Any] = {}
        for f in fields(cls):
            raw = os.environ.get(_ENV_PREFIX + f.name.upper())
            if raw is None:
                continue
            overrides[f.name] = _coerce(f.name, raw, getattr(config, f.name))
        return config.with_overrides(**overrides) if overrides else config

    def with_overrides(self, **overrides: Any) -> IDSConfig:
        """Return a copy with ``overrides`` applied, ignoring ``None`` values."""
        clean = {key: value for key, value in overrides.items() if value is not None}
        unknown = set(clean) - {f.name for f in fields(self)}
        if unknown:
            raise ConfigurationError(f"unknown configuration keys: {sorted(unknown)}")
        return replace(self, **clean)

    def to_dict(self) -> dict[str, Any]:
        """Return the configuration as a plain dictionary."""
        return {f.name: getattr(self, f.name) for f in fields(self)}


def _flatten_sections(raw: dict[str, Any]) -> dict[str, Any]:
    """Flatten one level of TOML tables into a single mapping.

    ``[capture] interface = "eth0"`` and a top-level ``interface`` are both
    accepted; sections exist purely to keep the example file readable.
    """
    flat: dict[str, Any] = {}
    for key, value in raw.items():
        if isinstance(value, dict):
            flat.update(value)
        else:
            flat[key] = value
    return flat


def _coerce(name: str, raw: str, current: Any) -> Any:
    """Convert an environment string to the type of the current value."""
    if isinstance(current, bool):
        lowered = raw.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
        raise ConfigurationError(f"{name}: expected a boolean, got {raw!r}")
    try:
        if isinstance(current, int):
            return int(raw)
        if isinstance(current, float):
            return float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name}: expected a number, got {raw!r}") from exc
    return raw
