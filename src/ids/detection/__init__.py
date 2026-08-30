"""Detection rules.

Importing this package registers every built-in rule, so
:func:`ids.detection.base.available_rules` reflects the full set without the
engine naming each module.
"""

from __future__ import annotations

from .base import DetectionRule, available_rules, build_rules, register
from .brute_force import BruteForceRule
from .correlation import CorrelationEngine
from .engine import DetectionEngine
from .port_scan import PortScanRule
from .traffic_anomaly import TrafficAnomalyRule

__all__ = [
    "DetectionRule",
    "DetectionEngine",
    "CorrelationEngine",
    "available_rules",
    "build_rules",
    "register",
    "BruteForceRule",
    "PortScanRule",
    "TrafficAnomalyRule",
]
