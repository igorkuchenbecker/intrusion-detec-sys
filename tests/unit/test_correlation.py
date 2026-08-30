"""Tests for the correlation layer."""

from __future__ import annotations

from ids.core.enums import Confidence, DetectionType, Severity
from ids.core.models import Detection
from ids.detection.correlation import CorrelationEngine
from tests.conftest import at, far_future


def _detection(
    kind: DetectionType, source: str, severity: Severity, offset: float = 0.0
) -> Detection:
    return Detection(
        rule=kind.code,
        detection_type=kind,
        severity=severity,
        confidence=Confidence.MEDIUM,
        description="d",
        evidence={},
        mitigation="m",
        source_ip=source,
        timestamp=at(offset),
    )


def test_two_types_from_one_source_correlate(config) -> None:
    engine = CorrelationEngine(config)
    assert (
        engine.correlate([_detection(DetectionType.PORT_SCAN, "10.0.0.5", Severity.MEDIUM)]) == []
    )
    result = engine.correlate(
        [_detection(DetectionType.BRUTE_FORCE, "10.0.0.5", Severity.MEDIUM, offset=5)]
    )
    assert len(result) == 1
    assert result[0].detection_type is DetectionType.CORRELATED_ACTIVITY
    assert set(result[0].evidence["detection_types"]) == {"port_scan", "brute_force"}


def test_repeats_of_one_type_do_not_correlate(config) -> None:
    engine = CorrelationEngine(config)
    result = []
    for index in range(5):
        result += engine.correlate(
            [_detection(DetectionType.PORT_SCAN, "10.0.0.5", Severity.MEDIUM, offset=index)]
        )
    assert result == []


def test_different_sources_do_not_correlate(config) -> None:
    engine = CorrelationEngine(config)
    engine.correlate([_detection(DetectionType.PORT_SCAN, "10.0.0.5", Severity.MEDIUM)])
    result = engine.correlate([_detection(DetectionType.BRUTE_FORCE, "10.0.0.9", Severity.MEDIUM)])
    assert result == []


def test_severity_is_inherited_not_escalated(config) -> None:
    """Several medium findings must not add up to a high one."""
    engine = CorrelationEngine(config)
    engine.correlate([_detection(DetectionType.PORT_SCAN, "10.0.0.5", Severity.MEDIUM)])
    result = engine.correlate(
        [_detection(DetectionType.BRUTE_FORCE, "10.0.0.5", Severity.MEDIUM, offset=1)]
    )
    assert result[0].severity is Severity.MEDIUM


def test_peak_component_severity_is_used(config) -> None:
    engine = CorrelationEngine(config)
    engine.correlate([_detection(DetectionType.PORT_SCAN, "10.0.0.5", Severity.HIGH)])
    result = engine.correlate(
        [_detection(DetectionType.BRUTE_FORCE, "10.0.0.5", Severity.LOW, offset=1)]
    )
    assert result[0].severity is Severity.HIGH


def test_correlations_are_not_themselves_correlated(config) -> None:
    engine = CorrelationEngine(config)
    correlated = _detection(DetectionType.CORRELATED_ACTIVITY, "10.0.0.5", Severity.MEDIUM)
    assert engine.correlate([correlated]) == []


def test_state_is_prunable(config) -> None:
    engine = CorrelationEngine(config)
    engine.correlate([_detection(DetectionType.PORT_SCAN, "10.0.0.5", Severity.MEDIUM)])
    assert engine.state_size() > 0
    engine.prune(now=far_future())
    assert engine.state_size() == 0
