"""Tests for repeated authentication failure detection."""

from __future__ import annotations

from ids.core.enums import Confidence, DetectionType, EventType
from ids.core.models import SecurityEvent
from ids.detection.brute_force import BruteForceRule
from tests.conftest import at, auth_failure, far_future, syn


def _feed(rule, events):
    detections = []
    for event in events:
        detections.extend(rule.evaluate(event))
    return detections


def test_repeated_failures_are_detected(config) -> None:
    rule = BruteForceRule(config)
    detections = _feed(rule, [auth_failure("10.0.0.5", offset=i) for i in range(5)])
    assert len(detections) == 1
    assert detections[0].detection_type is DetectionType.BRUTE_FORCE
    assert detections[0].mitre_technique == "T1110"
    assert detections[0].evidence["failure_count"] >= config.brute_force_threshold


def test_failures_below_threshold_do_not_alert(config) -> None:
    rule = BruteForceRule(config)
    detections = _feed(rule, [auth_failure("10.0.0.5", offset=i) for i in range(2)])
    assert detections == []


def test_failures_spread_beyond_the_window_do_not_alert(config) -> None:
    rule = BruteForceRule(config)
    spacing = config.brute_force_window
    detections = _feed(rule, [auth_failure("10.0.0.5", offset=i * spacing) for i in range(10)])
    assert detections == []


def test_network_events_are_ignored(config) -> None:
    rule = BruteForceRule(config)
    assert _feed(rule, [syn("10.0.0.5", 22, offset=i) for i in range(20)]) == []


def test_single_account_scores_higher_confidence_than_spraying(config) -> None:
    single = BruteForceRule(config)
    focused = _feed(single, [auth_failure("10.0.0.5", offset=i, account="root") for i in range(4)])
    assert focused[0].confidence is Confidence.HIGH
    assert focused[0].evidence["pattern"] == "single_account"

    sprayer = BruteForceRule(config)
    spread = _feed(
        sprayer,
        [auth_failure("10.0.0.6", offset=i, account=f"user{i}") for i in range(4)],
    )
    assert spread[0].confidence is Confidence.MEDIUM
    assert spread[0].evidence["pattern"] == "password_spraying"


def test_successful_logins_do_not_reset_the_counter(config) -> None:
    """A success in the middle of a guessing run is not exonerating."""
    rule = BruteForceRule(config)
    events = [auth_failure("10.0.0.5", offset=0), auth_failure("10.0.0.5", offset=1)]
    events.append(
        SecurityEvent(
            timestamp=at(2),
            event_type=EventType.AUTH_SUCCESS,
            source_ip="10.0.0.5",
            identity="10.0.0.5",
        )
    )
    events.append(auth_failure("10.0.0.5", offset=3))
    assert len(_feed(rule, events)) == 1


def test_cooldown_limits_repeat_alerts(config) -> None:
    rule = BruteForceRule(config)
    detections = _feed(rule, [auth_failure("10.0.0.5", offset=i * 0.5) for i in range(40)])
    assert len(detections) == 1


def test_state_is_prunable(config) -> None:
    rule = BruteForceRule(config)
    _feed(rule, [auth_failure(f"10.0.0.{i}", offset=i) for i in range(10)])
    assert rule.state_size() > 0
    rule.prune(now=far_future())
    assert rule.state_size() == 0
