"""Tests for host event sources and log sanitisation."""

from __future__ import annotations

from ids.core.enums import EventType
from ids.host.sources import AuthLogSource, InMemoryHostEventSource, sanitize_log_text

_FAILURE = (
    "Nov  3 10:00:01 host sshd[42]: Failed password for invalid user admin "
    "from 10.0.0.5 port 22 ssh2"
)
_SUCCESS = "Nov  3 10:00:09 host sshd[42]: Accepted password for igor " "from 10.0.0.9 port 22 ssh2"


def test_failure_line_becomes_an_auth_failure_event() -> None:
    event = AuthLogSource.parse_line(_FAILURE)
    assert event is not None
    assert event.event_type is EventType.AUTH_FAILURE
    assert event.source_ip == "10.0.0.5"
    assert event.attributes["account"] == "admin"
    assert event.destination_port == 22


def test_success_line_becomes_an_auth_success_event() -> None:
    event = AuthLogSource.parse_line(_SUCCESS)
    assert event is not None
    assert event.event_type is EventType.AUTH_SUCCESS


def test_unrelated_lines_are_ignored() -> None:
    assert AuthLogSource.parse_line("Nov  3 10:00:01 host cron[1]: session opened") is None
    assert AuthLogSource.parse_line("") is None


def test_control_characters_are_stripped() -> None:
    """Log text is attacker-influenceable; newlines would forge extra records."""
    hostile = "Failed password for a\nFAKE: root logged in\x00 from 10.0.0.5 port 22"
    cleaned = sanitize_log_text(hostile)
    assert "\n" not in cleaned
    assert "\x00" not in cleaned


def test_message_length_is_capped() -> None:
    assert len(sanitize_log_text("x" * 5000)) <= 512


def test_injected_line_cannot_forge_a_different_source() -> None:
    event = AuthLogSource.parse_line(
        "Failed password for admin from 10.0.0.5 port 22 ssh2 from 6.6.6.6 port 22"
    )
    assert event.source_ip == "10.0.0.5"  # first match wins, not the appended one


def test_file_source_reads_incrementally(tmp_path) -> None:
    path = tmp_path / "auth.log"
    path.write_text(_FAILURE + "\n", encoding="utf-8")
    source = AuthLogSource(path)

    assert len(source.poll()) == 1
    assert source.poll() == []  # nothing new

    with path.open("a", encoding="utf-8") as handle:
        handle.write(_FAILURE + "\n")
    assert len(source.poll()) == 1


def test_rotated_file_is_reread_from_the_start(tmp_path) -> None:
    path = tmp_path / "auth.log"
    path.write_text(_FAILURE + "\n" + _FAILURE + "\n", encoding="utf-8")
    source = AuthLogSource(path)
    assert len(source.poll()) == 2

    path.write_text(_FAILURE + "\n", encoding="utf-8")  # rotated: now smaller
    assert len(source.poll()) == 1


def test_missing_file_is_not_an_error(tmp_path) -> None:
    assert AuthLogSource(tmp_path / "absent.log").poll() == []


def test_in_memory_source_drains_once() -> None:
    source = InMemoryHostEventSource()
    source.push(AuthLogSource.parse_line(_FAILURE))
    assert len(source.poll()) == 1
    assert source.poll() == []
