"""Tests for the publish/subscribe bus that feeds the SSE stream."""

from __future__ import annotations

import pytest

from ids.core.events import EventBus


def test_message_reaches_every_subscriber() -> None:
    bus = EventBus()
    first, second = bus.subscribe(), bus.subscribe()
    bus.publish({"n": 1})
    assert bus.take(first.mailbox) == {"n": 1}
    assert bus.take(second.mailbox) == {"n": 1}


def test_empty_mailbox_returns_none() -> None:
    bus = EventBus()
    subscription = bus.subscribe()
    assert bus.take(subscription.mailbox) is None


def test_slow_subscriber_drops_oldest_instead_of_growing() -> None:
    """A browser tab that stops reading must not consume memory without bound."""
    bus = EventBus(max_pending=3)
    subscription = bus.subscribe()
    for index in range(10):
        bus.publish({"n": index})

    assert subscription.dropped == 7
    remaining = [bus.take(subscription.mailbox) for _ in range(3)]
    assert remaining == [{"n": 7}, {"n": 8}, {"n": 9}]  # newest kept


def test_unsubscribe_stops_delivery() -> None:
    bus = EventBus()
    subscription = bus.subscribe()
    subscription.close()
    bus.publish({"n": 1})
    assert bus.subscriber_count == 0


def test_listen_ends_when_the_bus_closes() -> None:
    """This is what lets an SSE response terminate at shutdown."""
    bus = EventBus()
    subscription = bus.subscribe()
    bus.publish({"n": 1})
    bus.close()
    assert list(subscription.listen(timeout=0.01)) == [{"n": 1}]


def test_listen_yields_none_as_a_heartbeat() -> None:
    bus = EventBus()
    subscription = bus.subscribe()
    stream = subscription.listen(timeout=0.01)
    assert next(stream) is None
    bus.close()


def test_invalid_capacity_rejected() -> None:
    with pytest.raises(ValueError):
        EventBus(max_pending=0)
