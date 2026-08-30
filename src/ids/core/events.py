"""In-process publish/subscribe bus.

The bus decouples alert production from alert delivery: the alert manager
publishes without knowing whether anyone is watching, and each dashboard client
gets its own bounded mailbox.

Bounded is the important word. A browser tab that stops reading must not grow a
queue until the process dies, so a full mailbox drops its oldest message and
counts the loss.
"""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

__all__ = ["EventBus", "Subscription"]


@dataclass(slots=True)
class _Mailbox:
    """One subscriber's bounded buffer plus its wake-up signal."""

    messages: deque[dict[str, Any]]
    ready: threading.Event
    dropped: int = 0


class Subscription:
    """A subscriber handle; iterate it to consume published messages."""

    def __init__(self, bus: EventBus, mailbox: _Mailbox) -> None:
        self._bus = bus
        self._mailbox = mailbox

    @property
    def dropped(self) -> int:
        """Messages discarded because this subscriber fell behind."""
        return self._mailbox.dropped

    def listen(self, timeout: float = 15.0) -> Iterator[dict[str, Any] | None]:
        """Yield messages as they arrive; yield ``None`` on idle timeout.

        The ``None`` is what lets an SSE stream emit a heartbeat and notice a
        disconnected client instead of blocking forever.

        Buffered messages are drained *before* the closed check, so an alert
        published moments before shutdown still reaches the client.
        """
        while True:
            while (message := self._bus.take(self._mailbox)) is not None:
                yield message
            if self._bus.closed:
                return
            if not self._mailbox.ready.wait(timeout=timeout):
                yield None

    def close(self) -> None:
        """Unsubscribe and release the mailbox."""
        self._bus.unsubscribe(self)

    @property
    def mailbox(self) -> _Mailbox:
        """The underlying mailbox (used by the bus itself)."""
        return self._mailbox


class EventBus:
    """Fan-out bus with bounded per-subscriber mailboxes."""

    def __init__(self, max_pending: int = 256) -> None:
        if max_pending <= 0:
            raise ValueError("max_pending must be > 0")
        self._max_pending = max_pending
        self._lock = threading.Lock()
        self._mailboxes: list[_Mailbox] = []
        self._closed = False

    @property
    def closed(self) -> bool:
        """Whether the bus has been closed."""
        return self._closed

    @property
    def subscriber_count(self) -> int:
        """How many subscribers are currently attached."""
        with self._lock:
            return len(self._mailboxes)

    def subscribe(self) -> Subscription:
        """Attach a new subscriber."""
        mailbox = _Mailbox(messages=deque(), ready=threading.Event())
        with self._lock:
            self._mailboxes.append(mailbox)
        return Subscription(self, mailbox)

    def unsubscribe(self, subscription: Subscription) -> None:
        """Detach ``subscription`` if still attached."""
        with self._lock:
            try:
                self._mailboxes.remove(subscription.mailbox)
            except ValueError:
                return
        subscription.mailbox.ready.set()

    def publish(self, message: dict[str, Any]) -> None:
        """Deliver ``message`` to every subscriber, dropping on overflow."""
        with self._lock:
            for mailbox in self._mailboxes:
                if len(mailbox.messages) >= self._max_pending:
                    mailbox.messages.popleft()
                    mailbox.dropped += 1
                mailbox.messages.append(message)
                mailbox.ready.set()

    def take(self, mailbox: _Mailbox) -> dict[str, Any] | None:
        """Pop the next message for ``mailbox``, or ``None`` when empty."""
        with self._lock:
            if not mailbox.messages:
                mailbox.ready.clear()
                return None
            return mailbox.messages.popleft()

    def close(self) -> None:
        """Close the bus and wake every subscriber so streams can end."""
        with self._lock:
            self._closed = True
            mailboxes = list(self._mailboxes)
            self._mailboxes.clear()
        for mailbox in mailboxes:
            mailbox.ready.set()
