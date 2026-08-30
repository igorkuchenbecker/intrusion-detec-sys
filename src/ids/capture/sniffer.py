"""Packet capture.

The capture callback does one thing: put the packet on a bounded queue. Parsing
and detection happen on another thread, because time spent in Scapy's callback
is time the kernel buffer keeps filling, and a slow callback shows up as
dropped packets rather than as slow alerts.

**Backpressure.** The queue is bounded. When it is full the *newest* packet is
discarded and ``packets_dropped`` is incremented. Blocking the capture thread
would push the loss into the kernel where we cannot count it, and an unbounded
queue would trade packet loss for an out-of-memory kill. Visible, counted loss
is the least bad of the three.
"""

from __future__ import annotations

import queue
import threading
from typing import Any

from ..config.settings import IDSConfig
from ..core.exceptions import CaptureError, PrivilegeError
from ..observability.log import get_logger
from ..observability.metrics import Metrics
from ..utils.privileges import check_capture_privileges

__all__ = ["PacketSniffer"]


class PacketSniffer:
    """Wraps Scapy's asynchronous sniffer and feeds the processing queue."""

    def __init__(
        self,
        config: IDSConfig,
        packet_queue: queue.Queue[Any],
        metrics: Metrics,
    ) -> None:
        self._config = config
        self._queue = packet_queue
        self._metrics = metrics
        self._sniffer: Any | None = None
        self._log = get_logger("capture")
        self._stopped = threading.Event()

    @property
    def running(self) -> bool:
        """Whether the underlying sniffer is currently capturing."""
        sniffer = self._sniffer
        return bool(sniffer is not None and getattr(sniffer, "running", False))

    def start(self) -> None:
        """Begin capturing. Raises if privileges or the interface are missing."""
        report = check_capture_privileges()
        if not report.can_capture:
            raise PrivilegeError("packet capture requires elevated privileges.\n" + report.guidance)

        # Imported here, not at module import time: the CLI, the API and every
        # test must work on a machine where capture is impossible.
        from scapy.sendrecv import AsyncSniffer

        try:
            self._sniffer = AsyncSniffer(
                iface=self._config.interface,
                filter=self._config.bpf_filter,
                prn=self._enqueue,
                store=False,
            )
            self._sniffer.start()
        except OSError as exc:
            raise CaptureError(f"cannot start capture: {exc}") from exc
        except ValueError as exc:
            raise CaptureError(f"invalid capture filter or interface: {exc}") from exc

        self._log.info(
            "capture started on %s%s",
            self._config.interface or "the default interface",
            f" with filter {self._config.bpf_filter!r}" if self._config.bpf_filter else "",
        )

    def stop(self) -> None:
        """Stop capturing, tolerating a sniffer that never started."""
        self._stopped.set()
        sniffer = self._sniffer
        if sniffer is None:
            return
        try:
            sniffer.stop()
        except (OSError, AttributeError, RuntimeError) as exc:
            # Scapy raises assorted errors when stopping a sniffer that never
            # fully started; shutdown must not fail because of it.
            self._log.debug("sniffer stop reported: %s", exc)
        finally:
            self._sniffer = None
        self._log.info("capture stopped")

    def _enqueue(self, packet: Any) -> None:
        """Scapy callback: hand the packet off and return immediately."""
        if self._stopped.is_set():
            return
        self._metrics.increment("packets_captured")
        try:
            self._queue.put_nowait(packet)
        except queue.Full:
            self._metrics.increment("packets_dropped")
