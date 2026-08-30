"""Pipeline orchestration.

**Concurrency decision.** The workload is I/O-bound (a capture socket, SQLite,
HTTP) with light per-packet CPU, so threads are the right primitive and the GIL
is not the bottleneck: Scapy releases it while blocked on the socket, and
SQLite releases it during writes. ``asyncio`` was rejected because Scapy's
sniffer is a blocking, callback-driven C-level loop -- adopting it would mean
running that in a thread anyway and then bridging every callback back into the
loop, adding a failure mode without removing one. ``multiprocessing`` was
rejected because it would mean serialising every packet across a pipe, which
costs more than the parsing it would parallelise.

So: Scapy's own capture thread hands packets to a bounded ``queue.Queue``; one
processing thread drains it; one background thread polls host sources and
performs maintenance; Flask runs in its own thread. ``queue.Queue`` (not
``asyncio.Queue``) because the producer is a foreign thread we do not control.

**Single-threaded rule state.** Every detection rule keeps mutable windows,
and nothing guards them with a lock. That is safe only because exactly one
thread ever touches them: host events are pushed onto the same queue as packets
rather than processed where they are polled, so all evaluation happens on the
processing thread. Keeping the invariant is cheaper and less error-prone than
locking every rule.

Everything stops on one ``threading.Event``.
"""

from __future__ import annotations

import queue
import threading
import time
from typing import Any

# Importing the rules package registers every built-in rule before the
# detection engine asks the registry to build them.
from .. import detection  # noqa: F401
from ..alerting.manager import AlertManager
from ..config.settings import IDSConfig
from ..core.events import EventBus
from ..core.exceptions import IDSError
from ..core.models import SecurityEvent
from ..detection.engine import DetectionEngine
from ..host.sources import HostEventSource
from ..observability.log import get_logger
from ..observability.metrics import Metrics
from ..storage.database import Database
from ..storage.repositories import AlertRepository, EventRepository, MetricRepository

__all__ = ["IDSEngine"]

_QUEUE_POLL_SECONDS = 0.25
_HOST_POLL_SECONDS = 1.0
_EVENT_FLUSH_SIZE = 100
_EVENT_FLUSH_SECONDS = 2.0
_MAINTENANCE_SECONDS = 300.0
_JOIN_TIMEOUT_SECONDS = 5.0


class IDSEngine:
    """Owns the threads, the queue and the lifecycle of a running IDS."""

    def __init__(
        self,
        config: IDSConfig,
        *,
        database: Database | None = None,
        metrics: Metrics | None = None,
        bus: EventBus | None = None,
        host_sources: list[HostEventSource] | None = None,
    ) -> None:
        self.config = config
        self.metrics = metrics or Metrics()
        self.bus = bus or EventBus()
        self.database = database or Database(config.database_path)
        self.database.initialize()

        self.alerts = AlertRepository(self.database)
        self.events = EventRepository(self.database)
        self.traffic = MetricRepository(self.database)

        self.detection = DetectionEngine(config, self.metrics)
        self.alert_manager = AlertManager(config, self.alerts, self.metrics, self.bus)

        self._host_sources = list(host_sources or [])
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=config.queue_max_size)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._sniffer: Any | None = None
        self._parser: Any | None = None
        self._pending_events: list[SecurityEvent] = []
        self._last_flush = 0.0
        self._in_flight = False
        self._log = get_logger("engine")

        self.metrics.set_gauge("queue_capacity", float(config.queue_max_size))

    # -- lifecycle -----------------------------------------------------------

    @property
    def running(self) -> bool:
        """Whether the engine has been started and not yet stopped."""
        return bool(self._threads) and not self._stop.is_set()

    @property
    def packet_queue(self) -> queue.Queue[Any]:
        """The bounded queue between capture and processing."""
        return self._queue

    def start(self, *, capture: bool = True) -> None:
        """Start the worker threads, and capture unless it is disabled.

        ``capture=False`` runs the whole pipeline without touching a network
        interface, which is how the simulator and the tests exercise it.
        """
        if self._threads:
            raise IDSError("engine already started")
        self._stop.clear()

        self._spawn("ids-processing", self._processing_loop)
        self._spawn("ids-background", self._background_loop)

        if capture:
            self._start_capture()
        self._log.info("engine started (capture=%s)", capture)

    def stop(self) -> None:
        """Stop capture and workers, flush pending work and close resources."""
        if self._stop.is_set() and not self._threads:
            return
        self._log.info("shutting down")
        self._stop.set()

        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None

        for thread in self._threads:
            thread.join(timeout=_JOIN_TIMEOUT_SECONDS)
            if thread.is_alive():
                self._log.warning("thread %s did not stop within the timeout", thread.name)
        self._threads.clear()

        self._drain_queue()
        self._tick()
        self._flush_events(force=True)
        self.bus.close()
        self.database.close_all()
        self._log.info("shutdown complete: %s", self.metrics.snapshot()["counters"])

    def __enter__(self) -> IDSEngine:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    # -- ingestion -----------------------------------------------------------

    def submit_packet(self, packet: Any) -> bool:
        """Enqueue a packet directly, applying the same backpressure policy.

        Used by the simulator and the tests to drive the real pipeline without
        a capture socket.
        """
        self.metrics.increment("packets_captured")
        try:
            self._queue.put_nowait(packet)
            return True
        except queue.Full:
            self.metrics.increment("packets_dropped")
            return False

    def submit_event(self, event: SecurityEvent) -> bool:
        """Enqueue an already-normalised event for the processing thread.

        Deliberately not evaluated inline: rule state belongs to one thread.
        """
        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            self.metrics.increment("packets_dropped")
            return False

    def wait_idle(self, timeout: float = 5.0) -> bool:
        """Block until the queue is drained, for deterministic tests."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._queue.empty() and not self._in_flight:
                return True
            time.sleep(0.01)
        return False

    def add_host_source(self, source: HostEventSource) -> None:
        """Register an additional host event source."""
        self._host_sources.append(source)

    # -- worker loops --------------------------------------------------------

    def _processing_loop(self) -> None:
        """Drain the queue: parse, normalise, detect, alert. Owns rule state."""
        try:
            while not self._stop.is_set():
                try:
                    item = self._queue.get(timeout=_QUEUE_POLL_SECONDS)
                except queue.Empty:
                    # Idle: close any time window that is due, then flush.
                    self._tick()
                    self._flush_events()
                    continue
                self._in_flight = True
                try:
                    self._process_item(item)
                except Exception:
                    # One malformed packet must never end the pipeline.
                    self.metrics.increment("processing_errors")
                    self._log.exception("error processing queued item; continuing")
                finally:
                    self._in_flight = False
                    self._queue.task_done()
                self.metrics.set_gauge("queue_size", float(self._queue.qsize()))
        finally:
            self.database.close_current()

    def _process_item(self, item: Any) -> None:
        """Handle a queued item, which is either a packet or a host event."""
        if isinstance(item, SecurityEvent):
            self.metrics.increment("host_events_processed")
            self._handle_event(item)
        else:
            self._process_packet(item)

    def _tick(self) -> None:
        """Advance time-driven rules and route anything they produce."""
        now = time.time()
        try:
            detections = self.detection.tick(now)
        except Exception:
            self.metrics.increment("processing_errors")
            self._log.exception("tick failed; continuing")
            return
        if detections:
            self.alert_manager.handle(detections)
        self._store_traffic_metrics()

    def _background_loop(self) -> None:
        """Poll host sources and run periodic maintenance.

        This thread never evaluates rules: it only reads sources and enqueues.
        """
        elapsed = 0.0
        try:
            while not self._stop.wait(_HOST_POLL_SECONDS):
                elapsed += _HOST_POLL_SECONDS
                self._poll_host_sources()
                if elapsed >= _MAINTENANCE_SECONDS:
                    elapsed = 0.0
                    self._run_retention()
        finally:
            self.database.close_current()

    def _poll_host_sources(self) -> None:
        for source in self._host_sources:
            try:
                events = source.poll()
            except Exception:
                self.metrics.increment("processing_errors")
                self._log.exception("host source %s failed; continuing", source.name)
                continue
            for event in events:
                self.submit_event(event)

    def _run_retention(self) -> None:
        """Delete data older than the retention period, if one is set."""
        days = self.config.retention_days
        if days <= 0:
            return
        try:
            removed = (
                self.alerts.delete_older_than(days)
                + self.events.delete_older_than(days)
                + self.traffic.delete_older_than(days)
            )
        except IDSError:
            self.metrics.increment("storage_errors")
            self._log.exception("retention cleanup failed")
            return
        if removed:
            self._log.info("retention removed %d rows older than %d days", removed, days)

    # -- pipeline stages -----------------------------------------------------

    def _process_packet(self, packet: Any) -> None:
        event = self._parse(packet)
        if event is None:
            self.metrics.increment("packets_unparsed")
            return
        self.metrics.increment("packets_parsed")
        self._handle_event(SecurityEvent.from_network_event(event))

    def _parse(self, packet: Any) -> Any:
        if self._parser is None:
            from ..capture.packet_parser import PacketParser

            self._parser = PacketParser(self.config.interface or "")
        return self._parser.parse(packet)

    def _handle_event(self, event: SecurityEvent) -> None:
        """Run one normalised event through detection, alerting and storage."""
        self.metrics.increment("events_processed")
        detections = self.detection.process(event)
        if detections:
            self.alert_manager.handle(detections)

        self._store_traffic_metrics()
        self._pending_events.append(event)
        self._flush_events()

    def _store_traffic_metrics(self) -> None:
        """Persist traffic windows closed since the last call."""
        for metric in self.detection.drain_metrics():
            try:
                self.traffic.add(metric)
            except IDSError:
                self.metrics.increment("storage_errors")
                self._log.exception("could not store traffic metric")

    def _flush_events(self, *, force: bool = False) -> None:
        """Write buffered events in batches rather than one commit per packet."""
        if not self._pending_events:
            return
        now = time.monotonic()
        due = (
            force
            or len(self._pending_events) >= _EVENT_FLUSH_SIZE
            or now - self._last_flush >= _EVENT_FLUSH_SECONDS
        )
        if not due:
            return

        batch, self._pending_events = self._pending_events, []
        self._last_flush = now
        try:
            self.events.add_many(batch)
        except IDSError:
            self.metrics.increment("storage_errors")
            self._log.exception("could not persist %d events", len(batch))

    def _drain_queue(self) -> None:
        """Process whatever is still queued at shutdown, without blocking."""
        drained = 0
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            try:
                self._process_item(item)
                drained += 1
            except Exception:
                self.metrics.increment("processing_errors")
            finally:
                self._queue.task_done()
        if drained:
            self._log.info("drained %d queued packets during shutdown", drained)

    # -- helpers -------------------------------------------------------------

    def _spawn(self, name: str, target: Any) -> None:
        thread = threading.Thread(target=target, name=name, daemon=True)
        thread.start()
        self._threads.append(thread)

    def _start_capture(self) -> None:
        from ..capture.sniffer import PacketSniffer

        self._sniffer = PacketSniffer(self.config, self._queue, self.metrics)
        self._sniffer.start()

    def health(self) -> dict[str, Any]:
        """Summarise component health for the API, without internal paths."""
        try:
            self.alerts.count()
            database_ok = True
        except IDSError:
            database_ok = False

        capacity = max(self.config.queue_max_size, 1)
        fill = self._queue.qsize() / capacity
        return {
            "status": "healthy" if database_ok and fill < 0.9 else "degraded",
            "database": "healthy" if database_ok else "unavailable",
            "capture": "running" if self._sniffer is not None else "disabled",
            "queue": {
                "size": self._queue.qsize(),
                "capacity": capacity,
                "state": "healthy" if fill < 0.9 else "saturated",
            },
            "detectors": {
                "count": len(self.detection.rules),
                "state_sizes": self.detection.state_sizes(),
            },
        }
