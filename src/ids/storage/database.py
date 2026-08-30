"""SQLite connection management and schema.

**Concurrency decision.** Capture, processing and Flask all run in different
threads, and a ``sqlite3.Connection`` is not safe to share across them. Rather
than serialising everything behind one global connection and one big lock, each
thread gets its own connection from a factory here, and the database runs in
WAL mode so readers (the API) never block the writer (the alert manager).

``check_same_thread`` is left at its default ``True`` on purpose: if a
connection ever escapes its thread, we want a loud error, not silent
corruption.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from ..core.exceptions import StorageError
from ..observability.log import get_logger

__all__ = ["Database"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id              TEXT PRIMARY KEY,
    timestamp       TEXT NOT NULL,
    detection_type  TEXT NOT NULL,
    severity        TEXT NOT NULL,
    severity_rank   INTEGER NOT NULL,
    confidence      TEXT NOT NULL,
    source_ip       TEXT,
    destination_ip  TEXT,
    source_port     INTEGER,
    destination_port INTEGER,
    description     TEXT NOT NULL,
    evidence        TEXT NOT NULL,
    mitigation      TEXT NOT NULL,
    rule            TEXT NOT NULL,
    mitre_technique TEXT,
    metadata        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts (source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity_rank DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts (detection_type);

CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    source_ip       TEXT,
    destination_ip  TEXT,
    source_port     INTEGER,
    destination_port INTEGER,
    protocol        TEXT,
    packet_size     INTEGER NOT NULL DEFAULT 0,
    tcp_flags       TEXT,
    identity        TEXT,
    message         TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events (source_ip);

CREATE TABLE IF NOT EXISTS traffic_metrics (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start    TEXT NOT NULL,
    window_end      TEXT NOT NULL,
    packets         INTEGER NOT NULL,
    bytes_total     INTEGER NOT NULL,
    events          INTEGER NOT NULL,
    unique_sources  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_metrics_window ON traffic_metrics (window_start DESC);
"""


class Database:
    """Per-thread SQLite connections against a single database file."""

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        self._local = threading.local()
        self._lock = threading.Lock()
        self._connections: list[tuple[int, sqlite3.Connection]] = []
        self._log = get_logger("storage")

    @property
    def path(self) -> str:
        """Filesystem path (or ``:memory:``) of the database."""
        return self._path

    def connect(self) -> sqlite3.Connection:
        """Return this thread's connection, creating it on first use."""
        connection: sqlite3.Connection | None = getattr(self._local, "connection", None)
        if connection is not None:
            return connection

        try:
            connection = sqlite3.connect(self._path)
        except sqlite3.Error as exc:
            raise StorageError(f"cannot open database {self._path}: {exc}") from exc

        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = ON")
        if self._path != ":memory:":
            # WAL lets the API read while the pipeline writes. It is
            # unavailable for in-memory databases, which are single-connection
            # anyway.
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = NORMAL")

        self._local.connection = connection
        with self._lock:
            self._connections.append((threading.get_ident(), connection))
        return connection

    def initialize(self) -> None:
        """Create tables and indexes if they do not exist."""
        connection = self.connect()
        try:
            with connection:
                connection.executescript(_SCHEMA)
        except sqlite3.Error as exc:
            raise StorageError(f"cannot initialise schema: {exc}") from exc
        self._log.debug("schema ready at %s", self._path)

    def close_current(self) -> None:
        """Close the calling thread's connection, if it has one.

        Each worker calls this as it exits. ``sqlite3`` refuses to close a
        connection from a thread other than the one that created it -- and it
        refuses even after that thread has been joined -- so ownership has to
        be respected rather than worked around.
        """
        connection: sqlite3.Connection | None = getattr(self._local, "connection", None)
        if connection is None:
            return
        thread_id = threading.get_ident()
        with self._lock:
            self._connections = [entry for entry in self._connections if entry[0] != thread_id]
        self._local.connection = None
        try:
            connection.close()
        except sqlite3.Error as exc:
            self._log.warning("error closing connection: %s", exc)

    def close_all(self) -> None:
        """Close what this thread owns and release the rest.

        Connections belonging to threads that did not close their own are
        dropped rather than force-closed: holding no reference lets the garbage
        collector finalise them, which is the only thread-safe option left.
        """
        self.close_current()
        with self._lock:
            abandoned = len(self._connections)
            self._connections.clear()
        if abandoned:
            self._log.debug("released %d connection(s) owned by other threads", abandoned)

    def __enter__(self) -> Database:
        self.initialize()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close_all()
