"""Data access.

Every SQL statement in the project lives here, and every value reaches SQLite
through a bound parameter. Filter *column names* are never taken from user
input: the API maps a query-string key to a fixed clause defined in this
module, so an unexpected key is rejected rather than interpolated.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from typing import Any

from ..core.enums import Confidence, DetectionType, EventType, Severity
from ..core.exceptions import StorageError
from ..core.models import Alert, SecurityEvent, TrafficMetric, utc_now
from ..observability.log import get_logger
from .database import Database

__all__ = ["AlertRepository", "EventRepository", "MetricRepository", "AlertFilters"]


class AlertFilters:
    """Validated filter set for alert queries.

    Constructed from already-parsed values; the API is responsible for turning
    raw strings into these types and rejecting anything malformed.
    """

    __slots__ = (
        "severity",
        "min_severity",
        "source_ip",
        "detection_type",
        "start_time",
        "end_time",
    )

    def __init__(
        self,
        *,
        severity: Severity | None = None,
        min_severity: Severity | None = None,
        source_ip: str | None = None,
        detection_type: DetectionType | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> None:
        self.severity = severity
        self.min_severity = min_severity
        self.source_ip = source_ip
        self.detection_type = detection_type
        self.start_time = start_time
        self.end_time = end_time

    def where(self) -> tuple[str, list[Any]]:
        """Build the WHERE clause and its bound parameters."""
        clauses: list[str] = []
        params: list[Any] = []
        if self.severity is not None:
            clauses.append("severity = ?")
            params.append(self.severity.label)
        if self.min_severity is not None:
            clauses.append("severity_rank >= ?")
            params.append(self.min_severity.rank)
        if self.source_ip is not None:
            clauses.append("source_ip = ?")
            params.append(self.source_ip)
        if self.detection_type is not None:
            clauses.append("detection_type = ?")
            params.append(self.detection_type.code)
        if self.start_time is not None:
            clauses.append("timestamp >= ?")
            params.append(self.start_time.isoformat())
        if self.end_time is not None:
            clauses.append("timestamp <= ?")
            params.append(self.end_time.isoformat())
        return (" WHERE " + " AND ".join(clauses) if clauses else "", params)


class AlertRepository:
    """Reads and writes security alerts."""

    def __init__(self, database: Database) -> None:
        self._db = database
        self._log = get_logger("storage.alerts")

    def add(self, alert: Alert) -> None:
        """Persist one alert."""
        connection = self._db.connect()
        try:
            with connection:
                connection.execute(
                    """
                    INSERT INTO alerts (
                        id, timestamp, detection_type, severity, severity_rank,
                        confidence, source_ip, destination_ip, source_port,
                        destination_port, description, evidence, mitigation,
                        rule, mitre_technique, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.id,
                        alert.timestamp.isoformat(),
                        alert.detection_type.code,
                        alert.severity.label,
                        alert.severity.rank,
                        alert.confidence.label,
                        alert.source_ip,
                        alert.destination_ip,
                        alert.source_port,
                        alert.destination_port,
                        alert.description,
                        json.dumps(dict(alert.evidence), default=str),
                        alert.mitigation,
                        alert.rule,
                        alert.mitre_technique,
                        json.dumps(dict(alert.metadata), default=str),
                    ),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"cannot insert alert: {exc}") from exc

    def list(
        self,
        filters: AlertFilters | None = None,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Alert]:
        """Return alerts newest first, filtered and paginated."""
        where, params = (filters or AlertFilters()).where()
        query = f"SELECT * FROM alerts{where} ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?"
        rows = self._query(query, [*params, limit, offset])
        return [self._to_alert(row) for row in rows]

    def count(self, filters: AlertFilters | None = None) -> int:
        """Return how many alerts match ``filters``."""
        where, params = (filters or AlertFilters()).where()
        rows = self._query(f"SELECT COUNT(*) AS total FROM alerts{where}", params)
        return int(rows[0]["total"]) if rows else 0

    def get(self, alert_id: str) -> Alert | None:
        """Return one alert by id, or ``None``."""
        rows = self._query("SELECT * FROM alerts WHERE id = ?", [alert_id])
        return self._to_alert(rows[0]) if rows else None

    def severity_counts(self) -> dict[str, int]:
        """Return the number of alerts per severity label."""
        rows = self._query("SELECT severity, COUNT(*) AS total FROM alerts GROUP BY severity", [])
        counts = {severity.label: 0 for severity in Severity}
        for row in rows:
            counts[str(row["severity"])] = int(row["total"])
        return counts

    def top_sources(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return the source addresses with the most alerts."""
        rows = self._query(
            """
            SELECT source_ip, COUNT(*) AS total FROM alerts
            WHERE source_ip IS NOT NULL
            GROUP BY source_ip ORDER BY total DESC LIMIT ?
            """,
            [limit],
        )
        return [{"source_ip": row["source_ip"], "alerts": int(row["total"])} for row in rows]

    def delete_older_than(self, days: int) -> int:
        """Delete alerts older than ``days``; return how many were removed."""
        if days <= 0:
            return 0
        cutoff = (utc_now() - timedelta(days=days)).isoformat()
        connection = self._db.connect()
        try:
            with connection:
                cursor = connection.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
                return cursor.rowcount
        except sqlite3.Error as exc:
            raise StorageError(f"cannot prune alerts: {exc}") from exc

    def _query(self, sql: str, params: list[Any]) -> list[sqlite3.Row]:
        try:
            return self._db.connect().execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            raise StorageError(f"query failed: {exc}") from exc

    @staticmethod
    def _to_alert(row: sqlite3.Row) -> Alert:
        return Alert(
            id=str(row["id"]),
            timestamp=datetime.fromisoformat(str(row["timestamp"])),
            detection_type=DetectionType.from_code(str(row["detection_type"])),
            severity=Severity.from_label(str(row["severity"])),
            confidence=Confidence.from_label(str(row["confidence"])),
            description=str(row["description"]),
            evidence=json.loads(str(row["evidence"])),
            mitigation=str(row["mitigation"]),
            source_ip=row["source_ip"],
            destination_ip=row["destination_ip"],
            source_port=row["source_port"],
            destination_port=row["destination_port"],
            rule=str(row["rule"]),
            mitre_technique=row["mitre_technique"],
            metadata=json.loads(str(row["metadata"])),
        )


class EventRepository:
    """Stores a bounded record of normalised events for later inspection."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def add_many(self, events: list[SecurityEvent]) -> None:
        """Persist a batch of events in a single transaction.

        Batching matters: one commit per packet would dominate the pipeline's
        cost on a busy interface.
        """
        if not events:
            return
        connection = self._db.connect()
        try:
            with connection:
                connection.executemany(
                    """
                    INSERT INTO events (
                        timestamp, event_type, source_ip, destination_ip,
                        source_port, destination_port, protocol, packet_size,
                        tcp_flags, identity, message
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            event.timestamp.isoformat(),
                            event.event_type.value,
                            event.source_ip,
                            event.destination_ip,
                            event.source_port,
                            event.destination_port,
                            event.protocol.value if event.protocol else None,
                            event.packet_size,
                            event.tcp_flags,
                            event.identity,
                            event.message,
                        )
                        for event in events
                    ],
                )
        except sqlite3.Error as exc:
            raise StorageError(f"cannot insert events: {exc}") from exc

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return the most recent events as plain dictionaries."""
        try:
            rows = (
                self._db.connect()
                .execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
                .fetchall()
            )
        except sqlite3.Error as exc:
            raise StorageError(f"query failed: {exc}") from exc
        return [
            {
                "timestamp": row["timestamp"],
                "event_type": row["event_type"],
                "source_ip": row["source_ip"],
                "destination_ip": row["destination_ip"],
                "source_port": row["source_port"],
                "destination_port": row["destination_port"],
                "protocol": row["protocol"],
                "packet_size": row["packet_size"],
                "tcp_flags": row["tcp_flags"],
                "identity": row["identity"],
                "message": row["message"],
            }
            for row in rows
        ]

    def count(self) -> int:
        """Return the total number of stored events."""
        try:
            row = self._db.connect().execute("SELECT COUNT(*) AS total FROM events").fetchone()
        except sqlite3.Error as exc:
            raise StorageError(f"query failed: {exc}") from exc
        return int(row["total"]) if row else 0

    def delete_older_than(self, days: int) -> int:
        """Delete events older than ``days``; return how many were removed."""
        if days <= 0:
            return 0
        cutoff = (utc_now() - timedelta(days=days)).isoformat()
        connection = self._db.connect()
        try:
            with connection:
                cursor = connection.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
                return cursor.rowcount
        except sqlite3.Error as exc:
            raise StorageError(f"cannot prune events: {exc}") from exc

    @staticmethod
    def event_types() -> tuple[str, ...]:
        """Return the event type codes, for API validation."""
        return tuple(member.value for member in EventType)


class MetricRepository:
    """Stores aggregated traffic windows."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def add(self, metric: TrafficMetric) -> None:
        """Persist one closed traffic window."""
        connection = self._db.connect()
        try:
            with connection:
                connection.execute(
                    """
                    INSERT INTO traffic_metrics (
                        window_start, window_end, packets, bytes_total,
                        events, unique_sources
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        metric.window_start.isoformat(),
                        metric.window_end.isoformat(),
                        metric.packets,
                        metric.bytes_total,
                        metric.events,
                        metric.unique_sources,
                    ),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"cannot insert metric: {exc}") from exc

    def recent(self, limit: int = 60) -> list[TrafficMetric]:
        """Return recent traffic windows, oldest first (chart-ready order)."""
        try:
            rows = (
                self._db.connect()
                .execute(
                    "SELECT * FROM traffic_metrics ORDER BY window_start DESC LIMIT ?", (limit,)
                )
                .fetchall()
            )
        except sqlite3.Error as exc:
            raise StorageError(f"query failed: {exc}") from exc
        metrics = [
            TrafficMetric(
                window_start=datetime.fromisoformat(str(row["window_start"])),
                window_end=datetime.fromisoformat(str(row["window_end"])),
                packets=int(row["packets"]),
                bytes_total=int(row["bytes_total"]),
                events=int(row["events"]),
                unique_sources=int(row["unique_sources"]),
            )
            for row in rows
        ]
        return list(reversed(metrics))

    def delete_older_than(self, days: int) -> int:
        """Delete metric windows older than ``days``."""
        if days <= 0:
            return 0
        cutoff = (utc_now() - timedelta(days=days)).isoformat()
        connection = self._db.connect()
        try:
            with connection:
                cursor = connection.execute(
                    "DELETE FROM traffic_metrics WHERE window_start < ?", (cutoff,)
                )
                return cursor.rowcount
        except sqlite3.Error as exc:
            raise StorageError(f"cannot prune metrics: {exc}") from exc
