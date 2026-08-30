"""HTTP routes.

Two rules govern this module. Every query parameter is parsed and validated
before it reaches the storage layer -- an unparseable value is a 400, never a
best-effort guess. And every response is built by explicit serialisation, so no
internal object, path or exception text can leak by accident.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Callable
from datetime import datetime
from typing import Any

from flask import Blueprint, Response, current_app, jsonify, render_template, request

from ..core.enums import DetectionType, Severity
from ..core.exceptions import IDSError
from ..storage.repositories import AlertFilters

__all__ = ["api", "pages", "ApiError"]

api = Blueprint("api", __name__, url_prefix="/api")
pages = Blueprint("pages", __name__)

_SSE_HEARTBEAT_SECONDS = 15.0


class ApiError(Exception):
    """A client-visible error carrying an HTTP status code."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


def _engine() -> Any:
    """Return the engine attached to the running app."""
    return current_app.config["IDS_ENGINE"]


def _envelope(data: Any, **meta: Any) -> Response:
    """Wrap ``data`` in the standard response shape."""
    return jsonify({"data": data, "meta": meta})


def _param(name: str, parser: Callable[[str], Any], default: Any = None) -> Any:
    """Parse one optional query parameter, raising :class:`ApiError` if invalid."""
    raw = request.args.get(name)
    if raw is None or raw == "":
        return default
    try:
        return parser(raw)
    except (ValueError, TypeError) as exc:
        raise ApiError(f"invalid value for {name!r}: {exc}") from exc


def _bounded_int(raw: str, *, minimum: int, maximum: int) -> int:
    value = int(raw)
    if not minimum <= value <= maximum:
        raise ValueError(f"must be between {minimum} and {maximum}")
    return value


def _ip_address(raw: str) -> str:
    """Validate an address before it is used as a filter value."""
    return str(ipaddress.ip_address(raw))


def _timestamp(raw: str) -> datetime:
    """Parse an ISO-8601 timestamp."""
    return datetime.fromisoformat(raw)


def _filters() -> AlertFilters:
    """Build the alert filter set from the query string."""
    return AlertFilters(
        severity=_param("severity", Severity.from_label),
        min_severity=_param("min_severity", Severity.from_label),
        source_ip=_param("source_ip", _ip_address),
        detection_type=_param("detection_type", DetectionType.from_code),
        start_time=_param("start_time", _timestamp),
        end_time=_param("end_time", _timestamp),
    )


@api.get("/health")
def health() -> Response:
    """Report component health without exposing internal paths."""
    engine = _engine()
    report = engine.health()
    status = 200 if report["status"] == "healthy" else 503
    response = _envelope(report)
    response.status_code = status
    return response


@api.get("/alerts")
def list_alerts() -> Response:
    """Return a filtered, paginated page of alerts, newest first."""
    engine = _engine()
    max_page = engine.config.max_page_size
    limit = _param("limit", lambda raw: _bounded_int(raw, minimum=1, maximum=max_page), 50)
    offset = _param("offset", lambda raw: _bounded_int(raw, minimum=0, maximum=10**7), 0)
    filters = _filters()

    alerts = engine.alerts.list(filters, limit=limit, offset=offset)
    total = engine.alerts.count(filters)
    return _envelope(
        [alert.to_dict() for alert in alerts],
        limit=limit,
        offset=offset,
        total=total,
        returned=len(alerts),
    )


@api.get("/alerts/<alert_id>")
def get_alert(alert_id: str) -> Response:
    """Return one alert by id."""
    if not alert_id.isalnum() or len(alert_id) > 64:
        raise ApiError("malformed alert id")
    alert = _engine().alerts.get(alert_id)
    if alert is None:
        raise ApiError("alert not found", status=404)
    return _envelope(alert.to_dict())


@api.get("/stats")
def stats() -> Response:
    """Return alert totals, severity breakdown and the noisiest sources."""
    engine = _engine()
    return _envelope(
        {
            "total_alerts": engine.alerts.count(),
            "severity_counts": engine.alerts.severity_counts(),
            "top_sources": engine.alerts.top_sources(limit=10),
            "events_recorded": engine.events.count(),
        }
    )


@api.get("/metrics")
def metrics() -> Response:
    """Return pipeline counters, gauges and per-rule state sizes."""
    engine = _engine()
    snapshot = engine.metrics.snapshot()
    snapshot["rule_state_sizes"] = engine.detection.state_sizes()
    return _envelope(snapshot)


@api.get("/traffic")
def traffic() -> Response:
    """Return recent traffic windows, oldest first."""
    limit = _param("limit", lambda raw: _bounded_int(raw, minimum=1, maximum=500), 60)
    windows = _engine().traffic.recent(limit=limit)
    return _envelope([window.to_dict() for window in windows], limit=limit)


@api.get("/events")
def recent_events() -> Response:
    """Return the most recently observed normalised events."""
    limit = _param("limit", lambda raw: _bounded_int(raw, minimum=1, maximum=500), 100)
    return _envelope(_engine().events.recent(limit=limit), limit=limit)


@api.get("/stream")
def stream() -> Response:
    """Stream alerts to the dashboard with Server-Sent Events.

    SSE rather than WebSockets: the traffic is one-way (server to browser),
    ``EventSource`` reconnects on its own, it rides on plain HTTP through the
    Flask app already being served, and it needs no extra dependency. A
    WebSocket would add a library and a protocol to gain a channel back from
    the browser that this dashboard never uses.
    """
    engine = _engine()
    subscription = engine.bus.subscribe()

    def generate():
        try:
            yield ": connected\n\n"
            for message in subscription.listen(timeout=_SSE_HEARTBEAT_SECONDS):
                if message is None:
                    # Heartbeat: keeps proxies from closing an idle stream and
                    # surfaces a disconnected client as a write failure.
                    yield ": heartbeat\n\n"
                else:
                    yield f"data: {json.dumps(message)}\n\n"
        finally:
            subscription.close()

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@pages.get("/")
def dashboard() -> str:
    """Render the dashboard shell; all data arrives from the API."""
    return render_template("index.html")


@api.errorhandler(ApiError)
def handle_api_error(error: ApiError) -> Response:
    """Return a client error as JSON."""
    response = jsonify({"error": {"message": error.message, "status": error.status}})
    response.status_code = error.status
    return response


@api.errorhandler(IDSError)
def handle_internal_error(error: IDSError) -> Response:
    """Log the detail, return a generic message.

    The client is told the request failed, not how: exception text can name
    tables, paths and query fragments.
    """
    current_app.logger.exception("internal error handling %s", request.path)
    response = jsonify({"error": {"message": "internal error", "status": 500}})
    response.status_code = 500
    return response
