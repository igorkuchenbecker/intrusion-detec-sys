"""API tests against the real Flask app and a populated database."""

from __future__ import annotations

import json

import pytest

from ids.api.app import create_app
from ids.capture.simulator import TrafficSimulator
from ids.config.settings import IDSConfig
from ids.core.engine import IDSEngine


@pytest.fixture()
def client(tmp_path):
    config = IDSConfig(database_path=str(tmp_path / "api.db"), max_page_size=100)
    engine = IDSEngine(config)
    engine.start(capture=False)
    TrafficSimulator().feed(engine, "correlated")
    engine.wait_idle(timeout=20.0)

    app = create_app(engine)
    app.config.update(TESTING=True)
    with app.test_client() as test_client:
        test_client.engine = engine
        yield test_client
    engine.stop()


def test_health_reports_components(client) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["status"] == "healthy"
    assert data["database"] == "healthy"
    assert "state_sizes" in data["detectors"]


def test_alerts_use_the_standard_envelope(client) -> None:
    payload = client.get("/api/alerts?limit=5").get_json()
    assert set(payload) == {"data", "meta"}
    assert {"limit", "offset", "total", "returned"} <= set(payload["meta"])
    assert isinstance(payload["data"], list)


def test_alert_fields_are_explicitly_serialised(client) -> None:
    alert = client.get("/api/alerts?limit=1").get_json()["data"][0]
    expected = {
        "id",
        "timestamp",
        "detection_type",
        "title",
        "severity",
        "confidence",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "description",
        "evidence",
        "mitigation",
        "rule",
        "mitre_technique",
        "metadata",
    }
    assert set(alert) == expected


def test_filters_narrow_the_result(client) -> None:
    everything = client.get("/api/alerts?limit=100").get_json()["meta"]["total"]
    filtered = client.get("/api/alerts?detection_type=port_scan").get_json()["meta"]["total"]
    assert 0 < filtered <= everything


def test_single_alert_can_be_fetched(client) -> None:
    alert_id = client.get("/api/alerts?limit=1").get_json()["data"][0]["id"]
    assert client.get(f"/api/alerts/{alert_id}").get_json()["data"]["id"] == alert_id


def test_unknown_alert_is_404(client) -> None:
    assert client.get("/api/alerts/" + "a" * 32).status_code == 404


@pytest.mark.parametrize(
    "query",
    [
        "severity=banana",
        "detection_type=nope",
        "source_ip=not-an-ip",
        "start_time=yesterday",
        "limit=0",
        "limit=99999",
        "limit=abc",
        "offset=-1",
    ],
)
def test_invalid_parameters_are_rejected(client, query) -> None:
    """Bad input is a 400 with a message, never a guess or a stack trace."""
    response = client.get(f"/api/alerts?{query}")
    assert response.status_code == 400
    body = response.get_json()
    assert "error" in body
    assert "Traceback" not in json.dumps(body)


def test_malformed_alert_id_is_rejected(client) -> None:
    assert client.get("/api/alerts/../../etc/passwd").status_code in (400, 404)
    assert client.get("/api/alerts/abc';DROP TABLE alerts;--").status_code == 400


def test_stats_and_metrics(client) -> None:
    stats = client.get("/api/stats").get_json()["data"]
    assert stats["total_alerts"] > 0
    assert "severity_counts" in stats

    metrics = client.get("/api/metrics").get_json()["data"]
    assert metrics["counters"]["events_processed"] > 0
    assert "rule_state_sizes" in metrics


def test_traffic_and_events_endpoints(client) -> None:
    assert client.get("/api/traffic?limit=5").status_code == 200
    assert client.get("/api/events?limit=5").status_code == 200


def test_dashboard_renders(client) -> None:
    response = client.get("/")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Intrusion Detection System" in body
    assert "alerts-body" in body


def test_security_headers_are_set(client) -> None:
    headers = client.get("/").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]


def test_debug_mode_is_off(client) -> None:
    """Debug mode would expose an interactive console to the browser."""
    assert client.application.config["DEBUG"] is False


def test_stream_emits_alerts_then_ends_at_shutdown(client) -> None:
    engine = client.engine
    response = client.get("/api/stream")
    assert response.mimetype == "text/event-stream"

    stream = response.response
    assert next(iter(stream)).startswith(b":")  # the connected preamble

    engine.bus.publish({"type": "alert", "alert": {"id": "x", "severity": "high"}})
    engine.bus.close()

    frames = [chunk for chunk in stream]
    payload = b"".join(frames).decode()
    assert '"severity": "high"' in payload
    response.close()


class TestAgainstRealServer:
    """Tests that exercise the actual WSGI server, not Flask's test client.

    The test client accepts responses a real server rejects. A hop-by-hop
    header such as ``Connection`` passes silently there and raises inside
    ``wsgiref``, which is exactly how the live SSE stream broke while every
    test client assertion kept passing.
    """

    @pytest.fixture()
    def server(self, tmp_path):
        import threading
        import urllib.request

        from ids.api.app import ApiServer

        config = IDSConfig(database_path=str(tmp_path / "live.db"), api_port=0)
        engine = IDSEngine(config)
        engine.start(capture=False)
        TrafficSimulator().feed(engine, "port_scan")
        engine.wait_idle(timeout=20.0)

        server = ApiServer(create_app(engine), "127.0.0.1", 0)
        server.start()
        yield f"http://127.0.0.1:{server.port}", engine, urllib.request, threading
        server.stop()
        engine.stop()

    def test_endpoints_serve_over_real_http(self, server) -> None:
        base, _engine, urllib_request, _threading = server
        for path in ("/", "/api/health", "/api/alerts", "/api/metrics", "/api/traffic"):
            with urllib_request.urlopen(base + path, timeout=10) as response:
                assert response.status == 200, path

    def test_static_assets_are_served(self, server) -> None:
        base, _engine, urllib_request, _threading = server
        for path in ("/static/css/style.css", "/static/js/dashboard.js", "/static/favicon.svg"):
            with urllib_request.urlopen(base + path, timeout=10) as response:
                assert response.status == 200, path

    def test_event_stream_survives_a_real_wsgi_server(self, server) -> None:
        """The regression test for the hop-by-hop header that broke the stream."""
        base, engine, urllib_request, threading = server

        response = urllib_request.urlopen(base + "/api/stream", timeout=10)
        assert response.status == 200
        assert response.headers["Content-Type"].startswith("text/event-stream")

        published = threading.Timer(
            0.3,
            lambda: engine.bus.publish({"type": "alert", "alert": {"severity": "high"}}),
        )
        closer = threading.Timer(1.2, engine.bus.close)
        published.start()
        closer.start()

        body = response.read().decode()
        published.cancel()
        closer.cancel()
        response.close()

        assert '"severity": "high"' in body
