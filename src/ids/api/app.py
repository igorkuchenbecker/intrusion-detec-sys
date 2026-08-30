"""Flask application factory.

The app is a thin read layer over the engine: it never captures, parses or
detects anything, it only serves what the pipeline already produced. That is
why it can run in its own thread without touching rule state.

**No authentication.** This is a deliberate, documented limitation: the server
binds to localhost by default and is meant for a single operator on their own
machine. Anything reachable from another host needs authentication and TLS
placed in front of it -- see the README.
"""

from __future__ import annotations

import threading
from typing import Any
from wsgiref.simple_server import WSGIRequestHandler, make_server

from flask import Flask

from ..observability.log import get_logger
from .routes import api, pages

__all__ = ["create_app", "ApiServer"]

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    # The dashboard ships its own CSS and JS as files and uses no inline
    # script, so the policy can stay strict.
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'none'"
    ),
}


def create_app(engine: Any) -> Flask:
    """Build the Flask app bound to ``engine``."""
    # Template and static folders are resolved relative to this module, which
    # lives in ids/api/, so the dashboard package next door is reachable.
    app = Flask(
        __name__,
        template_folder="../dashboard/templates",
        static_folder="../dashboard/static",
        static_url_path="/static",
    )
    # Debug and the reloader are never enabled: debug mode exposes an
    # interactive console that executes code from the browser.
    app.config.update(DEBUG=False, TESTING=False, IDS_ENGINE=engine, JSON_SORT_KEYS=False)
    app.register_blueprint(api)
    app.register_blueprint(pages)

    @app.after_request
    def _harden(response):
        for header, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response

    return app


class _QuietHandler(WSGIRequestHandler):
    """Request handler that routes access logs through our logger."""

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        get_logger("api.access").debug(format, *args)


class ApiServer:
    """Runs the Flask app on a background thread with a clean shutdown.

    ``wsgiref``'s server is used instead of ``app.run()`` because it exposes
    ``shutdown()``, which is what makes stopping deterministic. It is a
    development-grade server, and the README says so: this project is a
    monitoring console for one operator, not a public service.
    """

    def __init__(self, app: Flask, host: str, port: int) -> None:
        self._server = make_server(host, port, app, handler_class=_QuietHandler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="ids-api", daemon=True
        )
        self._log = get_logger("api")

    @property
    def port(self) -> int:
        """The bound port (useful when port 0 was requested)."""
        return int(self._server.server_address[1])

    def start(self) -> None:
        """Begin serving requests."""
        self._thread.start()
        self._log.info(
            "dashboard and API on http://%s:%d/", self._server.server_address[0], self.port
        )

    def stop(self) -> None:
        """Stop serving and join the thread."""
        self._server.shutdown()
        self._thread.join(timeout=5.0)
        self._server.server_close()
        self._log.info("API stopped")
