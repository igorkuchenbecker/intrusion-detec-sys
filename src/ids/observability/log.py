"""Logging setup.

Named ``log`` rather than ``logging`` on purpose: a module called
``ids.observability.logging`` invites confusion with the standard library at
every import site, for no benefit.

Records carry a component name so a line can be traced to the thread that
emitted it, which matters once capture, processing and the API run
concurrently.
"""

from __future__ import annotations

import logging
import sys

__all__ = ["configure_logging", "get_logger"]

_ROOT_NAME = "ids"
_FORMAT = "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"


def configure_logging(level: str = "INFO") -> logging.Logger:
    """Configure and return the package logger.

    Handlers are replaced rather than appended, so calling this twice (CLI
    re-entry, tests) cannot duplicate every line.
    """
    logger = logging.getLogger(_ROOT_NAME)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter(_FORMAT))
    logger.addHandler(handler)
    return logger


def get_logger(component: str | None = None) -> logging.Logger:
    """Return the package logger, optionally scoped to ``component``."""
    return logging.getLogger(f"{_ROOT_NAME}.{component}" if component else _ROOT_NAME)
