"""Terminal operator console for the intrusion detection system.

An optional front end. It imports the engine but nothing in the engine imports
it, so the IDS stays usable -- and testable -- with no interface library
installed. Install it with the ``tui`` extra:

.. code-block:: sh

    pip install -e ".[tui]"

The console adds no detection capability and makes the system no less passive.
It reads the same running engine the web dashboard reads: the same event bus,
the same metrics, the same repositories.
"""

from __future__ import annotations

__all__ = ["main"]


def main(argv: list[str] | None = None) -> int:
    """Launch the console.

    Imported lazily so ``ids.tui`` can be imported -- and its absence
    diagnosed -- without requiring ``textual`` to be installed.
    """
    from .app import main as _main

    return _main(argv)
