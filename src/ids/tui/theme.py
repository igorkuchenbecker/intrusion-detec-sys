"""The palette, shared with the web dashboard.

Defined once here and imported by the stylesheet loader, so a severity looks
the same in the terminal as it does in the browser. The hexes are the ones
already checked for WCAG AA contrast against the dark surface and for
colour-vision separation.

Severity is never carried by colour alone: every badge, bar and row is
labelled in writing, because a console is frequently read over SSH, piped, or
by someone who cannot separate the hues.
"""

from __future__ import annotations

from ..core.enums import Confidence, Severity

__all__ = [
    "BG",
    "PANEL",
    "LINE",
    "LINE_HOT",
    "INK",
    "MUTED",
    "ACCENT",
    "ACCENT_DIM",
    "SEVERITY_COLOURS",
    "CONFIDENCE_COLOURS",
    "NOMINAL",
    "css_variables",
]

BG = "#05070a"
PANEL = "#0a0f16"
LINE = "#17232f"
LINE_HOT = "#1d3442"
INK = "#d7e7ee"
MUTED = "#7d95a1"
ACCENT = "#00f5c8"
ACCENT_DIM = "#06b494"

SEVERITY_COLOURS: dict[Severity, str] = {
    Severity.CRITICAL: "#ff2d6f",
    Severity.HIGH: "#ff8a3d",
    Severity.MEDIUM: "#ffd166",
    Severity.LOW: "#4dd8ff",
    Severity.INFO: "#8aa4b8",
}

CONFIDENCE_COLOURS: dict[Confidence, str] = {
    Confidence.HIGH: INK,
    Confidence.MEDIUM: MUTED,
    Confidence.LOW: MUTED,
}

#: The colour of "nothing has fired". Deliberately the accent rather than a
#: green: this system reports indicators, and a reassuring green would read as
#: "you are safe", which no monitoring tool can promise.
NOMINAL = ACCENT


def css_variables() -> str:
    """Return the palette as Textual CSS variable declarations.

    Textual CSS has no ``:root``; variables are declared at the top of a
    stylesheet. Generating them from the same constants the widgets use keeps
    one source of truth instead of two lists that drift apart.
    """
    lines = [
        f"$bg: {BG};",
        f"$panel: {PANEL};",
        f"$line: {LINE};",
        f"$line-hot: {LINE_HOT};",
        f"$ink: {INK};",
        f"$muted: {MUTED};",
        f"$accent: {ACCENT};",
        f"$accent-dim: {ACCENT_DIM};",
    ]
    lines += [f"$sev-{severity.label}: {hex_};" for severity, hex_ in SEVERITY_COLOURS.items()]
    return "\n".join(lines)
