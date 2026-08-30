"""Capture privilege checks.

Packet capture needs elevated rights on every supported platform. This module
only *reports* on them: it never re-executes under ``sudo``, never writes a
setuid helper and never changes the caller's privileges. A tool that silently
escalates is a tool nobody should run as root.
"""

from __future__ import annotations

import os
import platform
import shutil
from dataclasses import dataclass

__all__ = ["PrivilegeReport", "check_capture_privileges"]

_LINUX_GUIDANCE = (
    "Run the capture with elevated privileges, or grant the interpreter the "
    "capture capabilities instead of using sudo:\n"
    "  sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python)\n"
    "Capabilities are the narrower option: they allow raw sockets without "
    "granting full root to the process."
)
_WINDOWS_GUIDANCE = (
    "Install Npcap (https://npcap.com) with 'WinPcap API-compatible mode' and "
    "run the terminal as Administrator. Scapy cannot capture without a packet "
    "driver installed."
)
_MACOS_GUIDANCE = (
    "Capture requires read access to /dev/bpf*. Run with elevated privileges, "
    "or adjust the BPF device permissions for your user."
)


@dataclass(frozen=True, slots=True)
class PrivilegeReport:
    """What the current process can and cannot do about capture."""

    system: str
    is_elevated: bool
    has_capabilities: bool
    can_capture: bool
    guidance: str

    def to_dict(self) -> dict[str, object]:
        """Serialise for the CLI and the health endpoint."""
        return {
            "system": self.system,
            "elevated": self.is_elevated,
            "capabilities": self.has_capabilities,
            "can_capture": self.can_capture,
        }


def check_capture_privileges() -> PrivilegeReport:
    """Report whether this process is likely able to capture packets.

    "Likely" is honest: the only certain test is opening a capture socket, and
    doing that as a side effect of a status check would itself require the
    privileges being tested.
    """
    system = platform.system()

    if system == "Windows":
        # Npcap presence is the real gate; an admin check alone would mislead.
        has_driver = _windows_has_npcap()
        return PrivilegeReport(
            system=system,
            is_elevated=_windows_is_admin(),
            has_capabilities=has_driver,
            can_capture=has_driver and _windows_is_admin(),
            guidance=_WINDOWS_GUIDANCE,
        )

    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    has_caps = _linux_has_net_raw() if system == "Linux" else False
    guidance = _LINUX_GUIDANCE if system == "Linux" else _MACOS_GUIDANCE
    return PrivilegeReport(
        system=system,
        is_elevated=is_root,
        has_capabilities=has_caps,
        can_capture=is_root or has_caps,
        guidance=guidance,
    )


def _linux_has_net_raw() -> bool:
    """Check whether the running interpreter carries CAP_NET_RAW.

    Read from ``/proc/self/status``: no subprocess, no parsing of a
    locale-dependent tool's output.
    """
    try:
        with open("/proc/self/status", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("CapEff:"):
                    effective = int(line.split(":", 1)[1].strip(), 16)
                    cap_net_raw = 13  # CAP_NET_RAW, from linux/capability.h
                    return bool(effective & (1 << cap_net_raw))
    except (OSError, ValueError):
        return False
    return False


def _windows_is_admin() -> bool:
    """Check for an elevated token on Windows."""
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return False


def _windows_has_npcap() -> bool:
    """Check whether a Npcap/WinPcap driver appears to be installed."""
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    candidate = os.path.join(system_root, "System32", "Npcap", "wpcap.dll")
    return os.path.exists(candidate) or shutil.which("wpcap.dll") is not None
