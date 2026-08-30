"""Command-line interface.

``argparse`` from the standard library: the command surface is small and
stable, and a third-party CLI framework would be a dependency bought for
nothing.

Subcommands exist because the three things an operator does -- run it, check
whether it *can* run, and demonstrate it without a network -- have genuinely
different arguments.
"""

from __future__ import annotations

import argparse
import signal
import sys
import threading
from collections.abc import Sequence

from ..api.app import ApiServer, create_app
from ..capture.simulator import SCENARIOS, TrafficSimulator
from ..config.settings import IDSConfig
from ..core.engine import IDSEngine
from ..core.exceptions import CaptureError, ConfigurationError, IDSError
from ..detection.base import available_rules
from ..host.sources import AuthLogSource
from ..observability.log import configure_logging, get_logger
from ..utils.privileges import check_capture_privileges

__all__ = ["main", "build_parser"]

_EPILOG = (
    "Defensive monitoring only. Run this against networks and hosts you are "
    "authorised to monitor."
)


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser."""
    parser = argparse.ArgumentParser(
        prog="ids",
        description="Network and host intrusion detection system (monitoring only).",
        epilog=_EPILOG,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    start = subparsers.add_parser("start", help="Capture traffic and serve the dashboard.")
    _add_common(start)
    start.add_argument("--interface", help="Interface to capture on (default: Scapy's choice).")
    start.add_argument("--bpf-filter", help="BPF capture filter, e.g. 'tcp or udp'.")
    start.add_argument("--auth-log", help="Path to an OpenSSH-style auth log to monitor.")
    start.add_argument("--host", help="Address to bind the dashboard to.")
    start.add_argument("--port", type=int, help="Port to bind the dashboard to.")
    start.add_argument("--no-dashboard", action="store_true", help="Run without the web UI.")
    start.add_argument(
        "--no-capture",
        action="store_true",
        help="Run the pipeline without packet capture (no privileges needed).",
    )
    start.add_argument(
        "--retention-days", type=int, help="Delete stored data older than this many days."
    )

    simulate = subparsers.add_parser(
        "simulate", help="Run a synthetic scenario through the full pipeline."
    )
    _add_common(simulate)
    simulate.add_argument(
        "--scenario", choices=SCENARIOS, default="all", help="Which scenario to generate."
    )
    simulate.add_argument("--serve", action="store_true", help="Serve the dashboard afterwards.")
    simulate.add_argument("--host", help="Address to bind the dashboard to.")
    simulate.add_argument("--port", type=int, help="Port to bind the dashboard to.")

    check = subparsers.add_parser("check", help="Report capture privileges and configuration.")
    _add_common(check)

    return parser


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", help="Path to a TOML configuration file.")
    parser.add_argument("--database", help="Path to the SQLite database.")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity.",
    )


def _load_config(args: argparse.Namespace) -> IDSConfig:
    """Build the effective config: file, then environment, then flags."""
    config = IDSConfig.from_toml(args.config) if args.config else IDSConfig()
    config = IDSConfig.from_env(config)
    return config.with_overrides(
        database_path=getattr(args, "database", None),
        log_level=getattr(args, "log_level", None),
        interface=getattr(args, "interface", None),
        bpf_filter=getattr(args, "bpf_filter", None),
        api_host=getattr(args, "host", None),
        api_port=getattr(args, "port", None),
        retention_days=getattr(args, "retention_days", None),
    )


def _serve(engine: IDSEngine, config: IDSConfig) -> ApiServer:
    server = ApiServer(create_app(engine), config.api_host, config.api_port)
    server.start()
    return server


def _wait_for_signal() -> None:
    """Block until SIGINT or SIGTERM, then return so shutdown can run."""
    stop = threading.Event()

    def _handle(signum: int, _frame: object) -> None:
        get_logger("cli").info("received signal %s; shutting down", signal.Signals(signum).name)
        stop.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, _handle)
    stop.wait()


def _command_start(args: argparse.Namespace, config: IDSConfig) -> int:
    log = get_logger("cli")
    engine = IDSEngine(config)

    if args.auth_log:
        engine.add_host_source(AuthLogSource(args.auth_log))
        log.info("monitoring auth log %s", args.auth_log)

    server: ApiServer | None = None
    try:
        engine.start(capture=not args.no_capture)
        if config.dashboard_enabled and not args.no_dashboard:
            server = _serve(engine, config)
        _wait_for_signal()
    except CaptureError as exc:
        log.error("%s", exc)
        return 2
    finally:
        if server is not None:
            server.stop()
        engine.stop()
    return 0


def _command_simulate(args: argparse.Namespace, config: IDSConfig) -> int:
    log = get_logger("cli")
    engine = IDSEngine(config)
    server: ApiServer | None = None
    try:
        engine.start(capture=False)
        submitted = TrafficSimulator().feed(engine, args.scenario)
        log.info(
            "scenario %r submitted: %d packets, %d host events",
            args.scenario,
            submitted["packets"],
            submitted["host_events"],
        )
        if not engine.wait_idle(timeout=30.0):
            log.warning("pipeline did not drain within the timeout")

        counters = engine.metrics.snapshot()["counters"]
        log.info(
            "processed %d events, raised %d alerts",
            counters["events_processed"],
            counters["alerts_generated"],
        )
        if args.serve:
            server = _serve(engine, config)
            _wait_for_signal()
    finally:
        if server is not None:
            server.stop()
        engine.stop()
    return 0


def _command_check(_args: argparse.Namespace, config: IDSConfig) -> int:
    report = check_capture_privileges()
    print(f"system            : {report.system}")
    print(f"elevated          : {report.is_elevated}")
    print(f"capture privileges: {report.has_capabilities}")
    print(f"capture possible  : {report.can_capture}")
    print(f"database          : {config.database_path}")
    print(f"interface         : {config.interface or '(default)'}")
    print(f"rules             : {', '.join(available_rules())}")
    if not report.can_capture:
        print("\n" + report.guidance)
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        config = _load_config(args)
    except ConfigurationError as exc:
        parser.error(str(exc))
        return 2

    configure_logging(config.log_level)

    handlers = {
        "start": _command_start,
        "simulate": _command_simulate,
        "check": _command_check,
    }
    try:
        return handlers[args.command](args, config)
    except IDSError as exc:
        get_logger("cli").error("%s", exc)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
