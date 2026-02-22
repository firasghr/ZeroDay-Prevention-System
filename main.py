"""
Main Controller — Zero-Day Prevention System
Starts the process monitor, file monitor, network monitor, and web dashboard
in separate daemon threads, keeping the program alive until interrupted.

Usage:
    python main.py [--port PORT] [--log-level LEVEL] [--auto-prevent] [--export-csv PATH]
"""

import argparse
import logging
import os
import sys
import threading

import config
from agent import process_monitor, prevention
from dashboard.app import app as dashboard_app
from file_monitor import file_monitor
from network import network_monitor


def _configure_logging(level: str) -> None:
    """Configure the root logger with the format specified in config."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=config.LOG_FORMAT,
        datefmt=config.LOG_DATE_FORMAT,
    )


def _parse_args() -> argparse.Namespace:
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Zero-Day Prevention System — behaviour-based threat detection",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=config.DASHBOARD_PORT,
        help=f"Dashboard port (default: {config.DASHBOARD_PORT})",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=config.LOG_LEVEL,
        help=f"Logging verbosity (default: {config.LOG_LEVEL})",
    )
    parser.add_argument(
        "--auto-prevent",
        action="store_true",
        default=False,
        help="Enable auto-prevention: automatically terminate HIGH-risk processes",
    )
    parser.add_argument(
        "--export-csv",
        metavar="PATH",
        default=None,
        help="Export current alerts.json to a CSV file and exit",
    )
    return parser.parse_args()


def _run_dashboard(port: int) -> None:
    """Start the Flask dashboard (blocking, runs in its own thread).

    Args:
        port: TCP port the dashboard listens on.
    """
    dashboard_app.run(debug=False, host=config.DASHBOARD_HOST, port=port, use_reloader=False)


def main() -> None:
    """Launch all monitoring agents and the web dashboard in separate daemon threads."""
    args = _parse_args()

    _configure_logging(args.log_level)
    logger = logging.getLogger(__name__)

    # Handle --export-csv early exit
    if args.export_csv:
        out = prevention.export_alerts_to_csv(args.export_csv)
        print(f"Alerts exported to: {out}")
        sys.exit(0)

    # Override auto-prevention if requested on the command line
    if args.auto_prevent:
        config.AUTO_PREVENTION_ENABLED = True
        logger.warning("Auto-prevention mode ENABLED — high-risk processes will be terminated.")

    monitor_path = os.path.dirname(os.path.abspath(__file__))

    threads = [
        threading.Thread(
            target=process_monitor.monitor_processes,
            name="ProcessMonitor",
            daemon=True,
        ),
        threading.Thread(
            target=file_monitor.start_file_monitor,
            args=(monitor_path,),
            name="FileMonitor",
            daemon=True,
        ),
        threading.Thread(
            target=network_monitor.monitor_network,
            name="NetworkMonitor",
            daemon=True,
        ),
        threading.Thread(
            target=_run_dashboard,
            args=(args.port,),
            name="Dashboard",
            daemon=True,
        ),
    ]

    for thread in threads:
        thread.start()
        logger.info("Started thread: %s", thread.name)

    logger.info("Dashboard available at http://localhost:%d", args.port)
    logger.info("Zero-day prevention system running. Press Ctrl+C to stop.")

    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        logger.info("Shutting down zero-day prevention system.")


if __name__ == "__main__":
    main()
