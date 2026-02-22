"""
Network Monitoring Agent — Zero-Day Prevention System
Monitors outgoing network connections every configured interval using psutil.
"""

import logging
import time

import psutil

import config

logger = logging.getLogger(__name__)


def get_connections() -> list:
    """
    Retrieve all current network connections with their associated process name.

    Returns:
        A list of dicts containing pid, local_address, remote_address,
        and process_name.  Returns an empty list if connections cannot be
        retrieved (e.g., insufficient privileges on macOS).
    """
    connections: list = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.raddr:  # Only outgoing/established connections with a remote address
                pid = conn.pid
                local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"

                process_name = "unknown"
                if pid:
                    try:
                        process_name = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        process_name = "unknown"

                connections.append(
                    {
                        "pid": pid,
                        "local_address": local,
                        "remote_address": remote,
                        "process_name": process_name,
                    }
                )
    except (psutil.AccessDenied, PermissionError):
        # macOS requires root for net_connections(); return empty list silently.
        pass

    return connections


def monitor_network() -> None:
    """
    Continuously monitor outgoing network connections every configured interval.

    Logs newly detected connections via the logging module.
    Known connections are refreshed each cycle to reflect closed connections
    and prevent unbounded memory growth.
    """
    logger.info("Network monitor started.")
    _warned_no_perms = False
    known_connections: set = set()

    while True:
        time.sleep(config.NETWORK_MONITOR_INTERVAL)
        try:
            current = get_connections()
            if not current and not _warned_no_perms:
                _warned_no_perms = True
                logger.warning(
                    "Network monitor: no connections retrieved. "
                    "On macOS, run with sudo for full network visibility."
                )

            current_keys: set = set()
            for conn in current:
                key = (conn["pid"], conn["local_address"], conn["remote_address"])
                current_keys.add(key)
                if key not in known_connections:
                    logger.info(
                        "New connection — PID: %s | Process: %s | %s → %s",
                        conn["pid"],
                        conn["process_name"],
                        conn["local_address"],
                        conn["remote_address"],
                    )

            # Prune connections that are no longer active
            known_connections = current_keys

        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Unexpected error in network monitor: %s", exc)


if __name__ == "__main__":
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL),
        format=config.LOG_FORMAT,
        datefmt=config.LOG_DATE_FORMAT,
    )
    monitor_network()
