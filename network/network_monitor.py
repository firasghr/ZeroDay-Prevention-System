"""
Network Monitoring Agent
Monitors outgoing network connections every 5 seconds using psutil.
"""

import time

import psutil


def get_connections():
    """
    Retrieve all current network connections with their associated process name.

    Returns a list of dictionaries containing pid, local_address,
    remote_address, and process_name.
    """
    connections = []
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


def monitor_network():
    """
    Continuously monitor outgoing network connections every 5 seconds.
    Prints newly detected connections to stdout.
    Known connections are refreshed each cycle to reflect closed connections
    and prevent unbounded memory growth.
    """
    print("[*] Network monitor started.")
    _warned_no_perms = False
    known_connections = set()

    while True:
        time.sleep(5)
        try:
            current = get_connections()
            if not current and not _warned_no_perms:
                _warned_no_perms = True
                print(
                    "[WARNING] Network monitor: no connections retrieved. "
                    "On macOS, run with sudo for full network visibility."
                )
            current_keys = set()
            for conn in current:
                key = (conn["pid"], conn["local_address"], conn["remote_address"])
                current_keys.add(key)
                if key not in known_connections:
                    print(
                        f"[NEW CONNECTION] PID: {conn['pid']} | "
                        f"Process: {conn['process_name']} | "
                        f"Local: {conn['local_address']} → "
                        f"Remote: {conn['remote_address']}"
                    )
            # Prune connections that are no longer active
            known_connections = current_keys
        except Exception as exc:  # pylint: disable=broad-except
            print(f"[ERROR] Unexpected error in network monitor: {exc}")


if __name__ == "__main__":
    monitor_network()
