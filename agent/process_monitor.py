"""
Process Monitoring Agent
Continuously monitors running processes and detects newly started ones.
"""

import time
import psutil

from engine import detection_engine
from agent import prevention


def get_process_info(proc):
    """
    Collect relevant information for a given psutil.Process object.

    Returns a dictionary with pid, name, cpu, memory, and path,
    or None if the process information cannot be retrieved.
    """
    try:
        with proc.oneshot():
            pid = proc.pid
            name = proc.name()
            cpu = proc.cpu_percent(interval=None)
            memory = proc.memory_info().rss / (1024 * 1024)  # Convert bytes to MB
            try:
                path = proc.exe()
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                path = None

        return {
            "pid": pid,
            "name": name,
            "cpu": round(cpu, 2),
            "memory": round(memory, 2),
            "path": path,
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def monitor_processes():
    """
    Continuously monitor all running processes every 2 seconds.
    Detects newly started processes and evaluates them for suspicious activity.
    """
    print("[*] Process monitor started.")
    known_pids = set(p.pid for p in psutil.process_iter())

    while True:
        time.sleep(2)
        try:
            current_pids = set(p.pid for p in psutil.process_iter())
            new_pids = current_pids - known_pids

            for pid in new_pids:
                try:
                    proc = psutil.Process(pid)
                    process_info = get_process_info(proc)
                    if process_info is None:
                        continue

                    print(
                        f"[NEW PROCESS] PID: {process_info['pid']} | "
                        f"Name: {process_info['name']} | "
                        f"CPU: {process_info['cpu']}% | "
                        f"Memory: {process_info['memory']} MB | "
                        f"Path: {process_info['path']}"
                    )

                    if detection_engine.is_process_suspicious(process_info):
                        print(
                            f"[ALERT] Suspicious process detected: "
                            f"PID={process_info['pid']}, Name={process_info['name']}"
                        )
                        prevention.log_alert(process_info)

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            known_pids = current_pids

        except Exception as exc:  # pylint: disable=broad-except
            print(f"[ERROR] Unexpected error in process monitor: {exc}")


if __name__ == "__main__":
    monitor_processes()
