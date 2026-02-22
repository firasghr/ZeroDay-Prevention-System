"""
Process Monitoring Agent — Zero-Day Prevention System
Continuously monitors running processes and detects newly started ones.
Optionally auto-terminates high-risk processes when AUTO_PREVENTION_ENABLED is set.
"""

import logging
import time

import psutil

import config
from agent import prevention
from engine import detection_engine

logger = logging.getLogger(__name__)


def get_process_info(proc: psutil.Process) -> dict | None:
    """
    Collect relevant information for a given psutil.Process object.

    Args:
        proc: A psutil.Process instance to inspect.

    Returns:
        A dictionary with pid, name, cpu, memory, and path,
        or None if the process information cannot be retrieved.
    """
    try:
        with proc.oneshot():
            pid = proc.pid
            name = proc.name()
            cpu = proc.cpu_percent(interval=None)
            memory = proc.memory_info().rss / (1024 * 1024)  # bytes → MB
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


def monitor_processes() -> None:
    """
    Continuously monitor all running processes every configured interval.

    Detects newly started processes and evaluates them for suspicious activity.
    When AUTO_PREVENTION_ENABLED is True, high-risk processes are terminated
    automatically after logging an alert.
    """
    logger.info("Process monitor started.")
    known_pids: set = set(p.pid for p in psutil.process_iter())

    while True:
        time.sleep(config.PROCESS_MONITOR_INTERVAL)
        try:
            current_pids: set = set(p.pid for p in psutil.process_iter())
            new_pids = current_pids - known_pids

            for pid in new_pids:
                try:
                    proc = psutil.Process(pid)
                    process_info = get_process_info(proc)
                    if process_info is None:
                        continue

                    logger.debug(
                        "New process — PID: %s | Name: %s | CPU: %.1f%% | "
                        "Memory: %.1f MB | Path: %s",
                        process_info["pid"],
                        process_info["name"],
                        process_info["cpu"],
                        process_info["memory"],
                        process_info["path"],
                    )

                    if detection_engine.is_process_suspicious(process_info):
                        score = detection_engine.calculate_threat_score(process_info)
                        threat_level = detection_engine.get_threat_level(score)

                        logger.warning(
                            "Suspicious process — PID=%s Name=%s Level=%s Score=%d",
                            process_info["pid"],
                            process_info["name"],
                            threat_level.upper(),
                            score,
                        )

                        prevention.log_alert(
                            process_info,
                            threat_level=threat_level,
                            score=score,
                        )

                        # Auto-prevention: kill high-risk processes if enabled
                        if config.AUTO_PREVENTION_ENABLED and threat_level == "high":
                            logger.critical(
                                "AUTO-PREVENTION: terminating high-risk process PID=%s (%s)",
                                process_info["pid"],
                                process_info["name"],
                            )
                            prevention.kill_process(process_info["pid"])

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            known_pids = current_pids

        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Unexpected error in process monitor: %s", exc)


if __name__ == "__main__":
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL),
        format=config.LOG_FORMAT,
        datefmt=config.LOG_DATE_FORMAT,
    )
    monitor_processes()
