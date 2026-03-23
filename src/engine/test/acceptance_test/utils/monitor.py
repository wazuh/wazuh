#!/usr/bin/env python3
from __future__ import annotations
"""
Process resource monitor.

Monitors a process (by PID or name) and writes periodic samples to a CSV file.
Designed to run in the background; creates a PID file so an external process
can send SIGTERM / SIGINT to stop it gracefully.

Usage examples:
    # Monitor PID 1234, sample every 1s, write to output.csv
    python3 monitor.py -p 1234 -o output.csv -s 1

    # Monitor by process name
    python3 monitor.py -n wazuh-engine -o output.csv -s 1

    # Stop a running monitor whose PID file is monitor.pid
    kill $(cat monitor.pid)
"""

import argparse
import atexit
import csv
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone

import psutil

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("monitor")

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
_running = True  # flipped to False on SIGINT / SIGTERM


# ---------------------------------------------------------------------------
# Signal handling & PID file
# ---------------------------------------------------------------------------
def _signal_handler(_signum, _frame):
    global _running
    _running = False
    logger.info("Stop signal received — finishing current sample and exiting.")


def write_pid_file(path: str) -> None:
    """Write current PID to *path* and register cleanup on exit."""
    with open(path, "w") as f:
        f.write(str(os.getpid()))
    logger.info("PID file written: %s (pid=%d)", path, os.getpid())
    atexit.register(_remove_pid_file, path)


def _remove_pid_file(path: str) -> None:
    try:
        os.remove(path)
        logger.info("PID file removed: %s", path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Process discovery
# ---------------------------------------------------------------------------
def find_process(pid: int | None, name: str | None) -> psutil.Process:
    """Return a psutil.Process for the given PID or process name."""
    if pid is not None:
        try:
            proc = psutil.Process(pid)
            logger.info("Attached to PID %d (%s)", proc.pid, proc.name())
            return proc
        except psutil.NoSuchProcess:
            logger.critical("PID %d does not exist.", pid)
            sys.exit(1)

    # Search by name
    for proc in psutil.process_iter(["pid", "name"]):
        if proc.info["name"] == name:
            logger.info("Found process '%s' with PID %d", name, proc.pid)
            return proc

    logger.critical("No running process named '%s' found.", name)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Sampling
# ---------------------------------------------------------------------------
CSV_HEADER = [
    "timestamp",
    "cpu_pct",       # Absolute CPU %: 100 = 1 full core
    "rss_mb",        # Resident Set Size in MB
    "vms_mb",        # Virtual Memory Size in MB
    "fds",           # Open file descriptors
    "read_ops",      # Cumulative read operations
    "write_ops",     # Cumulative write operations
    "read_bytes",    # Cumulative bytes read
    "write_bytes",   # Cumulative bytes written
    "disk_pct",      # Process I/O as % of total disk I/O
]


def sample(proc: psutil.Process, interval: float) -> dict | None:
    """
    Collect one sample from *proc*.  Returns a dict matching CSV_HEADER keys,
    or None if the process is gone.

    ``cpu_percent(interval)`` blocks for *interval* seconds and returns the
    absolute CPU usage (num_cpus × 100 max) when called **without** percpu.
    We pass ``interval`` so psutil does the delta internally.
    """
    try:
        # cpu_percent with interval > 0 is a blocking call that measures
        # CPU over that window. By default psutil reports *per-process*
        # absolute CPU (100 % == 1 core).
        cpu = proc.cpu_percent(interval=interval)

        mem = proc.memory_info()
        rss_mb = round(mem.rss / (1024 * 1024), 2)
        vms_mb = round(mem.vms / (1024 * 1024), 2)

        try:
            fds = proc.num_fds()
        except AttributeError:
            # Windows: num_fds not available; fall back to handles
            fds = getattr(proc, "num_handles", lambda: 0)()

        # I/O counters (may raise AccessDenied in some environments)
        try:
            io = proc.io_counters()
            read_ops = io.read_count
            write_ops = io.write_count
            read_bytes = io.read_bytes
            write_bytes = io.write_bytes

            # Disk usage as percentage of total system I/O
            total_io = psutil.disk_io_counters()
            total_bytes = total_io.read_bytes + total_io.write_bytes
            if total_bytes > 0:
                disk_pct = round(
                    (io.read_bytes + io.write_bytes) / total_bytes * 100, 4
                )
            else:
                disk_pct = 0.0
        except (psutil.AccessDenied, AttributeError):
            read_ops = write_ops = read_bytes = write_bytes = 0
            disk_pct = 0.0

        return {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cpu_pct": round(cpu, 2),
            "rss_mb": rss_mb,
            "vms_mb": vms_mb,
            "fds": fds,
            "read_ops": read_ops,
            "write_ops": write_ops,
            "read_bytes": read_bytes,
            "write_bytes": write_bytes,
            "disk_pct": disk_pct,
        }

    except psutil.NoSuchProcess:
        logger.warning("Process %d no longer exists.", proc.pid)
        return None
    except psutil.AccessDenied as e:
        logger.warning("Access denied reading process %d: %s", proc.pid, e)
        return None


# ---------------------------------------------------------------------------
# Main monitoring loop
# ---------------------------------------------------------------------------
def monitor_loop(
    proc: psutil.Process,
    csv_path: str,
    interval: float,
) -> None:
    """Sample *proc* every *interval* seconds, appending rows to *csv_path*."""
    write_header = not os.path.isfile(csv_path) or os.path.getsize(csv_path) == 0

    with open(csv_path, "a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_HEADER)
        if write_header:
            writer.writeheader()
            fh.flush()

        logger.info(
            "Monitoring PID %d (%s) every %.1fs -> %s",
            proc.pid,
            proc.name(),
            interval,
            csv_path,
        )

        while _running:
            row = sample(proc, interval)
            if row is None:
                logger.info("Target process exited. Stopping monitor.")
                break
            writer.writerow(row)
            fh.flush()

            # Also log to stderr for visibility when running interactively
            logger.info(
                "cpu=%.1f%%  rss=%.1fMB  vms=%.1fMB  fds=%d  "
                "r_ops=%d  w_ops=%d  r_bytes=%d  w_bytes=%d  disk=%.2f%%",
                row["cpu_pct"],
                row["rss_mb"],
                row["vms_mb"],
                row["fds"],
                row["read_ops"],
                row["write_ops"],
                row["read_bytes"],
                row["write_bytes"],
                row["disk_pct"],
            )

    logger.info("Monitor finished. CSV written to %s", csv_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Monitor a process and write resource usage to CSV.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--pid", type=int, help="PID of the process to monitor")
    group.add_argument(
        "-n", "--name", type=str, help="Name of the process to monitor"
    )

    p.add_argument(
        "-o",
        "--output",
        type=str,
        required=True,
        help="Path to the output CSV file",
    )
    p.add_argument(
        "-s",
        "--interval",
        type=float,
        default=1.0,
        help="Sampling interval in seconds (default: 1.0)",
    )
    p.add_argument(
        "--pidfile",
        type=str,
        default="monitor.pid",
        help="Path to PID file (default: monitor.pid)",
    )
    p.add_argument(
        "-d", "--debug", action="store_true", help="Enable debug logging"
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # Write PID file
    write_pid_file(args.pidfile)

    # Find target process
    proc = find_process(args.pid, args.name)

    # Run monitoring loop
    monitor_loop(proc, args.output, args.interval)


if __name__ == "__main__":
    main()
