#!/usr/bin/env python3
from __future__ import annotations
"""
Process resource monitor for Inventory Sync benchmarks.

Monitors wazuh-modulesd (or any process by PID/name) and writes periodic
resource samples to a CSV file.  Designed to run in the background alongside
the benchmark sender.

Usage:
    # Monitor wazuh-modulesd, sample every 1s
    python3 monitor.py -n wazuh-modulesd -o monitor.csv -s 1

    # Monitor by PID
    python3 monitor.py -p 1234 -o monitor.csv -s 1

    # Stop a running monitor
    kill $(cat monitor.pid)
"""

import argparse
import atexit
import csv
import logging
import os
import re
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
_running = True


# ---------------------------------------------------------------------------
# Signal handling & PID file
# ---------------------------------------------------------------------------
def _signal_handler(_signum, _frame):
    global _running
    _running = False
    logger.info("Stop signal received — finishing current sample and exiting.")


def write_pid_file(path: str) -> None:
    with open(path, "w") as f:
        f.write(str(os.getpid()))
    logger.info("PID file written: %s (pid=%d)", path, os.getpid())
    atexit.register(_remove_pid_file, path)


def _remove_pid_file(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Process discovery
# ---------------------------------------------------------------------------
def find_process(pid: int | None, name: str | None) -> psutil.Process:
    if pid is not None:
        try:
            proc = psutil.Process(pid)
            logger.info("Attached to PID %d (%s)", proc.pid, proc.name())
            return proc
        except psutil.NoSuchProcess:
            logger.critical("PID %d does not exist.", pid)
            sys.exit(1)

    # Collect every process matching the name so we can pick the right one
    # when there are stale duplicates (e.g. a zombie modulesd from a previous
    # restart still parented to init). Picking the first match is fragile —
    # psutil.process_iter() order is not deterministic, and attaching to a
    # zombie gives 0% CPU / flat RSS readings while the real process does
    # the work elsewhere.
    matches: list[psutil.Process] = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if proc.info["name"] == name:
                matches.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not matches:
        logger.critical("No running process named '%s' found.", name)
        sys.exit(1)

    # Prefer the most recently started process: a fresh service restart
    # spawns the new instance with a later create_time(), while orphaned
    # zombies keep their old timestamp.
    matches.sort(key=lambda p: p.create_time(), reverse=True)
    chosen = matches[0]

    if len(matches) > 1:
        others = ", ".join(f"PID {p.pid} (started {time.ctime(p.create_time())})"
                           for p in matches[1:])
        logger.warning(
            "Multiple processes named '%s' detected (%d). Attaching to the "
            "newest: PID %d (started %s). Stale instances: %s. "
            "Consider 'pkill -9 -f %s && service wazuh-manager restart' "
            "before re-running.",
            name, len(matches), chosen.pid,
            time.ctime(chosen.create_time()), others, name,
        )
    else:
        logger.info("Found process '%s' with PID %d", name, chosen.pid)
    return chosen


# ---------------------------------------------------------------------------
# Sampling
# ---------------------------------------------------------------------------
BASE_CSV_HEADER = [
    "timestamp",
    "elapsed_s",
    "pid",
    "uptime_sec",
    "cpu_pct",
    "mem_pct",
    "rss_mb",
    "vms_mb",
    "fds",
    "threads",
    "read_bytes",
    "write_bytes",
]


def disk_col_name(path: str) -> str:
    """Stable CSV column name derived from a directory path.

    Example: /var/wazuh-manager/queue/inventory_sync/  ->  dir_inventory_sync_mb
    """
    basename = os.path.basename(os.path.normpath(path)) or "root"
    safe = re.sub(r"[^A-Za-z0-9_]", "_", basename)
    return f"dir_{safe}_mb"


def dir_size_mb(path: str) -> float:
    """Recursive directory size in MB. Returns 0 if path doesn't exist or
    can't be read. Implemented with os.scandir for low overhead, no subprocess.
    """
    total = 0
    try:
        stack = [path]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        try:
                            if entry.is_symlink():
                                continue
                            if entry.is_file(follow_symlinks=False):
                                total += entry.stat(follow_symlinks=False).st_size
                            elif entry.is_dir(follow_symlinks=False):
                                stack.append(entry.path)
                        except (FileNotFoundError, PermissionError):
                            continue
            except (FileNotFoundError, PermissionError, NotADirectoryError):
                continue
    except Exception:
        return 0.0
    return round(total / (1024 * 1024), 2)


def sample(proc: psutil.Process, interval: float, start_time: float,
           disk_paths: list[str] | None = None) -> dict | None:
    try:
        cpu = proc.cpu_percent(interval=interval)
        mem = proc.memory_info()
        rss_mb = round(mem.rss / (1024 * 1024), 2)
        vms_mb = round(mem.vms / (1024 * 1024), 2)

        try:
            mem_pct = round(proc.memory_percent(), 2)
        except (psutil.AccessDenied, AttributeError):
            mem_pct = 0.0

        try:
            uptime_sec = int(time.time() - proc.create_time())
        except (psutil.AccessDenied, AttributeError):
            uptime_sec = 0

        try:
            fds = proc.num_fds()
        except AttributeError:
            fds = getattr(proc, "num_handles", lambda: 0)()

        try:
            threads = proc.num_threads()
        except (psutil.AccessDenied, AttributeError):
            threads = 0

        try:
            io = proc.io_counters()
            read_bytes = io.read_bytes
            write_bytes = io.write_bytes
        except (psutil.AccessDenied, AttributeError):
            read_bytes = write_bytes = 0

        row = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "elapsed_s": round(time.monotonic() - start_time, 1),
            "pid": proc.pid,
            "uptime_sec": uptime_sec,
            "cpu_pct": round(cpu, 2),
            "mem_pct": mem_pct,
            "rss_mb": rss_mb,
            "vms_mb": vms_mb,
            "fds": fds,
            "threads": threads,
            "read_bytes": read_bytes,
            "write_bytes": write_bytes,
        }
        for p in (disk_paths or []):
            row[disk_col_name(p)] = dir_size_mb(p)
        return row

    except psutil.NoSuchProcess:
        logger.warning("Process %d no longer exists.", proc.pid)
        return None
    except psutil.AccessDenied as e:
        logger.warning("Access denied reading process %d: %s", proc.pid, e)
        return None


# ---------------------------------------------------------------------------
# Main monitoring loop
# ---------------------------------------------------------------------------
def monitor_loop(proc: psutil.Process, csv_path: str, interval: float,
                 disk_paths: list[str] | None = None) -> None:
    disk_paths = disk_paths or []
    header = BASE_CSV_HEADER + [disk_col_name(p) for p in disk_paths]

    write_header = not os.path.isfile(csv_path) or os.path.getsize(csv_path) == 0
    start_time = time.monotonic()

    with open(csv_path, "a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=header)
        if write_header:
            writer.writeheader()
            fh.flush()

        logger.info(
            "Monitoring PID %d (%s) every %.1fs -> %s",
            proc.pid, proc.name(), interval, csv_path,
        )
        if disk_paths:
            logger.info("Disk paths: %s", ", ".join(disk_paths))

        while _running:
            row = sample(proc, interval, start_time, disk_paths)
            if row is None:
                logger.info("Target process exited. Stopping monitor.")
                break
            writer.writerow(row)
            fh.flush()

            disk_extra = "  " + "  ".join(
                f"{disk_col_name(p)}={row.get(disk_col_name(p), 0):.1f}MB"
                for p in disk_paths
            ) if disk_paths else ""
            logger.info(
                "cpu=%.1f%%  mem=%.1f%%  rss=%.1fMB  vms=%.1fMB  fds=%d  "
                "threads=%d  up=%ds  r_bytes=%d  w_bytes=%d%s",
                row["cpu_pct"], row["mem_pct"], row["rss_mb"], row["vms_mb"],
                row["fds"], row["threads"], row["uptime_sec"],
                row["read_bytes"], row["write_bytes"], disk_extra,
            )

    logger.info("Monitor finished. CSV written to %s", csv_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Monitor wazuh-modulesd resource usage during inventory sync benchmarks.",
    )
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--pid", type=int, help="PID of process to monitor")
    group.add_argument("-n", "--name", type=str, help="Process name to monitor")
    p.add_argument("-o", "--output", type=str, required=True, help="Output CSV path")
    p.add_argument("-s", "--interval", type=float, default=1.0, help="Sample interval (s)")
    p.add_argument("--pidfile", type=str, default="monitor.pid", help="PID file path")
    p.add_argument(
        "--disk-path",
        action="append",
        default=[],
        metavar="PATH",
        help="Recursive directory size to track. Repeat to track multiple. "
             "Each path adds a 'dir_<basename>_mb' column to the CSV. "
             "Common Wazuh targets: "
             "/var/wazuh-manager/queue/inventory_sync, "
             "/var/wazuh-manager/queue/engine-output, "
             "/var/wazuh-manager/queue/vd",
    )
    p.add_argument("-d", "--debug", action="store_true", help="Debug logging")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    write_pid_file(args.pidfile)

    proc = find_process(args.pid, args.name)
    monitor_loop(proc, args.output, args.interval, disk_paths=args.disk_path)


if __name__ == "__main__":
    main()
