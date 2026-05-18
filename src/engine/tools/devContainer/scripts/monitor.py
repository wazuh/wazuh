#!/usr/bin/env python3
from __future__ import annotations
"""
Process resource monitor for Wazuh Manager benchmarks.

Monitors all Wazuh manager processes by default and writes periodic resource
samples to per-process CSV files inside an output directory.  Disk usage is
tracked independently in a separate ``disk_usage.csv``.

Usage:
    # Monitor all default Wazuh processes with default disk paths
    python3 monitor.py

    # Monitor specific processes by executable path
    python3 monitor.py --exe /var/wazuh-manager/bin/wazuh-manager-analysisd \
                       --exe /var/wazuh-manager/bin/wazuh-manager-remoted

    # Legacy: monitor single process by name
    python3 monitor.py -n wazuh-modulesd -o monitor.csv -s 1

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
import threading
from datetime import datetime, timezone

import psutil

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_EXECUTABLES = [
    "/var/wazuh-manager/bin/wazuh-manager-analysisd",
    "/var/wazuh-manager/bin/wazuh-manager-monitord",
    "/var/wazuh-manager/api/scripts/wazuh_manager_apid.py",
    "/var/wazuh-manager/framework/scripts/wazuh_manager_clusterd.py",
    "/var/wazuh-manager/bin/wazuh-manager-db",
    "/var/wazuh-manager/bin/wazuh-manager-modulesd",
    "/var/wazuh-manager/bin/wazuh-manager-remoted",
]

DEFAULT_DISK_PATHS = [
    "/var/wazuh-manager/queue/inventory_sync",
    "/var/wazuh-manager/queue/engine-output",
    "/var/wazuh-manager/queue/vd",
    "/var/wazuh-manager/",
]

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

    for proc in psutil.process_iter(["pid", "name"]):
        if proc.info["name"] == name:
            logger.info("Found process '%s' with PID %d", name, proc.pid)
            return proc

    logger.critical("No running process named '%s' found.", name)
    sys.exit(1)


def find_process_by_exe(exe_path: str) -> psutil.Process | None:
    """Find a process whose executable or any cmdline argument matches *exe_path*.

    Matches both native binaries (exe == path) and Python scripts where the
    script path appears as cmdline[1] (e.g. python3 /path/to/script.py).

    Selection when multiple processes match:
      - Native binaries match via `exe`. Only fall back to `cmdline` when no
        exe matches. This prevents transient helpers (bash subshells, pgrep,
        ps) that happen to have the binary path in their cmdline from
        outvoting the real binary process.
      - Most recently started first. This handles the zombie-after-restart
        case: stale orphans from a previous service restart keep their old
        create_time(), while the active master spawned by the new restart
        has a fresh create_time().
      - Lowest PID within the same generation (parent over its workers).
    """
    exe_matches: list[psutil.Process] = []
    cmdline_matches: list[psutil.Process] = []
    for proc in psutil.process_iter(["pid", "exe", "cmdline"]):
        try:
            if proc.info["exe"] == exe_path:
                exe_matches.append(proc)
                continue
            cmdline = proc.info.get("cmdline") or []
            if exe_path in cmdline:
                cmdline_matches.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    candidates = exe_matches if exe_matches else cmdline_matches
    if not candidates:
        return None

    candidates.sort(key=lambda p: (-p.create_time(), p.pid))
    chosen = candidates[0]

    # Warn loudly if there are leftover processes from a previous generation —
    # they typically hold file locks on shared queues (e.g. RocksDB) and
    # silently break the active master.
    stale = [p for p in candidates[1:]
             if (chosen.create_time() - p.create_time()) > 60]
    if stale:
        others = ", ".join(f"PID {p.pid} (started {time.ctime(p.create_time())})"
                           for p in stale)
        logger.warning(
            "Multiple %s instances detected. Attaching to PID %d (newest, "
            "started %s). Stale instances: %s. Consider "
            "'pkill -9 -f %s && service wazuh-manager restart' before re-running.",
            os.path.basename(exe_path), chosen.pid,
            time.ctime(chosen.create_time()), others,
            os.path.basename(exe_path),
        )

    return chosen


def wait_for_processes(exe_paths: list[str], timeout: float = 30.0) -> dict[str, psutil.Process]:
    """Wait until every executable in *exe_paths* is running.

    Returns a dict mapping exe_path -> psutil.Process.
    Raises SystemExit if timeout expires before all processes appear.
    """
    remaining = set(exe_paths)
    found: dict[str, psutil.Process] = {}
    deadline = time.monotonic() + timeout

    logger.info("Waiting for %d processes (timeout=%ds)...", len(remaining), int(timeout))
    while remaining and time.monotonic() < deadline and _running:
        for exe in list(remaining):
            proc = find_process_by_exe(exe)
            if proc is not None:
                logger.info("  Found %s -> PID %d", os.path.basename(exe), proc.pid)
                found[exe] = proc
                remaining.discard(exe)
        if remaining:
            time.sleep(1)

    if remaining:
        logger.critical(
            "Timeout: the following processes were NOT found after %ds: %s",
            int(timeout), ", ".join(os.path.basename(e) for e in sorted(remaining)),
        )
        sys.exit(1)

    logger.info("All %d processes found.", len(found))
    return found


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


def sample(proc: psutil.Process, interval: float, start_time: float) -> dict | None:
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

        return {
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

    except psutil.NoSuchProcess:
        logger.warning("Process %d no longer exists.", proc.pid)
        return None
    except psutil.AccessDenied as e:
        logger.warning("Access denied reading process %d: %s", proc.pid, e)
        return None


# ---------------------------------------------------------------------------
# Main monitoring loop
# ---------------------------------------------------------------------------
def monitor_loop(proc: psutil.Process, csv_path: str, interval: float) -> None:
    write_header = not os.path.isfile(csv_path) or os.path.getsize(csv_path) == 0
    start_time = time.monotonic()

    with open(csv_path, "a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=BASE_CSV_HEADER)
        if write_header:
            writer.writeheader()
            fh.flush()

        try:
            proc_label = proc.name()
        except psutil.NoSuchProcess:
            logger.warning("Process PID %d vanished before monitoring started.", proc.pid)
            return
        logger.info(
            "Monitoring PID %d (%s) every %.1fs -> %s",
            proc.pid, proc_label, interval, csv_path,
        )

        while _running:
            row = sample(proc, interval, start_time)
            if row is None:
                logger.info("Target process %s (PID %d) exited. Stopping its monitor.",
                            proc_label, proc.pid)
                break
            writer.writerow(row)
            fh.flush()

            logger.info(
                "[%s] cpu=%.1f%%  mem=%.1f%%  rss=%.1fMB  vms=%.1fMB  fds=%d  "
                "threads=%d  up=%ds  r_bytes=%d  w_bytes=%d",
                proc_label,
                row["cpu_pct"], row["mem_pct"], row["rss_mb"], row["vms_mb"],
                row["fds"], row["threads"], row["uptime_sec"],
                row["read_bytes"], row["write_bytes"],
            )

    logger.info("Monitor finished for %s. CSV written to %s", proc_label, csv_path)


def disk_monitor_loop(csv_path: str, interval: float,
                      disk_paths: list[str],
                      stop_event: threading.Event | None = None) -> None:
    """Periodically measure directory sizes and write to a dedicated CSV."""
    header = ["timestamp", "elapsed_s"] + [disk_col_name(p) for p in disk_paths]

    write_header = not os.path.isfile(csv_path) or os.path.getsize(csv_path) == 0
    start_time = time.monotonic()

    with open(csv_path, "a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=header)
        if write_header:
            writer.writeheader()
            fh.flush()

        logger.info("Disk monitor every %.1fs -> %s", interval, csv_path)
        logger.info("Disk paths: %s", ", ".join(disk_paths))

        while _running and not (stop_event and stop_event.is_set()):
            row = {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "elapsed_s": round(time.monotonic() - start_time, 1),
            }
            for p in disk_paths:
                row[disk_col_name(p)] = dir_size_mb(p)
            writer.writerow(row)
            fh.flush()

            logger.info(
                "[disk] %s",
                "  ".join(f"{disk_col_name(p)}={row[disk_col_name(p)]:.1f}MB"
                          for p in disk_paths),
            )
            # Sleep in small steps so we react quickly to stop_event.
            deadline = time.monotonic() + interval
            while time.monotonic() < deadline and _running and not (stop_event and stop_event.is_set()):
                time.sleep(min(0.5, deadline - time.monotonic()))

    logger.info("Disk monitor finished. CSV written to %s", csv_path)


def monitor_multi(processes: dict[str, psutil.Process], output_dir: str,
                  interval: float, disk_paths: list[str]) -> None:
    """Spawn one monitoring thread per process plus a disk-usage thread."""
    os.makedirs(output_dir, exist_ok=True)
    logger.info("Output directory: %s", output_dir)

    proc_threads: list[threading.Thread] = []
    disk_stop = threading.Event()

    # Per-process resource threads
    for exe_path, proc in processes.items():
        basename = os.path.basename(exe_path)
        csv_path = os.path.join(output_dir, f"{basename}.csv")
        t = threading.Thread(
            target=monitor_loop,
            args=(proc, csv_path, interval),
            name=f"mon-{basename}",
            daemon=True,
        )
        proc_threads.append(t)

    # Disk-usage thread (single, independent of processes)
    disk_thread: threading.Thread | None = None
    if disk_paths:
        disk_csv = os.path.join(output_dir, "disk_usage.csv")
        disk_thread = threading.Thread(
            target=disk_monitor_loop,
            args=(disk_csv, interval, disk_paths, disk_stop),
            name="mon-disk",
            daemon=True,
        )

    for t in proc_threads:
        t.start()
    if disk_thread:
        disk_thread.start()

    # Wait for all process threads to finish.
    while _running and any(t.is_alive() for t in proc_threads):
        for t in proc_threads:
            t.join(timeout=1.0)

    # All process monitors done — stop the disk thread.
    disk_stop.set()
    if disk_thread and disk_thread.is_alive():
        disk_thread.join(timeout=5.0)

    logger.info("All monitoring threads finished. Results in %s", output_dir)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Monitor Wazuh manager process resource usage during benchmarks.",
    )
    # --- multi-process mode (default) ---
    p.add_argument(
        "--exe",
        action="append",
        default=None,
        metavar="PATH",
        help="Executable path to monitor. Repeat for multiple. "
             "If omitted, monitors all default Wazuh manager processes.",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Seconds to wait for all target processes to appear (default: 30)",
    )

    # --- legacy single-process mode ---
    legacy = p.add_argument_group("legacy single-process mode")
    legacy.add_argument("-p", "--pid", type=int, help="PID of a single process to monitor")
    legacy.add_argument("-n", "--name", type=str, help="Process name to monitor (single)")
    legacy.add_argument("-o", "--output", type=str, default=None,
                        help="Output CSV path (only for legacy single-process mode)")

    # --- common ---
    p.add_argument("-s", "--interval", type=float, default=1.0, help="Sample interval (s)")
    p.add_argument("--pidfile", type=str, default="monitor.pid", help="PID file path")
    p.add_argument(
        "--disk-path",
        action="append",
        default=None,
        metavar="PATH",
        help="Recursive directory size to track. Repeat to track multiple. "
             "Each path adds a 'dir_<basename>_mb' column to the CSV. "
             "If omitted, uses default Wazuh paths.",
    )
    p.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Output directory for multi-process mode. "
             "Defaults to ./result_<timestamp>.",
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

    disk_paths = args.disk_path if args.disk_path is not None else DEFAULT_DISK_PATHS

    # Legacy single-process mode
    if args.pid is not None or args.name is not None:
        if args.output is None:
            logger.critical("Legacy mode requires -o/--output.")
            sys.exit(1)
        proc = find_process(args.pid, args.name)
        monitor_loop(proc, args.output, args.interval)
        return

    # Multi-process mode (default)
    exe_list = args.exe if args.exe is not None else DEFAULT_EXECUTABLES
    processes = wait_for_processes(exe_list, timeout=args.timeout)

    output_dir = args.output_dir
    if output_dir is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(".", f"result_{ts}")

    monitor_start_time = datetime.now()
    monitor_multi(processes, output_dir, args.interval, disk_paths)

    # Post-processing: extract InventorySync stats from wazuh-manager.log
    extract_invsync_logs(output_dir, start_time=monitor_start_time)


# ---------------------------------------------------------------------------
# InventorySync log extraction (temporary — will be removed in the future)
# ---------------------------------------------------------------------------
WAZUH_LOG_PATH = "/var/wazuh-manager/logs/wazuh-manager.log"

_RE_QUEUE_STATS = re.compile(
    r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) .+InventorySync queue stats: (.+)$"
)
_RE_SESSION_STATS = re.compile(
    r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) .+InventorySync session stats: (.+)$"
)


def _parse_flat_kv(text: str) -> dict[str, str]:
    """Parse 'key=value key2=value2 key3={a=1 b=2}' into a flat dict.

    Nested braces like  raw_bytes={total=587568 avg=693 max=744 min_nonzero=672}
    are flattened as   raw_bytes_total=587568  raw_bytes_avg=693  ...
    """
    result: dict[str, str] = {}
    i = 0
    while i < len(text):
        # skip whitespace
        while i < len(text) and text[i] == " ":
            i += 1
        if i >= len(text):
            break
        # read key
        eq = text.index("=", i)
        key = text[i:eq]
        i = eq + 1
        if i < len(text) and text[i] == "{":
            # nested block
            close = text.index("}", i)
            inner = text[i + 1:close]
            for sub_kv in inner.split():
                sk, sv = sub_kv.split("=", 1)
                result[f"{key}_{sk}"] = sv
            i = close + 1
        else:
            # simple value — runs until next space or end
            end = text.find(" ", i)
            if end == -1:
                end = len(text)
            result[key] = text[i:end]
            i = end
    return result


_LOG_TS_FMT = "%Y/%m/%d %H:%M:%S"


def extract_invsync_logs(output_dir: str,
                         log_path: str = WAZUH_LOG_PATH,
                         start_time: datetime | None = None) -> None:
    """Parse wazuh-manager.log and write queue/session stats CSVs.

    Only log lines with a timestamp >= *start_time* are included so that
    data from previous runs is not mixed in.

    This function is temporary and will be removed in the future.
    """
    if not os.path.isfile(log_path):
        logger.info("Log file %s not found — skipping InventorySync extraction.", log_path)
        return

    queue_rows: list[dict[str, str]] = []
    session_rows: list[dict[str, str]] = []

    logger.info("Extracting InventorySync stats from %s (since %s) ...",
                log_path,
                start_time.strftime(_LOG_TS_FMT) if start_time else "beginning")
    with open(log_path, "r", errors="replace") as fh:
        for line in fh:
            m = _RE_QUEUE_STATS.match(line)
            if m:
                ts_str = m.group(1)
                if start_time and datetime.strptime(ts_str, _LOG_TS_FMT) < start_time:
                    continue
                row = {"timestamp": ts_str}
                row.update(_parse_flat_kv(m.group(2)))
                queue_rows.append(row)
                continue
            m = _RE_SESSION_STATS.match(line)
            if m:
                ts_str = m.group(1)
                if start_time and datetime.strptime(ts_str, _LOG_TS_FMT) < start_time:
                    continue
                row = {"timestamp": ts_str}
                row.update(_parse_flat_kv(m.group(2)))
                session_rows.append(row)

    if queue_rows:
        path = os.path.join(output_dir, "invsync_queue_stats.csv")
        _write_csv(path, queue_rows)
        logger.info("Wrote %d queue-stats rows -> %s", len(queue_rows), path)
    else:
        logger.info("No InventorySync queue stats found in log.")

    if session_rows:
        path = os.path.join(output_dir, "invsync_session_stats.csv")
        _write_csv(path, session_rows)
        logger.info("Wrote %d session-stats rows -> %s", len(session_rows), path)
    else:
        logger.info("No InventorySync session stats found in log.")


def _write_csv(path: str, rows: list[dict[str, str]]) -> None:
    """Write a list of dicts to CSV, deriving the header from all keys."""
    all_keys: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for k in row:
            if k not in seen:
                all_keys.append(k)
                seen.add(k)
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=all_keys)
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
