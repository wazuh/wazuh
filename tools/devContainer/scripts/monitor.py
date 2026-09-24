#!/usr/bin/env python3
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
from __future__ import annotations

import argparse
import atexit
import csv
import http.client
import json
import logging
import os
import re
import signal
import socket
import struct
import sys
import time
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import psutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench_samples  # noqa: E402  (sibling module, needs the path above)
import bench_collect  # noqa: E402
from bench_collect import _as_int, api_monitor_loop  # noqa: E402

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_EXECUTABLES = [
    "/var/wazuh-manager/bin/wazuh-manager-analysisd",
    "/var/wazuh-manager/api/scripts/wazuh_manager_apid.py",
    "/var/wazuh-manager/framework/scripts/wazuh_manager_clusterd.py",
    "/var/wazuh-manager/bin/wazuh-manager-db",
    "/var/wazuh-manager/bin/wazuh-manager-modulesd",
    "/var/wazuh-manager/bin/wazuh-manager-remoted",
]

# wazuh-indexer is co-located only in all-in-one deployments. The monitor
# probes for its executable at startup and silently skips it if absent.
INDEXER_EXECUTABLE = "/usr/share/wazuh-indexer/jdk/bin/java"
INDEXER_ENGINE_EXECUTABLE = "/usr/share/wazuh-indexer/engine/bin/wazuh-engine"
DASHBOARD_EXECUTABLE = "/usr/share/wazuh-dashboard/bin/opensearch-dashboards"
DASHBOARD_NODE_EXECUTABLE = "/usr/share/wazuh-dashboard/node/bin/node"

# queue/inventory_sync is deliberately absent: it belonged to the retired
# inventory_sync module. inventory_sync_server keeps no local store at all (it
# streams straight to the indexer), so whatever is left at that path is frozen
# residue and would only plot a flat line. queue/vd stays — the vulnerability
# scanner's RocksDB is live and does grow.
DEFAULT_DISK_PATHS = [
    "/var/wazuh-manager/queue/vd",
    "/var/wazuh-manager/",
]



# remoted's C++ module publishes its own metrics on a manager-local admin socket, served by
# the same shared HTTP-over-UDS transport inventory_sync_server uses. This is ADDITIVE to the
# legacy framed `getstats` above: that one carries remoted's C statistics, which stay where
# they are. The C++ module's counters exist nowhere else.

# The alias tables and wide headers that used to live here now live in bench_samples.py.
# They moved because they changed role: as long as the collector wrote a fixed wide CSV
# they were a FILTER -- a metric absent from the table never reached the disk, and a
# metric present in the table but absent from the dump was written as a literal 0. Now the
# collector writes every metric it is given to samples/metrics.ndjson under the module's
# own name, and the tables are consulted only to DERIVE the short-named CSV. Adding a
# metric to a module no longer requires editing this file.

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

# Stop events of the running collector threads, so the signal handler can reach them.
_API_STOP_EVENTS: list[threading.Event] = []


# ---------------------------------------------------------------------------
# Signal handling & PID file
# ---------------------------------------------------------------------------
def _signal_handler(_signum, _frame):
    global _running
    _running = False
    # The collector loops live in bench_collect and stop on their event, not on this flag.
    for stop in _API_STOP_EVENTS:
        stop.set()
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


@dataclass(frozen=True)
class ProcessTarget:
    key: str
    exe_paths: tuple[str, ...]
    cmdline_markers: tuple[str, ...] = ()
    require_cmdline_marker: bool = False
    csv_name: str | None = None
    display_name: str | None = None

    @property
    def name(self) -> str:
        return self.display_name or self.csv_name or os.path.basename(self.key)


def process_target_from_exe(
    exe_path: str,
    *,
    csv_name: str | None = None,
    display_name: str | None = None,
    cmdline_markers: tuple[str, ...] | None = None,
    extra_exe_paths: tuple[str, ...] = (),
    require_cmdline_marker: bool = False,
) -> ProcessTarget:
    markers = (exe_path,) if cmdline_markers is None else cmdline_markers
    return ProcessTarget(
        key=exe_path,
        exe_paths=(exe_path,) + extra_exe_paths,
        cmdline_markers=markers,
        require_cmdline_marker=require_cmdline_marker,
        csv_name=csv_name,
        display_name=display_name,
    )


def _cmdline_has_marker(cmdline: list[str], markers: tuple[str, ...]) -> bool:
    if not markers:
        return False
    return any(marker in arg for marker in markers for arg in cmdline)


def find_process_by_target(target: ProcessTarget) -> psutil.Process | None:
    """Find a process matching *target*.

    Matches native binaries via ``exe`` and interpreted commands via stable
    command-line markers. Dashboard monitoring uses an additional cmdline
    marker requirement so a generic Node.js process is not mistaken for
    wazuh-dashboard.

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
            exe = proc.info.get("exe") or ""
            cmdline = proc.info.get("cmdline") or []
            exe_match = exe in target.exe_paths
            cmdline_match = _cmdline_has_marker(cmdline, target.cmdline_markers)

            if target.require_cmdline_marker:
                if exe_match and cmdline_match:
                    exe_matches.append(proc)
                continue

            if exe_match:
                exe_matches.append(proc)
                continue
            if cmdline_match:
                cmdline_matches.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    candidates = exe_matches if exe_matches else cmdline_matches
    if not candidates:
        return None

    candidates.sort(key=lambda p: (-p.create_time(), p.pid))
    chosen = candidates[0]

    # Warn loudly if there are leftover processes from a previous generation -
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
            target.name, chosen.pid,
            time.ctime(chosen.create_time()), others,
            target.name,
        )

    return chosen


def find_process_by_exe(exe_path: str) -> psutil.Process | None:
    return find_process_by_target(process_target_from_exe(exe_path))


def wait_for_processes(
    targets: list[ProcessTarget] | list[str],
    timeout: float = 30.0,
) -> dict[ProcessTarget, psutil.Process]:
    """Wait until every target in *targets* is running.

    Returns a dict mapping ProcessTarget -> psutil.Process.
    Raises SystemExit if timeout expires before all processes appear.
    """
    target_list = [
        process_target_from_exe(t) if isinstance(t, str) else t
        for t in targets
    ]
    remaining = set(target_list)
    found: dict[ProcessTarget, psutil.Process] = {}
    deadline = time.monotonic() + timeout

    logger.info("Waiting for %d processes (timeout=%ds)...", len(remaining), int(timeout))
    while remaining and time.monotonic() < deadline and _running:
        for target in list(remaining):
            proc = find_process_by_target(target)
            if proc is not None:
                logger.info("  Found %s -> PID %d", target.name, proc.pid)
                found[target] = proc
                remaining.discard(target)
        if remaining:
            time.sleep(1)

    if remaining:
        missing = ", ".join(t.name for t in sorted(remaining, key=lambda t: t.name))
        logger.critical(
            "Timeout: the following processes were NOT found after %ds: %s",
            int(timeout), missing,
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

    Example: /var/wazuh-manager/queue/vd/  ->  dir_vd_mb
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
# CSV schema safety
#
# Only the per-process and disk CSVs need this now: the daemons' statistics go to the
# samples file, whose schema cannot drift -- a new metric is one more key in `m`, and
# older lines simply do not have it.
# ---------------------------------------------------------------------------
def needs_header(csv_path: str, header: Sequence[str]) -> bool:
    """Whether the caller must write the header row, rotating a mismatched file first.

    Every writer below APPENDS and writes the header only for a new file, so reusing a path whose
    CSV an older monitor.py produced would put today's fields under yesterday's header:
    `csv.DictWriter` emits values in `fieldnames` order, so each appended row lands shifted, and
    the chart generator then either dies on the field count or silently reads the wrong column.
    The column set grows whenever a metric is added -- module-standards asks for exactly that on
    every instrumented change -- so this is routine, not exotic.

    The existing file is ROTATED, never rewritten or deleted: its rows stay chartable on their own
    and the run still gets a valid file. A header we cannot read is left alone (appending to it is
    no worse than failing the run for an unreadable byte).

    The rotated name deliberately does NOT end in `.csv`: the rotated file lands next to the
    original, and monitor_graphics_generator.py discovers per-process samples by walking the
    results directory and taking every `*.csv` that is not one of the known stats names
    (STATS_CSV_NAMES, an exact-name set), so a `.csv` suffix here would get the old file plotted
    as if it were a monitored process. Keep any future suffix off `.csv` for the same reason.
    """
    if not os.path.isfile(csv_path) or os.path.getsize(csv_path) == 0:
        return True

    try:
        with open(csv_path, newline="") as fh:
            existing = next(csv.reader(fh), [])
    except OSError as e:
        logger.warning("Could not read the header of %s (%s); appending without rotating.",
                       csv_path, e)
        return False

    if list(existing) == list(header):
        return False

    rotated = f"{csv_path}.{time.strftime('%Y%m%d-%H%M%S')}.oldschema"
    try:
        os.replace(csv_path, rotated)
    except OSError as e:
        logger.warning("%s has a different column set but could not be rotated (%s); appending "
                       "anyway -- its rows will be misaligned.", csv_path, e)
        return False

    logger.warning(
        "%s was written with a different column set (%d columns, this build writes %d): moved it "
        "to %s (CSV content, renamed off .csv so the chart generator does not read it as a "
        "process sample) and started a fresh file. Appending would have written the new fields "
        "under the old header.",
        csv_path, len(existing), len(header), rotated,
    )
    return True


# ---------------------------------------------------------------------------
# Main monitoring loop
# ---------------------------------------------------------------------------
def monitor_loop(proc: psutil.Process, csv_path: str, interval: float) -> None:
    write_header = needs_header(csv_path, BASE_CSV_HEADER)
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

    write_header = needs_header(csv_path, header)
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


# Friendly CSV filename overrides for processes whose basename is generic.
# e.g. wazuh-indexer runs as "java" - we want wazuh-indexer.csv instead.
_EXE_CSV_ALIAS: dict[str, str] = {
    INDEXER_EXECUTABLE: "wazuh-indexer",
    INDEXER_ENGINE_EXECUTABLE: "wazuh-indexer-engine",
    DASHBOARD_EXECUTABLE: "wazuh-dashboard",
    DASHBOARD_NODE_EXECUTABLE: "wazuh-dashboard",
}

OPTIONAL_PROCESS_TARGETS = [
    process_target_from_exe(
        INDEXER_EXECUTABLE,
        csv_name="wazuh-indexer",
        display_name="wazuh-indexer",
    ),
    process_target_from_exe(
        INDEXER_ENGINE_EXECUTABLE,
        csv_name="wazuh-indexer-engine",
        display_name="wazuh-indexer-engine",
    ),
    ProcessTarget(
        key=DASHBOARD_EXECUTABLE,
        exe_paths=(DASHBOARD_EXECUTABLE, DASHBOARD_NODE_EXECUTABLE),
        cmdline_markers=(
            DASHBOARD_EXECUTABLE,
            "/usr/share/wazuh-dashboard/src/cli",
            "/usr/share/wazuh-dashboard",
        ),
        require_cmdline_marker=True,
        csv_name="wazuh-dashboard",
        display_name="wazuh-dashboard",
    ),
]


def monitor_multi(processes: dict[ProcessTarget, psutil.Process], output_dir: str,
                  interval: float, disk_paths: list[str],
                  ndjson_path: str | None = None, run_label: str | None = None) -> None:
    """Spawn the process, disk and per-daemon API monitoring threads.

    Every API collector appends to ONE samples file (NdjsonWriter serialises them), so a
    run's server-side numbers are a single artifact instead of one file per daemon that a
    reader has to know the names of in advance.
    """
    os.makedirs(output_dir, exist_ok=True)
    logger.info("Output directory: %s", output_dir)

    if ndjson_path is None:
        ndjson_path = os.path.join(output_dir, "samples", bench_samples.SAMPLES_FILENAME)
    # Opening the sink starts a run. The file is append-mode and a reused benchmark label
    # reuses its results directory, so the run id is what keeps a second run's numbers from
    # being read as a continuation of the first.
    ndjson = bench_samples.NdjsonWriter(ndjson_path, label=run_label)
    logger.info("Samples: %s (run %s)", ndjson_path, ndjson.run_id)

    proc_threads: list[threading.Thread] = []
    disk_stop = threading.Event()

    # Per-process resource threads
    for target, proc in processes.items():
        basename = (
            target.csv_name
            or _EXE_CSV_ALIAS.get(target.key, os.path.basename(target.key))
        )
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

    # One thread per statistics endpoint, all driven off API_MONITORS: adding a daemon is
    # an entry there, not another copy of this block.
    api_threads: list[tuple[threading.Thread, threading.Event]] = []
    for src_name, (socket_path, query, log_line) in bench_collect.API_MONITORS.items():
        stop = threading.Event()
        _API_STOP_EVENTS.append(stop)
        api_threads.append((
            threading.Thread(
                target=api_monitor_loop,
                args=(src_name, interval, socket_path, query, log_line, ndjson, stop),
                name=f"mon-{src_name}-api",
                daemon=True,
            ),
            stop,
        ))

    for t in proc_threads:
        t.start()
    if disk_thread:
        disk_thread.start()
    for t, _ in api_threads:
        t.start()

    # Wait for all process threads to finish.
    while _running and any(t.is_alive() for t in proc_threads):
        for t in proc_threads:
            t.join(timeout=1.0)

    # All process monitors done — stop independent monitors.
    disk_stop.set()
    for _, stop in api_threads:
        stop.set()
    if disk_thread and disk_thread.is_alive():
        disk_thread.join(timeout=5.0)
    # An in-flight query may still need to write its result or timeout error.
    # Keep the shared sink open until every collector has finished that write.
    for t, _ in api_threads:
        t.join()
    ndjson.close()

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
    p.add_argument(
        "--log-path",
        type=str,
        default=WAZUH_LOG_PATH,
        help="Manager log path used for the final log-event extraction "
             f"(default: {WAZUH_LOG_PATH})",
    )
    p.add_argument(
        "--run-label", type=str, default=None,
        help="Label recorded in the samples file's run marker, so a file holding several "
             "runs says which is which.",
    )
    p.add_argument(
        "--ndjson", type=str, default=None,
        help="Samples file for every daemon's statistics (default: <output-dir>/samples/"
             "metrics.ndjson). Per-daemon CSVs can be exported on demand with bench_samples.py.",
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
    targets = [process_target_from_exe(exe) for exe in exe_list]

    # Probe for all-in-one companion processes. Add them only when they are
    # actually running so the monitor works unchanged on manager-only hosts.
    if args.exe is None:
        for optional_target in OPTIONAL_PROCESS_TARGETS:
            optional_proc = find_process_by_target(optional_target)
            if optional_proc is not None:
                logger.info("%s detected (PID %d) - adding to monitored set",
                            optional_target.name, optional_proc.pid)
                targets.append(optional_target)
            else:
                logger.info("%s not found - skipping", optional_target.name)

    processes = wait_for_processes(targets, timeout=args.timeout)

    output_dir = args.output_dir
    if output_dir is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(".", f"result_{ts}")

    monitor_start_time = datetime.now()
    monitor_multi(processes, output_dir, args.interval, disk_paths, args.ndjson, args.run_label)

    # Post-processing: count the manager-log events that have no metric.
    extract_manager_log_events(output_dir, log_path=args.log_path, start_time=monitor_start_time)


# ---------------------------------------------------------------------------
# Manager log event counting
# ---------------------------------------------------------------------------
# Everything the retired inventory_sync module used to log ("InventorySync queue
# stats:", session stats, the RocksDB gauges) is gone: that module is no longer
# built or registered, so those lines can never appear again. What remains here
# counts what the CURRENT modules actually emit, and exists mainly for one gap:
# the UDS transport's accept/parse/timeout failures have no metric counterpart,
# so a log line is the only way to see them. Everything else below has a metric
# in GET /metrics too, and is counted here only because a spike is easier to
# spot against the same timeline as the rest of logs.csv.
WAZUH_LOG_PATH = "/var/wazuh-manager/logs/wazuh-manager.log"

# Rejections are logged THROTTLED, carrying their own count for the window:
#   "Rejected 1234 request(s) with 503 in the last 90 s: ..."
# Counting occurrences would undercount by orders of magnitude, so these
# patterns capture the number and the counter sums it instead.
_THROTTLED_EVENTS: dict[str, re.Pattern] = {
    "session_rejected_403": re.compile(
        r"Rejected (\d+) request\(s\) with 403 .*identity does not match"),
    # inventory_sync_server's OWN scan lane. The vulnerability scanner's dispatcher is a
    # different queue with its own counter below; the two are kept apart by wording ("scan
    # lane queue" vs "scan dispatch queue") because one column mixing both would be useless.
    "vd_lane_full_503": re.compile(
        r"Rejected (\d+) .*with 503 .*scan lane queue is full"),
    # --- bounded lanes behind vd-http.sock ----------------------------------------------------
    "vd_scan_dispatch_full_503": re.compile(
        r"Rejected (\d+) scan request\(s\) with 503 .*scan dispatch queue is full"),
    # remoted's relay leg failing for NON-capacity reasons (VD unreachable / not ready):
    # capacity 503s are VD's own line above, this one is the passthrough's.
    "scanvd_relay_503": re.compile(
        r"Answered (\d+) scan request\(s\) with 503 .*VD did not queue them"),
    "ondemand_lane_full_503": re.compile(
        r"Rejected (\d+) on-demand update\(s\) with 503 .*on-demand lane is full"),
    # Not a failure: concurrent triggers for one topic coalesce into a single update.
    "ondemand_in_progress_409": re.compile(
        r"Answered (\d+) on-demand request\(s\) with 409"),
    "ondemand_unknown_topic_404": re.compile(
        r"Rejected (\d+) on-demand request\(s\) with 404"),
    # The noun varies by endpoint: sessions on /stateful, "stats document(s)" on /stats and
    # "config document(s)" on /config -- all three now charge the same pipeline.
    "indexer_unhealthy_503": re.compile(
        r"Rejected (\d+) (?:\w+ )?(?:session|document)\(s\) with 503 "
        r".*no configured indexer host is currently healthy"),
    "pipeline_full_503": re.compile(
        r"Rejected (\d+) session\(s\) with 503 .*sync pipeline queue is full"),
    # --- shared UDS transport (inventory sync, vulnerability detector, remoted admin) -----
    # These are capacity conditions of the transport itself rather than of a module's
    # pipeline, and they are what a saturation run needs: they say whether load was shed at
    # the door and by which mechanism. All of them are throttled with an embedded count.
    #
    # None of the messages name their server -- only the log tag does -- so a single column
    # per condition mixes the three daemons on purpose: the per-server split lives in each
    # module's own metrics CSV, and here what matters is the timeline.
    "transport_connection_cap_503": re.compile(
        # Note the verb: connections are REFUSED at accept time, requests are REJECTED after
        # the head is read. Anchoring this one on "Rejected" would silently never match.
        r"Refused (\d+) connection\(s\) with 503 .*connection limit is reached"),
    "transport_class_session_cap_503": re.compile(
        r"Rejected (\d+) request\(s\) with 503 .*-class session limit"),
    "transport_body_cap_413": re.compile(
        r"Rejected (\d+) request\(s\) with 413 .*-class cap"),
    "transport_budget_503": re.compile(
        r"Rejected (\d+) request\(s\) with 503 .*in-flight payload budget is exhausted"),
    "transport_no_route": re.compile(
        r"Answered (\d+) request\(s\) .*no route for"),
    "transport_response_timeout_504": re.compile(
        r"(\d+) request\(s\) in the last \d+ s were not answered within"),
    "transport_abandoned_503": re.compile(
        r"(\d+) request\(s\) in the last \d+ s were dropped by their handler"),
    "transport_malformed_400": re.compile(
        r"Rejected (\d+) malformed HTTP request\(s\)"),
    "transport_accept_error": re.compile(
        r"Failed to accept (\d+) .*connection\(s\)"),
}

# One line, one occurrence.
_EVENT_PATTERNS: dict[str, re.Pattern] = {
    "bulk_flush_failed":   re.compile(r"A bulk flush of \d+ session\(s\) failed"),
    "scan_failed":         re.compile(r"The vulnerability scan for agent .* failed"),
    "indexer_unreachable": re.compile(r"No configured indexer host is currently reachable"),
    # Shutdown summaries from the bounded lanes (one line per stop, not per request): accepted
    # work that was shed because the module went down mid-flight. The scan lane DROPS its queue
    # (the peers were answered at admission), the on-demand lane still answers 503s (deferred).
    "lane_shutdown_shed": re.compile(
        r"queued (?:scan request|update)\(s\) were (?:answered 503|dropped)"),
    # Deliberately a count of LINES, not of events: every transport message is throttled and
    # carries its own count, so one line here means "a 90 s throttle window fired", and the
    # events inside it are counted by the specific _THROTTLED_EVENTS patterns above. A
    # catch-all with a capture group would be fragile (the count sits in a different position
    # per message) and would double-count what those already sum.
    #
    # The tag alternation covers the three servers that now share the transport; the tag is a
    # line PREFIX and precedes the level, so tag-then-level is the right order here.
    "transport_error":     re.compile(
        r"(?:inventory-sync-server:server|vulnerability-scanner:server|remoted-module:admin)"
        r".*(ERROR|WARNING)", re.IGNORECASE),
}

_COUNTER_NAMES: tuple[str, ...] = tuple(_THROTTLED_EVENTS) + tuple(_EVENT_PATTERNS)
_LOGS_CSV_HEADER = ["timestamp", "elapsed_s"] + list(_COUNTER_NAMES)

_RE_LOG_TIMESTAMP = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")
_LOG_TS_FMT = "%Y/%m/%d %H:%M:%S"


def extract_manager_log_events(output_dir: str,
                               log_path: str = WAZUH_LOG_PATH,
                               start_time: datetime | None = None) -> None:
    """Parse wazuh-manager.log into ``logs.csv``: per-second event counters.

    Only lines at or after *start_time* are counted, so a previous run's noise
    is not mixed in. Throttled rejection lines contribute the count they carry
    rather than 1, which is the difference between reading "4 rejections" and
    the 40 000 they actually represent.
    """
    if not os.path.isfile(log_path):
        logger.info("Log file %s not found — skipping log extraction.", log_path)
        return

    # elapsed second -> {counter: total}
    buckets: dict[int, dict[str, int]] = {}

    def bump(second: int, name: str, amount: int) -> None:
        bucket = buckets.setdefault(second, {k: 0 for k in _COUNTER_NAMES})
        bucket[name] += amount

    logger.info("Extracting manager log events from %s (since %s) ...",
                log_path,
                start_time.strftime(_LOG_TS_FMT) if start_time else "beginning")

    with open(log_path, "r", errors="replace") as fh:
        for line in fh:
            ts_match = _RE_LOG_TIMESTAMP.match(line)
            if not ts_match:
                continue
            try:
                line_dt = datetime.strptime(ts_match.group(1), _LOG_TS_FMT)
            except ValueError:
                continue
            if start_time and line_dt < start_time:
                continue

            elapsed_s = int((line_dt - start_time).total_seconds()) if start_time else 0

            for name, regex in _THROTTLED_EVENTS.items():
                m = regex.search(line)
                if m:
                    bump(elapsed_s, name, _as_int(m.group(1), 1))

            for name, regex in _EVENT_PATTERNS.items():
                if regex.search(line):
                    bump(elapsed_s, name, 1)

    if not buckets:
        logger.info("No matching log events found — logs.csv not written.")
        return

    max_sec = max(buckets)
    rows: list[dict[str, object]] = []
    for sec in range(0, max_sec + 1):
        counters = buckets.get(sec, {})
        row: dict[str, object] = {
            "timestamp": (start_time + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ")
            if start_time else "",
            "elapsed_s": sec,
        }
        for name in _COUNTER_NAMES:
            row[name] = counters.get(name, 0)
        rows.append(row)

    logs_path = os.path.join(output_dir, "logs.csv")
    with open(logs_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=_LOGS_CSV_HEADER)
        writer.writeheader()
        writer.writerows(rows)
    logger.info("Wrote %d rows -> %s", len(rows), logs_path)


if __name__ == "__main__":
    main()
